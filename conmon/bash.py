#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Dict, Iterator, Optional, Set, Tuple, Union

from psutil import NoSuchProcess, Process

from conmon.utils import AsyncPipeReader


def exceptook(type_, value, traceback):
    for child in Process().children():
        print("killing", child.name())
        child.kill()
    sys.__excepthook__(type_, value, traceback)


sys.excepthook = exceptook


class BashError(Exception):
    pass


class Bash:
    def __init__(self, executable: Union[str, Path]):
        # pylint: disable=consider-using-with
        proc = Popen(
            [executable],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
            encoding="utf-8",
            bufsize=0,
        )
        assert proc.stdout
        assert proc.stderr
        self.stdout = AsyncPipeReader(proc.stdout)
        self.stderr = AsyncPipeReader(proc.stderr)
        self.proc = proc
        self.last_cmd: Optional[str] = None

    def check_running(self):
        poll = self.proc.poll()
        if poll is not None:
            raise BashError(f"Bash exited with code {poll}")

    def send(self, cmd: str):
        self.check_running()
        self.stdout.readlines()
        assert self.proc.stdin
        self.proc.stdin.write(f"{cmd}\n")
        self.last_cmd = cmd

    def receive(self, timeout: Optional[float] = None) -> str:
        stdout = "".join(
            self.stdout.readlines(block_first=timeout is not None, timeout=timeout)
        )
        stderr = "".join(self.stderr.readlines())
        if stderr:
            self.exit()
            raise BashError(stderr)
        return stdout

    def check_output(self, cmd: str, timeout=0.5) -> str:
        self.send(cmd)
        return self.receive(timeout=timeout)

    def exit(self) -> int:
        if self.proc.poll() is None:
            with suppress(TimeoutExpired):
                self.proc.communicate("exit\n", timeout=0.2)
        return self.proc.wait()

    def __del__(self):
        with suppress(AttributeError):
            self.proc.kill()


def parse_ps(output: str) -> Iterator[Dict[str, str]]:
    lines = output.splitlines(keepends=False)
    if len(lines) < 2:
        return

    header = lines[0].split()
    for line in lines[1:]:
        if not line.startswith(" "):
            continue
        entries = line.split(maxsplit=len(header) - 1)
        yield dict(zip(header, entries))


def scan_msys(ps_output: str):
    procs: Dict[Process, Set[Process]] = {}
    # mapping pid -> ppid, winpid
    ppid_map: Dict[int, Tuple[int, int]] = {}

    def root_process(child_pid: int) -> Process:
        parent_pid, win_pid = ppid_map[child_pid]
        if parent_pid == 1:
            return Process(win_pid)
        return root_process(parent_pid)

    for info in parse_ps(ps_output):
        if info.get("COMMAND", "/ps").endswith("/ps"):
            continue
        try:
            ppid_map[int(info["PID"])] = int(info["PPID"]), int(info["WINPID"])
        except ValueError:
            ppid_map.clear()

    for pid, (_, winpid) in ppid_map.items():
        with suppress(NoSuchProcess, KeyError):
            root_proc = root_process(pid)
            procs.setdefault(root_proc, set()).add(Process(winpid))

    return procs
