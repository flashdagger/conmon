#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import sys
from contextlib import suppress
from subprocess import PIPE, Popen, TimeoutExpired
from typing import TYPE_CHECKING, Dict, Iterator, Optional, Set, Tuple

from psutil import NoSuchProcess, Process

from .logging import colorama_init
from .utils import ProcessStreamHandler

# pylint: disable=invalid-name
if TYPE_CHECKING:
    ignore = ()
    union = attr = 0


def exceptook(type_, value, traceback):
    for child in Process().children():
        print("killing", child.name())
        child.kill()
    sys.__excepthook__(type_, value, traceback)


sys.excepthook = exceptook


class Command:
    def __init__(self) -> None:
        self.proc: Optional[Popen] = None
        self.streams: Optional[ProcessStreamHandler] = None

    def __repr__(self):
        proc = self.proc
        name = self.__class__.__name__
        if proc:
            return str(Process(proc.pid)).replace("psutil.Process", name)
        return f"{name}()"

    def run(self, args, **kwargs):
        if self.is_running():
            self.wait(kill=True)

        options = dict(
            stdout=PIPE,
            stderr=PIPE,
            stdin=PIPE,
            encoding="utf-8",
            bufsize=0,
        )
        options.update(kwargs)
        # pylint: disable=consider-using-with
        proc = Popen(
            args,
            **options,
        )
        self.streams = ProcessStreamHandler(proc)
        self.proc = proc

    def is_running(self):
        with suppress(AttributeError):
            poll = self.proc.poll()
            return poll is None
        return False

    @property
    def returncode(self):
        return self.proc and self.proc.returncode

    def wait(self, *, kill=False, terminate=False, timeout=None):
        if self.proc is None:
            return None
        if terminate:
            self.proc.kill()
        elif kill:
            self.proc.terminate()
        returncode = self.proc.wait(timeout=timeout)
        return returncode

    def __del__(self):
        self.wait(kill=True)


class Shell(Command):
    class Error(Exception):
        pass

    def run(self, args, **kwargs):
        super().run(args, **kwargs)
        # terminal is getting messed up by msys
        colorama_init(wrap=False)

    def send(self, cmd: str, flush=True):
        if not self.is_running():
            raise self.Error("Process is not running")

        if flush:
            self.streams.readboth()  # type: ignore [union-attr]

        self.proc.stdin.write(f"{cmd}\n")  # type: ignore [union-attr]

    def receive(self, timeout: Optional[float] = None) -> str:
        stdout, stderr = self.streams.readboth(timeout=timeout)  # type: ignore [union-attr]
        if stderr:
            self.exit()
            raise self.Error("".join(stderr))
        return "".join(stdout)

    def exit(self) -> int:
        if self.is_running():
            with suppress(TimeoutExpired):
                self.proc.communicate("exit\n", timeout=0.2)  # type: ignore [union-attr]
        colorama_init(wrap=True)
        return self.proc.wait()  # type: ignore [union-attr]


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
