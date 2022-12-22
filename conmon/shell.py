#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import sys
from contextlib import suppress
from subprocess import PIPE, Popen, TimeoutExpired
from typing import Optional

from psutil import Process

from .logging import colorama_init
from .utils import ProcessStreamHandler


def exceptook(type_, value, traceback):
    for child in Process().children():
        print("killing", child.name())
        child.kill()
    sys.__excepthook__(type_, value, traceback)


sys.excepthook = exceptook


class Command:
    def __init__(self) -> None:
        self.proc: Popen = None  # type: ignore
        self.streams: ProcessStreamHandler = None  # type: ignore
        self.returned_error = False

    def __repr__(self):
        proc = self.proc
        name = self.__class__.__name__
        if proc:
            return f"<{name}: returncode: {self.returncode} args: {proc.args}>"
        return f"<{name}>"

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
        self.returned_error = returncode != 0
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
            self.streams.readboth()

        assert self.proc.stdin
        self.proc.stdin.write(f"{cmd}\n")

    def receive(self, timeout: Optional[float] = None) -> str:
        stdout, stderr = self.streams.readboth(timeout=timeout)
        if stderr:
            self.exit()
            raise self.Error("".join(stderr))
        return "".join(stdout)

    def exit(self) -> int:
        if self.is_running():
            with suppress(TimeoutExpired):
                self.proc.communicate("exit\n", timeout=0.2)
        colorama_init(wrap=True)
        return self.wait()
