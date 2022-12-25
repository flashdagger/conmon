#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

import json_stream

from . import json
from .conan import conmon_setting
from .shell import Command
from .utils import ProcessStreamHandler


def replay_logfile(setting: str, create_if_not_exists=True) -> Optional[Path]:
    logfile = conmon_setting(setting)
    if logfile is None:
        return None
    path = Path(logfile)
    replay_path = path.with_suffix(f".replay{path.suffix}")
    if not replay_path.exists() and create_if_not_exists:
        path.rename(replay_path)
    return replay_path


def replay_json(setting: str, key: Optional[str] = None) -> Dict[str, Any]:
    logfile = replay_logfile(setting)
    if logfile is None:
        return {}
    fh = logfile.open("r", encoding="utf8")
    stream = json_stream.load(fh, persistent=not key)
    if key:
        with fh:
            return json.manifest(stream.get(key, {}))
    return stream


# pylint: disable=too-few-public-methods
class ReplayStreamHandler(ProcessStreamHandler):
    class DummyPipe:
        def __init__(self):
            self.last_timestamp = 0.0

    def __init__(self, *_args):
        super().__init__()
        self.stdout = self.DummyPipe()
        self.stderr = self.DummyPipe()
        self._exhausted = False
        self.loglines = self._readlines(replay_logfile("conan.log"))

    @staticmethod
    def _readlines(logfile: Optional[Path]):
        if logfile is None:
            return

        pipe = "stdout"
        timestamp = None
        loglines: List[str] = []
        with logfile.open("r", encoding="utf8") as fh:
            for line in fh:
                match = re.fullmatch(
                    r"^(?P<state>\[[A-Z][a-z]+] )?"
                    r"(?:-+ <(?P<pipe>[a-z]+)@?(?P<timestamp>\d+\.\d+)?> -+)?"
                    r"(?P<line>.*\n)$",
                    line,
                )
                assert match, repr(line)
                if match.group("pipe"):
                    if loglines:
                        yield pipe, timestamp, tuple(loglines)
                        loglines.clear()
                    pipe, timestamp = match.group("pipe", "timestamp")
                else:
                    loglines.append(match.group("line"))

        if loglines:
            yield pipe, timestamp, tuple(loglines)

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def readboth(self, block=False, block_first=False):
        pipe, timestamp_str, loglines = next(self.loglines, (None, None, ()))
        if timestamp_str:
            timestamp = float(timestamp_str)
            obj = self.stderr if pipe == "stderr" else self.stdout
            obj.last_timestamp = timestamp

        if not loglines:
            self._exhausted = True
            return (), ()
        if pipe == "stderr":
            return (), loglines
        return loglines, ()


class ReplayPopen(subprocess.Popen):
    def __init__(self, args, **_kwargs):
        conan = replay_json("report.json", "conan")
        self.args = conan.get("command", args)
        self.returncode = conan.get("returncode", -1)

    @property
    def pid(self):
        return None


class ReplayCommand(Command):
    def __init__(self):
        super().__init__()
        self.proc_json = replay_json("proc.json")

    def run(self, args, **kwargs):
        self.streams = ReplayStreamHandler()
        self.proc = ReplayPopen([])

    def is_running(self):
        return not self.streams.exhausted

    def wait(self, **_kwargs):
        return self.proc.returncode

    @property
    def returncode(self):
        return self.proc.returncode if self.streams.exhausted else None
