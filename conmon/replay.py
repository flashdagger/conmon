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
from .streams import ProcessStreamHandler


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


class ReplayStreamHandler(ProcessStreamHandler):
    def __init__(self, proc):
        super().__init__(proc)
        self._exhausted = False
        self.loglines = self._readlines(replay_logfile("conan.log"))

    @staticmethod
    def _readlines(logfile: Optional[Path]):
        if logfile is None:
            return

        pipe = "stdout"
        timestamp = 0.0
        loglines: List[str] = []
        with logfile.open("r", encoding="utf8") as fh:
            for line in fh:
                match = re.fullmatch(
                    r"^(?P<state>\[(?:[A-Z][a-z]+)+] )?"
                    r"(?:-+ <(?P<pipe>[a-z]+)@?(?P<timestamp>\d+\.\d+)?> -+)?"
                    r"(?P<line>.*\n)$",
                    line,
                )
                assert match, repr(line)
                if match.group("pipe"):
                    if loglines:
                        yield pipe, timestamp, tuple(loglines)
                        loglines.clear()
                    pipe, timestamp_str = match.group("pipe", "timestamp")
                    try:
                        timestamp = float(timestamp_str)
                    except (TypeError, ValueError):
                        timestamp = -1.0
                else:
                    loglines.append(match.group("line"))

        if loglines:
            yield pipe, timestamp, tuple(loglines)

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def iterpipes(self, timeout=0.0, total=False):
        yield from self.loglines
        self._exhausted = True


class ReplayPopen(subprocess.Popen):
    def __init__(self, args, **_kwargs):
        self.stdout = None
        self.stderr = None
        conan = replay_json("report.json", "conan")
        self.args = conan.get("command", args)
        self.returncode = conan.get("returncode", "<unknown>")

    @property
    def pid(self):
        return None


class ReplayCommand(Command):
    def __init__(self):
        super().__init__()
        self.proc_json = replay_json("proc.json")

    def run(self, args, **kwargs):
        proc = self.proc = ReplayPopen([])
        self.streams = ReplayStreamHandler(proc)

    def is_running(self):
        return not self.streams.exhausted

    def wait(self, **_kwargs):
        return self.proc.returncode if self.proc else -1

    @property
    def returncode(self):
        return self.proc.returncode if self.streams.exhausted else None
