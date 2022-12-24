#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import shutil
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
    if not replay_path.is_file() and create_if_not_exists:
        shutil.copy2(path, replay_path)
    return replay_path


def replay_json(setting: str, key: Optional[str] = None) -> Dict[str, Any]:
    logfile = replay_logfile(setting)
    if logfile is None:
        return {}
    with logfile.open("r", encoding="utf8") as fh:
        if key is None:
            return json.load(fh)
        return json_stream.load(fh, persistent=True).get(key, {})


# pylint: disable=too-few-public-methods
class ReplayStreamHandler(ProcessStreamHandler):
    def __init__(self, *_args):
        super().__init__()
        self._exhausted = False
        self.loglines = self._readlines(replay_logfile("conan.log"))

    @staticmethod
    def _readlines(logfile: Optional[Path]):
        if logfile is None:
            return

        pipe = "stdout"
        loglines: List[str] = []
        with logfile.open("r", encoding="utf8") as fh:
            for line in fh:
                match = re.fullmatch(
                    r"^(?P<state>\[[A-Z][a-z]+] )?"
                    r"(?:-+ <(?P<pipe>[a-z]+)[^>]*> -+)?"
                    r"(?P<line>.*\n)$",
                    line,
                )
                assert match, repr(line)
                if match.group("pipe"):
                    if loglines:
                        yield pipe, tuple(loglines)
                        loglines.clear()
                    pipe = match.group("pipe")
                else:
                    loglines.append(match.group("line"))

        if loglines:
            yield pipe, tuple(loglines)

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def readboth(self, block=False, block_first=False):
        pipe, loglines = next(self.loglines, (None, ()))
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
