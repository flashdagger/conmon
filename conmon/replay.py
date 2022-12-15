#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from psutil import Process

from conmon import json
from conmon.buildmon import BuildMonitor as BuildMonitorOrig
from conmon.conan import conmon_setting
from conmon.utils import freeze_json_object


def replay_logfile(setting: str, create_if_not_exists=True) -> Optional[Path]:
    logfile = conmon_setting(setting)
    if logfile is None:
        return None
    path = Path(logfile)
    replay_path = path.with_suffix(f".replay{path.suffix}")
    if not replay_path.is_file() and create_if_not_exists:
        shutil.copy2(path, replay_path)
    return replay_path


def replay_json(setting: str) -> Dict[str, Any]:
    logfile = replay_logfile(setting)
    if logfile is None:
        return {}
    with logfile.open("r", encoding="utf8") as fh:
        return json.load(fh)


class ReplayStreamHandler:
    def __init__(self):
        self.exhausted = False
        self.loglines = self._readlines(replay_logfile("conan.log"))

    @staticmethod
    def _readlines(logfile: Optional[Path]):
        if logfile is None:
            return

        loglines: List[str] = []
        pipe = "stdout"
        with logfile.open("r", encoding="utf8") as fh:
            for line in fh.readlines():
                match = re.fullmatch(
                    r"^(?P<state>\[[A-Z][a-z]+] )?(?:-+ <(?P<pipe>[a-z]+)> -+)?(?P<line>.*\n)$",
                    line,
                )
                assert match, repr(line)
                logline = match.group("line")
                if match.group("pipe"):
                    if loglines:
                        yield pipe, tuple(loglines)
                        loglines.clear()
                    pipe = match.group("pipe")
                else:
                    loglines.append(logline)

            yield pipe, tuple(loglines)

    def readboth(self):
        pipe, loglines = next(self.loglines, (None, ()))
        if not loglines:
            self.exhausted = True
            return (), ()
        if pipe == "stderr":
            return (), loglines
        return loglines, ()

    def readmerged(self):
        stdout, stderr = self.readboth()
        return stdout or stderr


class ReplayProcess(Process):
    def __init__(self, _pid=None):
        super().__init__(None)
        self.proc_json = replay_json("proc.json")
        self.log_json = replay_json("report.json")
        self._exitcode = self.log_json.get("conan", {}).get("returncode", -1)

    def cmdline(self):
        default = super().cmdline()
        return self.log_json.get("conan", {}).get("command", default)


class BuildMonitor(BuildMonitorOrig):
    _PROC_FILE = None

    def __init__(self, proc):
        super().__init__(proc)
        if not self._PROC_FILE:
            return
        with open(self._PROC_FILE, encoding="utf8") as fh:
            procs = json.load(fh)
        for proc_list in procs.values():
            for proc_info in proc_list:
                self.proc_cache[freeze_json_object(proc_info)] = None
