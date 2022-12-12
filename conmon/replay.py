#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, List
from unittest.mock import patch

from conmon import __version__, json
from conmon.__main__ import main as conmon_main
from conmon.buildmon import BuildMonitor as BuildMonitorOrig
from conmon.conan import conmon_setting
from conmon.utils import freeze_json_object

DEFAULT_LOG = {
    "logfile": conmon_setting("conan_log"),
    "--procfile": conmon_setting("proc_json"),
    "--reportfile": conmon_setting("report_json"),
}


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


def replay_log(filename: str):
    with open(filename, encoding="utf8") as fh:
        output = sys.stdout
        errlines: List[str] = []
        for line in fh.readlines():
            match = re.fullmatch(
                r"^(?P<state>\[[A-Z][a-z]+] )?(?:-+ <(?P<pipe>[a-z]+)> -+)?(?P<line>.*\n)$",
                line,
            )
            assert match
            pipe, logline = match.group("pipe", "line")
            if pipe:
                output = sys.stderr if pipe == "stderr" else sys.stdout
                if output is sys.stdout and errlines:
                    sys.stderr.write("".join(errlines))
                    sys.stderr.flush()
                    errlines.clear()
            elif output is sys.stderr:
                errlines.append(logline)
            else:
                sys.stdout.flush()
                time.sleep(0.002)
                sys.stdout.write(logline)

        if errlines:
            print(logline, file=sys.stderr)


def find_tus(report):
    mapping = {}
    for name, log in report["requirements"].items():
        for build in ("build", "test_build"):
            if build not in log:
                continue
            key = f"{name}.{build}"
            mapping[key] = log[build]["translation_units"]

    return mapping


def call_cmd_and_version():
    return [sys.executable, "-m", "conmon.replay", "--detached"], __version__


def run_process(args: argparse.Namespace) -> int:
    returncode = 0
    replay_log(args.logfile)

    if args.reportfile:
        with open(args.reportfile, encoding="utf8") as fh:
            report = json.load(fh)
            returncode = report["conan"]["returncode"]

    return returncode


def main() -> int:
    """main entry point for console script"""
    parsed_args = parse_args(args=sys.argv[1:])

    if parsed_args.detached:
        return run_process(parsed_args)

    # we copy the log files if they can be overwritten
    sys.argv = sys.argv[:1]
    for key in ("logfile", "--procfile", "--reportfile"):
        value = getattr(parsed_args, key.lstrip("-"))
        if value is None:
            continue
        path = Path(value)
        if not path.is_file():
            raise ValueError(f"{key} {value!r} is not an existing file")
        if path == Path(DEFAULT_LOG[key]):
            replay_path = path.with_suffix(f".replay{path.suffix}")
            if not replay_path.exists():
                shutil.copy2(path, replay_path)
        else:
            replay_path = path

        if key == "--procfile":
            setattr(BuildMonitor, "_PROC_FILE", str(replay_path))

        if key.startswith("--"):
            sys.argv.append(key)
        sys.argv.append(str(replay_path))

    with (
        patch("conmon.conan.call_cmd_and_version", call_cmd_and_version),
        patch("conmon.buildmon.BuildMonitor", BuildMonitor),
    ):
        return conmon_main()


class FileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values and not os.path.isfile(values):
            raise argparse.ArgumentError(self, f"{values!r} is not a file")
        setattr(namespace, self.dest, values)


# noinspection PyTypeChecker
def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "Simulate a conmon run"
    parser = argparse.ArgumentParser(
        description=description,
        prog="replay",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    logfile_default = DEFAULT_LOG["logfile"]
    extra_kwargs: Any = {"nargs": "?"} if logfile_default else {}
    parser.add_argument(
        "logfile",
        action=FileAction,
        default=logfile_default,
        help="the conan output logfile created by conmon",
        **extra_kwargs,
    )
    parser.add_argument(
        "--procfile",
        "-p",
        action=FileAction,
        default=DEFAULT_LOG["--procfile"],
        help="the debug process JSON file created by conmon",
    )
    parser.add_argument(
        "--reportfile",
        "-r",
        action=FileAction,
        default=DEFAULT_LOG["--reportfile"],
        help="the report JSON file created by conmon",
    )
    parser.add_argument(
        "--detached",
        action="store_true",
        help="run the actual subprocess",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
