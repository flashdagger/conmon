#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import os
import re
import shutil
import sys
from tempfile import TemporaryDirectory
from typing import Any, List
from unittest.mock import patch

import psutil

from conmon import json, __version__
from conmon.__main__ import main as conmon_main
from conmon.buildmon import BuildMonitor
from conmon.conan import conmon_setting


def replay_log(filename: str):
    with open(filename, encoding="utf8") as fh:
        output = sys.stdout
        for line in fh.readlines():
            match = re.fullmatch(
                r"^(?P<state>\[[A-Z][a-z]+] )?(?:-+ <(?P<pipe>[a-z]+)> -+)?(?P<line>.*)\n$",
                line,
            )
            assert match
            pipe, logline = match.group("pipe", "line")
            if pipe:
                output = sys.stderr if pipe == "stderr" else sys.stdout
                continue
            print(logline, file=output)


def parse_procs(filename):
    buildmon = BuildMonitor(psutil.Process())
    with open(filename, encoding="utf8") as fh:
        procs = json.load(fh)
    for _requirement, proc_list in procs.items():
        for proc in proc_list:
            buildmon.check_process(proc)
    # with open("replayed_tus.json", mode="w", encoding="utf8") as fh:
    #    json.dump({"build": buildmon.translation_units}, fh, indent=4)


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

    if args.procfile:
        parse_procs(args.procfile)
    if args.reportfile:
        with open(args.reportfile, encoding="utf8") as fh:
            report = json.load(fh)
            returncode = report["conan"]["returncode"]
        # with open("report_tus.json", mode="w", encoding="utf8") as fh:
        #     json.dump(find_tus(report), fh, indent=4)

    return returncode


def main() -> int:
    """main entry point for console script"""
    parsed_args = parse_args(args=sys.argv[1:])

    if parsed_args.detached:
        return run_process(parsed_args)

    sys.argv = sys.argv[:1]
    with TemporaryDirectory() as temp_dir:
        # we copy the log files to a temporary directory
        for key in ("logfile", "--procfile", "--reportfile"):
            value = getattr(parsed_args, key.lstrip("-"))
            if value is None:
                continue
            if not os.path.isfile(value):
                raise ValueError(f"{key} {value!r} is not a file")
            shutil.copy2(value, temp_dir)
            if key.startswith("--"):
                sys.argv.append(key)
            sys.argv.append(os.path.join(temp_dir, os.path.basename(value)))

        with patch("conmon.conan.call_cmd_and_version", call_cmd_and_version):
            return conmon_main()


class FileAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if values and not os.path.isfile(values):
            raise argparse.ArgumentError(self, f"{values!r} is not a file")
        setattr(namespace, self.dest, values)


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

    logfile_default = conmon_setting("conan_log")
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
        default=conmon_setting("proc_json"),
        help="the debug process JSON file created by conmon",
    )
    parser.add_argument(
        "--reportfile",
        "-r",
        action=FileAction,
        default=conmon_setting("report_json"),
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
