#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import re
import sys
from typing import List

import psutil

from conmon import json
from conmon.buildmon import BuildMonitor


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
        proc_list = json.load(fh)
    for proc in proc_list:
        buildmon.check_process(proc)
    with open("replayed_tus.json", mode="w", encoding="utf8") as fh:
        json.dump({"build": buildmon.translation_units}, fh, indent=4)


def find_tus(report):
    mapping = {}
    for name, log in report["requirements"].items():
        for build in ("build", "test_build"):
            if build not in log:
                continue
            key = f"{name}.{build}"
            mapping[key] = log[build]["translation_units"]

    return mapping


def main() -> int:
    """main entry point for console script"""
    args = parse_args(sys.argv[1:])
    replay_log(args.logfile)
    if args.procfile:
        parse_procs(args.procfile)
    if args.reportfile:
        with open(args.reportfile, encoding="utf8") as fh:
            report = json.load(fh)
        with open("report_tus.json", mode="w", encoding="utf8") as fh:
            json.dump(find_tus(report), fh, indent=4)
        returncode = report["conan"]["returncode"]
    else:
        returncode = 0

    return returncode


def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "Simulate a conmon run"
    parser = argparse.ArgumentParser(
        description=description, prog="replay", add_help=True
    )
    parser.add_argument(
        "logfile",
        help="the conan output logfile created by conmon",
    )
    parser.add_argument(
        "--procfile",
        help="the debug process JSON file created by conmon",
    )
    parser.add_argument(
        "--reportfile",
        help="the report JSON file created by conmon",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
