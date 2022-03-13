#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import json
import logging
import os
import platform
import re
import sys
import tempfile
from collections import defaultdict
from configparser import ConfigParser
from contextlib import suppress
from io import StringIO
from pathlib import Path
from subprocess import PIPE, check_output, CalledProcessError
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
)

import colorama  # type: ignore
import colorlog  # type: ignore
import psutil  # type: ignore

from . import __version__
from .buildmon import BuildMonitor, LOG as PLOG
from .compilers import LOG as BLOG, parse_warnings, COMPILER_REGEX_MAP

LOG = logging.getLogger("CONMON")
DECOLORIZE_REGEX = re.compile(r"[\u001b]\[\d{1,2}m", re.UNICODE)

PARENT_PROCS = [parent.name() for parent in psutil.Process(os.getppid()).parents()]


def filehandler(env, mode="w", hint="report"):
    path = os.getenv(env, os.devnull)
    if path != os.devnull:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        LOG.info("Saving %s to %s", hint, path)
    else:
        fmt = "export %s=<path>"
        for name in PARENT_PROCS:
            if name == "bash":
                break
            if name == "powershell.exe":
                fmt = "$env:%s='<path>'"
                break
            if name == "cmd.exe":
                fmt = "set %s=<path>"
                break
        LOG.info(f"use {fmt!r} to generate %s", env, hint)

    return open(path, mode)


class StrictConfigParser(ConfigParser):
    OPTCRE = re.compile(
        # allow only = or : for option separator
        r"(?P<option>[^=\n\s]+)\s*"
        r"(?P<vi>[=:]\s*)"
        r"(?P<value>.*)"
    )

    def optionxform(self, optionstr):
        return optionstr


class ConanParser:
    REF_PART_PATTERN = r"\w[\w\+\.\-]{1,50}"
    REF_REGEX = re.compile(
        rf"(?P<ref>(?P<name>{REF_PART_PATTERN})/(?P<version>{REF_PART_PATTERN})@"
        rf"?((?P<user>{REF_PART_PATTERN})/(?P<channel>{REF_PART_PATTERN}))?)"
    )
    STATES = {
        "configuration": {
            "start": lambda line: line == "Configuration:",
            "end": lambda line: not (re.match(r"(\[[\w.-]+]$)|[^\s:]+\s*[:=]", line)),
        },
        "build": {
            "start": lambda line: line == "Calling build()",
            "end": lambda line: re.match(r"Package '(\w+)' built$", line),
        },
        "export": {
            "start": lambda line: re.match(r"^exports[:_]", line),
            "end": lambda line: not re.match(r"^exports[:_]", line),
        },
        "package": {
            "start": lambda line: line == "Calling package()",
            "end": lambda line: re.match(r"^Created package revision ", line),
        },
    }

    def __init__(self):
        self.log: Dict[str, Any] = defaultdict(dict)
        self.last_line_len = 0
        self.ref = ""
        self.current_state: Optional[str] = None
        self.state_start = True
        self.state_end = False
        self.rest: str
        self.pending_line = False
        self.warnings = 0
        self.callbacks = []

    def print_line(self, line="", *, overwrite=False, indent=0, end="\n"):
        if not (line or end):
            return

        self.pending_line = not bool(end)
        spaces = " " * max(1, indent - self.last_line_len) if indent else ""

        if overwrite:
            if self.last_line_len:
                # clear the whole line
                print(colorama.ansi.clear_line(2), end="\r")
            else:
                print("")
            self.last_line_len = len(line)
        else:
            self.last_line_len = 0
        print(spaces + line, end=end)

    def build(self, line: str):
        if self.state_start:
            self.print_line(f"Building {self.ref} ", overwrite=True, end="")
            sys.stdout.flush()
            self.ref_log.setdefault("build", [])
            self.ref_log.setdefault("log", []).append(line)
            return

        if self.state_end:
            self.print_line("done", indent=39)
            sys.stdout.flush()
            self.ref_log.setdefault("log", []).append(line)
            return

        if not line:
            return

        match = re.fullmatch(
            r"((?P<progress>\[[0-9\s/%]+]\s)"
            r"(Building|Linking).*?)?"
            r"(?P<file>[\-.\w]+\.[a-zA-Z]{1,3})?",
            line.lstrip(),
        )
        if match and match.group():
            groupdict = match.groupdict()
            output = (
                (groupdict["progress"] or "") + groupdict["file"] + " "
                if groupdict["file"]
                else line
            )
            if self.warnings:
                self.print_line(
                    colorama.Fore.YELLOW + f"{self.warnings:3} warning(s)",
                    overwrite=False,
                    indent=35,
                    end="",
                )
            self.warnings = 0
            self.print_line(output, overwrite=True, end="")
        else:
            match = re.match(
                r"(?:^|.*?\s)(warning|error)[:\s]", line, flags=re.IGNORECASE
            )
            info = match.group(1)[0].upper() if match else ""
            if info == "E":
                prefix = "\n" if self.pending_line else ""
                self.print_line(colorama.Fore.RED + f"{prefix}{info} {line}")
            elif info == "W":
                self.warnings += 1
            else:
                self.print_line(info, end="")
        self.ref_log["build"].append(line)
        sys.stdout.flush()

    def package(self, line: str):
        if self.state_start:
            self.print_line(f"Packaging {self.ref} ", overwrite=True, end="")
            sys.stdout.flush()
            self.ref_log.setdefault("log", []).append(line)
            return
        if self.state_end:
            self.print_line("done", indent=39)
        match = re.match(r".*?([0-9a-f]{32,40})", line)
        if match:
            if "package revision" in match.group():
                self.ref_log["package_revision"] = match.group(1)
            else:
                self.ref_log["package_id"] = match.group(1)
        self.ref_log.setdefault("package", []).append(line)

    @staticmethod
    def parse_config(content: str) -> Mapping[str, Any]:
        mapping = dict()
        buffer = StringIO(content)
        config = StrictConfigParser()
        config.read_file(buffer, "profile.ini")

        for section in config.sections():
            mapping[section] = dict(config.items(section))

        return mapping

    def config(self, line):
        if self.state_start:
            assert line == "Configuration:"
            return

        if (
            "[env]" in self.log["config"].get("profile", ())
            and line
            and "=" not in line
        ):
            self.state_end = True

        if self.state_end:
            profile = self.log["config"].pop("profile")
            self.log["config"] = self.parse_config("\n".join(profile))
            self.current_state = None
            if line:
                self.process(line)
        else:
            self.log["config"].setdefault("profile", []).append(line)

    def parse_reference(self, line) -> str:
        ref_match = re.fullmatch(
            rf"\.*{self.REF_REGEX.pattern}[\s:]{{1,2}}(?P<rest>.*)",
            line,
        )

        if ref_match:
            ref, rest = ref_match.group("ref"), ref_match.group("rest")
        else:
            ref, rest = None, line

        if self.current_state:
            if ref != self.ref:
                rest = line
        else:
            self.ref = ref

        return rest

    @property
    def ref_log(self) -> Dict[str, Any]:
        match = self.REF_REGEX.fullmatch(self.ref)
        assert match
        groupdict = match.groupdict()
        return self.log["requirements"].setdefault(groupdict["name"], groupdict)

    def process(self, line: str):
        rest = self.parse_reference(line)

        if self.ref and self.ref in line and "is locked" in line:
            LOG.warning(line)

        self.state_start = False
        self.state_end = False
        if self.current_state is None:
            for state, test in self.STATES.items():
                if test["start"](rest):
                    self.current_state = state
                    self.state_start = True
                    break
        else:
            self.state_end = self.STATES[self.current_state]["end"](rest)

        if self.current_state == "build":
            self.build(rest)
        elif self.current_state == "package":
            self.package(rest)
        elif self.current_state == "configuration":
            self.config(line)
        elif self.ref:
            key = self.current_state or "log"
            self.ref_log.setdefault(key, []).append(rest)
        elif line:
            self.print_line(line)
            self.log.setdefault("stdout", []).append(line)

        if self.state_start or self.state_end:
            for callback in self.callbacks:
                assert callable(callback)
                callback(self.current_state, self.ref, self.state_start)

        if self.state_end:
            self.current_state = None

    def finalize(self, errs: str):
        err_lines = []
        idx = 0
        for match in COMPILER_REGEX_MAP["cmake"].finditer(errs + "\n"):
            err_lines.extend(errs[idx : match.span()[0]].splitlines())
            idx = match.span()[1]
            log_level = logging.getLevelName(match.group("severity").upper())
            if not isinstance(log_level, int):
                log_level = logging.getLevelName("ERROR")
            LOG.log(log_level, match.group(0))
        err_lines.extend(errs[idx:].splitlines())

        if self.current_state:
            for callback in self.callbacks:
                assert callable(callback)
                callback(self.current_state, self.ref, False)

        log_level = logging.ERROR
        lines: List[str] = []
        for line in err_lines:
            if not line:
                continue
            match = re.match(
                rf"(?:{self.REF_REGEX.pattern}:\s+)?"
                rf"(?P<severity>ERROR|WARN):\s+(?P<msg>.*)",
                line,
            )
            if match:
                if lines:
                    LOG.log(log_level, "\n".join(lines))
                    lines.clear()

                ref = match.group("name")
                log_level = logging.getLevelName(match.group("severity"))

                if ref:
                    self.log["requirements"].setdefault(ref, {}).setdefault(
                        "log", []
                    ).append(": ".join((match.group("severity"), match.group("msg"))))
                    line = ": ".join((match.group("ref"), match.group("msg")))
                else:
                    line = match.group("msg")

            lines.append(line)

        if lines:
            LOG.log(log_level, "\n".join(lines))
            lines.clear()


def check_conan() -> str:
    try:
        out = check_output(
            [sys.executable, *"-m conans.conan --version".split()],
            universal_newlines=True,
        )
    except CalledProcessError as exc:
        LOG.error("%s", exc.output)
        sys.exit(1)
    except FileNotFoundError:
        LOG.error("The 'conan' command cannot be executed.")
        sys.exit(1)

    version = re.search(r"[12](\.\d+){2}", out)
    assert version
    return version.group()


def register_callback(process: psutil.Process, parser: ConanParser):
    # run monitor in its own thread
    buildmon: Optional[BuildMonitor] = None

    def callback(state: Optional[str], _ref: str, start_not_end: bool):
        nonlocal buildmon
        if state != "build":
            assert buildmon is None
            return
        if start_not_end:
            buildmon = BuildMonitor(process)
            buildmon.start()
            return
        assert buildmon is not None
        buildmon.finish.set()
        buildmon.join()
        tu_list = buildmon.translation_units

        package_re = re.compile(r".*?[a-f0-9]{40}")
        for unit in tu_list:
            src_match = package_re.match(unit["sources"][0])
            includes, unit["includes"] = unit.get("includes", []), []
            for include in sorted(includes):
                inc_match = package_re.match(include)
                if (
                    src_match
                    and include.startswith(src_match.group())
                    or inc_match is None
                ):
                    unit["includes"].append(include)
                else:
                    unit.setdefault("system_includes", []).append(include)

        proc_fh = filehandler("CONMON_PROC_JSON", hint="process debug json")
        json.dump(
            list(buildmon.proc_cache.values()),
            proc_fh,
            indent=2,
        )
        proc_fh.close()

        ref_log = parser.ref_log
        ref_log["translation_units"] = tu_list
        ref_log["warnings"] = parse_warnings_conan(
            ref_log["build"], parser.log["config"]
        )
        buildmon = None

    parser.callbacks.append(callback)


def monitor(args: List[str]) -> int:
    # prevent MsBuild from allocating workers
    # which are not children of the parent process
    os.environ["MSBUILDDISABLENODEREUSE"] = "1"
    # tell conan not to prompt for user input
    os.environ["CONAN_NON_INTERACTIVE"] = "1"

    if not os.getenv("CONAN_TRACE_FILE"):
        tmp_file = tempfile.NamedTemporaryFile("w", delete=False)
        os.environ["CONAN_TRACE_FILE"] = tmp_file.name
        tmp_file.close()

    conan_version = check_conan()
    full_command = [sys.executable, "-m", "conans.conan", *args]
    process = psutil.Popen(
        full_command, stdout=PIPE, stderr=PIPE, universal_newlines=True, bufsize=0
    )

    parser = ConanParser()
    parser.log.update(
        dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.version_info)),
            conan_version=conan_version,
        )
    )
    register_callback(process, parser)

    raw_fh = filehandler("CONMON_CONAN_LOG", hint="raw conan output")
    for line in iter(process.stdout.readline, ""):
        raw_fh.write(line)
        parser.process(DECOLORIZE_REGEX.sub("", line.rstrip()))

    _, errors = process.communicate(input=None, timeout=None)
    raw_fh.write(errors)
    raw_fh.close()

    parser.finalize(errors.rstrip())
    returncode = process.wait()
    tracelog = []

    if os.getenv("CONAN_TRACE_FILE"):
        with open(os.environ["CONAN_TRACE_FILE"]) as fh:
            for line in fh.readlines():
                action = json.loads(line)
                if action["_action"] in {"REST_API_CALL", "UNZIP"}:
                    continue
                ref_id = action.get("_id")
                if not ref_id:
                    tracelog.append(action)
                    continue
                name, *_ = ref_id.split("/", maxsplit=1)
                pkg_id = ref_id.split(":", maxsplit=1)
                req = parser.log["requirements"].setdefault(name, {})
                if len(pkg_id) == 2:
                    req["package_id"] = pkg_id[1]
                req.setdefault("actions", []).append(action["_action"])

        with suppress(FileNotFoundError):
            if "tmp" in os.environ["CONAN_TRACE_FILE"]:
                os.unlink(os.environ["CONAN_TRACE_FILE"])
                os.unlink(os.environ["CONAN_TRACE_FILE"] + ".lock")

    parser.log.update(
        dict(
            stderr=errors.splitlines(),
            tracelog=tracelog,
            command=full_command,
            returncode=returncode,
        )
    )

    json_fh = filehandler("CONMON_REPORT_JSON", hint="report json")
    json.dump(parser.log, json_fh, indent=2)
    json_fh.close()

    return returncode


def parse_warnings_conan(
    log: Iterable[str], profile: Dict[str, Any]
) -> List[Dict[str, Any]]:
    if "settings" not in profile:
        return []
    compiler = profile["settings"].get("compiler")

    if "clang-cl" in profile.get("env", {}).get("CC", ""):
        compiler_type = "clang-cl"
    elif compiler in {"clang", "gcc", "cc"}:
        compiler_type = "gnu"
    elif compiler == "Visual Studio":
        compiler_type = "vs"
    else:
        raise Exception(f"unknown compiler {compiler!r}")

    return parse_warnings("\n".join(log), compiler=compiler_type)


def main() -> int:
    """main entry point for console script"""

    args = parse_args(sys.argv[1:])

    colorama_args = dict(autoreset=True, convert=None, strip=None, wrap=True)
    # prevent messing up colorama settings
    if os.getenv("CI"):
        colorama.deinit()
        colorama_args.update(dict(strip=False, convert=False))
    colorama.init(**colorama_args)

    handler = logging.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter("%(log_color)s[%(name)s:%(levelname)s] %(message)s")
    )

    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG)
    BLOG.addHandler(handler)
    BLOG.setLevel(logging.INFO)
    PLOG.addHandler(handler)
    PLOG.setLevel(logging.INFO)

    if os.getenv("CI"):
        LOG.info("Running in Gitlab CI")

    return monitor(args.cmd)


def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "Run conan as monitored process with parsed JSON output"
    parser = argparse.ArgumentParser(description=description, prog="conmon")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s version {__version__}"
    )
    parser.add_argument(
        "cmd",
        metavar="<command>",
        help="conan command and options",
        nargs=argparse.REMAINDER,
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
