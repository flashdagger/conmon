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
import time
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
LOG_HINTS = {}


def filehandler(env, mode="w", hint="report"):
    path = os.getenv(env, os.devnull)
    if path != os.devnull:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        LOG_HINTS.setdefault(f"saved {hint} to {path!r}")
    else:
        path = ".".join(env.lower().split("_")[-2:])
        fmt = "export {}={}"
        for name in PARENT_PROCS:
            if name == "bash":
                break
            if name == "powershell.exe":
                fmt = "$env:{}='{}'"
                break
            if name == "cmd.exe":
                fmt = "set {}={}"
                break
        template = f"hint: use {fmt!r} to save {{}}"
        LOG_HINTS.setdefault(template.format(env, path, hint))

    return open(path, mode, encoding="utf8")


class StopWatch:
    def __init__(self):
        self._last_ts = time.time()

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self._last_ts

    def timespan_elapsed(self, timespan_s: float) -> bool:
        if self.elapsed_seconds >= timespan_s:
            self._last_ts = time.time() - self.elapsed_seconds % timespan_s
            return True

        return False

    def reset(self):
        self._last_ts = time.time()


class StrictConfigParser(ConfigParser):
    OPTCRE = re.compile(
        # allow only = or : for option separator
        r"(?P<option>[^=\n\s]+)\s*"
        r"(?P<vi>[=:]\s*)"
        r"(?P<value>.*)"
    )

    def optionxform(self, optionstr):
        return optionstr


class ScreenWriter:
    def __init__(self):
        self._last_line = ""

    def reset(self):
        self._last_line = ""

    def print(self, line: str, overwrite=False, indent=-1):
        append = indent >= 0
        spaces = " " * max(0, indent - len(self._last_line)) if append else ""

        if self._last_line and not append:
            printed_line = "\r" + colorama.ansi.clear_line(2) + line
        else:
            printed_line = spaces + line

        if overwrite:
            self._last_line = line
            print(printed_line, end="")
            sys.stdout.flush()
        else:
            self._last_line = ""
            print(printed_line)


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
        self.ref = ""
        self.last_ref = ""
        self.current_state: Optional[str] = None
        self.state_start = True
        self.state_end = False
        self.rest: str
        self.screen = ScreenWriter()
        self.warnings = 0
        self.callbacks = []

    def build(self, line: str):
        if self.state_start:
            self.screen.print(f"Building {self.ref} ", overwrite=True)
            self.ref_log.setdefault("build", [])
            self.ref_log.setdefault("log", []).append(line)
            return

        if self.state_end:
            self.screen.print("done", indent=39)
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
                self.screen.print(
                    colorama.Fore.YELLOW + f"{self.warnings:3} warning(s)",
                    indent=35,
                )
            self.warnings = 0
            self.screen.print(output, overwrite=True)
        else:
            match = re.match(
                r"(?:^|.*?\s)(warning|error)[:\s]", line, flags=re.IGNORECASE
            )
            info = match.group(1)[0].upper() if match else ""
            if info == "E":
                self.screen.print(colorama.Fore.RED + f"{info} {line}")
            elif info == "W":
                self.warnings += 1
            elif info:
                self.screen.print(info, indent=0)
        self.ref_log["build"].append(line)

    def package(self, line: str):
        if self.state_start:
            self.screen.print(f"Packaging {self.ref} ", overwrite=True)
            sys.stdout.flush()
            self.ref_log.setdefault("log", []).append(line)
            return
        if self.state_end:
            self.screen.print("done", indent=39)
        match = re.match(r".*?([0-9a-f]{32,40})", line)
        if match:
            if "package revision" in match.group():
                self.ref_log["package_revision"] = match.group(1)
            else:
                self.ref_log["package_id"] = match.group(1)
        self.ref_log.setdefault("package", []).append(line)

    @staticmethod
    def parse_config(content: str) -> Mapping[str, Any]:
        mapping = {}
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
            self.last_ref = ref
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

        match_download = re.match(r"Downloading conan\w+\.[a-z]{2,3}$", rest)
        if self.current_state == "build":
            self.build(rest)
        elif self.current_state == "package":
            self.package(rest)
        elif self.current_state == "configuration":
            self.config(line)
        elif self.ref:
            key = self.current_state or "log"
            self.ref_log.setdefault(key, []).append(rest)
        elif match_download and self.last_ref:
            self.screen.print(
                f"{self.last_ref}: {match_download.group()}", overwrite=True
            )
        else:
            if line:
                self.log.setdefault("stdout", []).append(line)
            self.screen.print(line)

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
        tmp_file, os.environ["CONAN_TRACE_FILE"] = tempfile.mkstemp()
        os.close(tmp_file)

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
    stopwatch = StopWatch()
    for line in iter(process.stdout.readline, ""):
        raw_fh.write(line)
        if stopwatch.timespan_elapsed(1.0):
            raw_fh.flush()
        parser.process(DECOLORIZE_REGEX.sub("", line.rstrip()))

    _, errors = process.communicate(input=None, timeout=None)
    raw_fh.write(errors)
    raw_fh.close()

    parser.finalize(errors.rstrip())
    returncode = process.wait()
    tracelog = []

    if os.getenv("CONAN_TRACE_FILE"):
        with open(os.environ["CONAN_TRACE_FILE"], encoding="utf8") as fh:
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

    with filehandler("CONMON_REPORT_JSON", hint="report json") as fh:
        json.dump(parser.log, fh, indent=2)

    for hint in LOG_HINTS:
        LOG.info(hint)

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

    # general logger
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG)
    # conan build logger
    BLOG.addHandler(handler)
    BLOG.setLevel(logging.INFO)
    # buildmon process logger
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
