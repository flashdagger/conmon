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
from io import StringIO
from itertools import chain
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

from conmon.utils import (
    StopWatch,
    StrictConfigParser,
    ScreenWriter,
    AsyncPipeReader,
    shorten,
)
from . import __version__
from .buildmon import BuildMonitor, LOG as PLOG
from .compilers import (
    LOG as BLOG,
    parse_compiler_warnings,
    parse_cmake_warnings,
    filter_compiler_warnings,
)

LOG = logging.getLogger("CONMON")
DECOLORIZE_REGEX = re.compile(r"[\u001b]\[\d{1,2}m", re.UNICODE)

PARENT_PROCS = [parent.name() for parent in psutil.Process(os.getppid()).parents()]
LOG_HINTS = {}


def filehandler(env, mode="w", hint="report"):
    path = os.getenv(env)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        LOG_HINTS.setdefault(f"saved {hint} to {path!r}")
    else:
        hint_path = ".".join(env.lower().split("_")[-2:])
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
        LOG_HINTS.setdefault(template.format(env, hint_path, hint))

    return open(path or os.devnull, mode, encoding="utf8")


class ConanParser:
    REF_PART_PATTERN = r"\w[\w\+\.\-]{1,50}"
    REF_REGEX = re.compile(
        rf"""(?x)
            (?P<ref>
            (?P<name>{REF_PART_PATTERN})/
            (?P<version>{REF_PART_PATTERN})@?
            (
                (?P<user>{REF_PART_PATTERN})/
                (?P<channel>{REF_PART_PATTERN})
             )?
         )
        """
    )
    BUILD_STATUS_REGEX = re.compile(
        r"""(?x)
            (?:
                (?P<status>
                    \[[0-9\s/%]+] | \ +CC(?:LD)?(?=\ )
                )?  # ninja, cmake or automake
                .*? # msbuild prints only the filename
            )?
            (?P<file>
                [\-.\w/\\]+ (?(status) $ | \.(?:cpp|c)$ )
            )
    """
    )
    BUILD_STATUS_REGEX2 = re.compile(
        r"""(?x)
            (?P<status>(?!))?
            .*\ -c\ 
            (?P<file>
                [\-.\w/\\]+ \. (?:cpp|c) (?=\ ) 
            )
        """
    )
    WARNING_REGEX = re.compile(
        rf"""
        (?:{REF_REGEX.pattern}:\ +)?
        (?P<severity>ERROR|WARN):\ +(?P<info>.*)
        """.replace(
            "(?:(?x)", "(?x)(?:"
        ),
        re.VERBOSE,
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
        self._resolved = False

    def build(self, line: str):
        if self.state_start:
            self.screen.print(f"Building {self.ref}")
            self.ref_log.setdefault("build", [])
            self.ref_log.setdefault("stdout", []).append(line)
            return

        if self.state_end:
            self.ref_log.setdefault("stdout", []).append(line)
            self.screen.print("", overwrite=True)
            sys.stdout.flush()
            return

        if not line:
            return

        match = self.BUILD_STATUS_REGEX.fullmatch(line) or self.BUILD_STATUS_REGEX2.match(line)
        if match:
            status, file = match.groups()
            prefix = f"{status.strip()} " if status else ""
            output = shorten(
                file,
                width=40,
                template=f"{prefix}{{}} ",
                strip_left=True,
                placeholder="...",
            )
            output = re.sub(r"\.\.\.[^/\\]+(?=[/\\])", "...", output)  # shorten at path separator
            if self.warnings:
                self.screen.print(
                    colorama.Fore.YELLOW + f"{self.warnings:4} warning(s)",
                    indent=40,
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
            self.screen.print(f"Packaging {self.ref} ")
            self.ref_log.setdefault("stdout", []).append(line)
            return
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

    @property
    def compiler_type(self) -> Optional[str]:
        profile = self.log.get("config", {})
        if "settings" not in profile:
            return None

        compiler = profile["settings"].get("compiler")
        if "clang-cl" in profile.get("env", {}).get("CC", ""):
            compiler_type = "clang-cl"
        elif compiler in {"clang", "gcc", "cc"}:
            compiler_type = "gnu"
        elif compiler == "Visual Studio":
            compiler_type = "vs"
        else:
            compiler_type = None

        return compiler_type

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
        if not self.ref:
            return self.log

        match = self.REF_REGEX.fullmatch(self.ref)
        assert match
        groupdict = match.groupdict()
        return self.log["requirements"].setdefault(groupdict["name"], groupdict)

    def process(self, line: str, error_lines: Iterable[str] = ()):
        line = line.rstrip()
        rest = self.parse_reference(line)

        if error_lines:
            self.ref_log.setdefault("stderr_lines", []).append(
                [line.rstrip() for line in error_lines]
            )

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
            assert line == rest
            self.config(rest)
        elif self.ref:
            key = self.current_state or "stdout"
            self.ref_log.setdefault(key, []).append(rest)
            self.screen.print(f"{line} ", overwrite=True)
        elif match_download and self.last_ref:
            self.screen.print(
                f"{match_download.group()} for {self.last_ref} ", overwrite=True
            )
        else:
            if line.startswith("Installing (downloading, building) binaries..."):
                self._resolved = True
            self.log.setdefault("stdout", []).append(line)
            self.screen.print(f"{line} ", overwrite=self._resolved)

        if self.state_start or self.state_end:
            for callback in self.callbacks:
                assert callable(callback)
                callback(self.current_state, self.ref, self.state_start)

        if self.state_end:
            self.current_state = None

    def finalize(self, errs: List[str]):
        self.log.setdefault("stderr_lines", []).append(errs)
        self.screen.print("")

        if self.current_state:
            for callback in self.callbacks:
                assert callable(callback)
                callback(self.current_state, self.ref, False)

        for lines in self.log.pop("stderr_lines"):
            self.log.setdefault("stderr", []).extend(lines)
            errmsg = "\n".join(lines)
            if not errmsg:
                continue
            match = self.WARNING_REGEX.search(errmsg)
            if match and match.group("severity") == "ERROR":
                LOG.error(errmsg)
            else:
                LOG.warning(errmsg)

    def parse_conan_warnings(self, output: str) -> List[Dict[str, Any]]:
        warnings = []
        last_item: Optional[Dict] = None
        for line in output.splitlines(keepends=False):
            match = self.WARNING_REGEX.fullmatch(line)
            if match:
                last_item = match.groupdict()
                for key in list(self.WARNING_REGEX.groupindex.keys())[1:5]:
                    last_item.pop(key, None)
                last_item["severity"] = (
                    "warning" if last_item["severity"].startswith("WARN") else "error"
                )
                last_item["from"] = "conan"
                warnings.append(last_item)
                if match["ref"]:
                    LOG.warning(line)
            elif last_item:
                last_item["info"] += f"\n{line}"
        return warnings


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

        with filehandler("CONMON_PROC_JSON", hint="process debug json") as proc_fh:
            json.dump(
                list(buildmon.proc_cache.values()),
                proc_fh,
                indent=2,
            )
        buildmon = None

        ref_log = parser.ref_log
        ref_log["translation_units"] = tu_list

        warnings = ref_log.setdefault("warnings", [])
        warnings.extend(
            parse_compiler_warnings(
                "\n".join(ref_log["build"]),
                compiler=parser.compiler_type,
            ),
        )
        stderr_lines = ref_log.pop("stderr_lines", ())
        ref_log["stderr"] = list(chain(*stderr_lines))

        def popwarnings(error_lines, parse_func):
            residue = []
            parsed_warnings = []

            for lines in error_lines:
                warnings_found = parse_func("\n".join(lines))
                if warnings_found:
                    parsed_warnings.extend(warnings_found)
                else:
                    residue.append(lines)

            return parsed_warnings, residue

        warning_output, stderr_lines = filter_compiler_warnings(
            stderr_lines, compiler=parser.compiler_type
        )
        compiler_warnings = parse_compiler_warnings(
            warning_output, compiler=parser.compiler_type
        )
        cmake_warnings, stderr_lines = popwarnings(stderr_lines, parse_cmake_warnings)
        conan_warnings, stderr_lines = popwarnings(
            stderr_lines, parser.parse_conan_warnings
        )
        warnings.extend((*compiler_warnings, *cmake_warnings, *conan_warnings))

        res_msg = "\n".join(chain(*stderr_lines)).rstrip()
        if res_msg:
            LOG.warning("[STDERR] %s", res_msg)

    parser.callbacks.append(callback)


def monitor(args: List[str]) -> int:
    # prevent MsBuild from allocating workers
    # which are not children of the parent process
    os.environ["MSBUILDDISABLENODEREUSE"] = "1"
    # tell conan not to prompt for user input
    os.environ["CONAN_NON_INTERACTIVE"] = "1"

    trace_path = Path(os.getenv("CONAN_TRACE_FILE", "."))
    if trace_path == Path("."):
        tmp_file, tmp_name = tempfile.mkstemp()
        trace_path = Path(tmp_name)
        os.environ["CONAN_TRACE_FILE"] = tmp_name
        os.close(tmp_file)
    elif not trace_path.is_absolute():
        os.environ["CONAN_TRACE_FILE"] = str(trace_path.absolute())

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
    stderr = AsyncPipeReader(process.stderr)
    for line in iter(process.stdout.readline, ""):
        raw_fh.write(line)
        error_lines = list(stderr.readlines())
        raw_fh.write("".join(error_lines))
        if stopwatch.timespan_elapsed(1.0):
            raw_fh.flush()
        parser.process(DECOLORIZE_REGEX.sub("", line), error_lines)

    _, errors = process.communicate(input=None, timeout=None)
    assert not errors
    returncode = process.wait()

    errors = [line.rstrip() for line in stderr.readlines()]
    parser.finalize(errors)
    raw_fh.write("\n".join(errors))
    raw_fh.close()

    tracelog = []
    if trace_path.exists():
        for line in trace_path.read_text().splitlines():
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

        if trace_path.name.startswith("tmp"):
            trace_path.unlink(missing_ok=True)
            Path(str(trace_path) + ".lock").unlink(missing_ok=True)

    parser.log.update(
        dict(
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
    parser = argparse.ArgumentParser(
        description=description, prog="conmon", add_help=False
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s version {__version__}"
    )
    parser.add_argument(
        "cmd",
        metavar="<command>",
        help="conan command and options",
        nargs=argparse.REMAINDER,
    )

    known_args, unknown_args = parser.parse_known_args(args)
    known_args.cmd.extend(unknown_args)

    return known_args


if __name__ == "__main__":
    sys.exit(main())
