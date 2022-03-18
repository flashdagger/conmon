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
    Optional,
    Set,
    Type,
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
    unique,
    compact_pattern,
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
LOG_HINTS: Dict[str, None] = {}


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

    return open(path or os.devnull, mode, encoding="utf-8")


class State:
    _ACTIVE: Set["State"] = set()  # currently active
    _EXECUTE: Set["State"] = set()  # can be executed

    def __init__(self, parser: "ConanParser"):
        self.screen = parser.screen

    @classmethod
    def add(cls, state_cls: Type["State"], *args) -> "State":
        assert state_cls not in {type(state) for state in cls._EXECUTE}
        state = state_cls(*args)
        cls._EXECUTE.add(state)
        return state

    @classmethod
    def all_active(cls):
        return tuple(cls._ACTIVE)

    @classmethod
    def all_states(cls):
        return tuple(cls._EXECUTE)

    @property
    def is_active(self) -> bool:
        return self in self._ACTIVE

    def _deactivate(self, final=False):
        if not self.is_active:
            LOG.debug("%s already deactivated", self.__class__.__name__)
            return

        self._ACTIVE.remove(self)
        if final:
            self._EXECUTE.remove(self)

    def deactivate(self):
        self._deactivate(final=False)

    @classmethod
    def deactivate_all(cls):
        for state in tuple(cls._ACTIVE):
            state.deactivate()

    def _activate(self):
        if self.is_active:
            LOG.debug("%s already active", self.__class__.__name__)
            return

        self.deactivate_all()
        self._ACTIVE.add(self)

    def _activated(self, ref: Optional[str], line: str) -> bool:
        raise NotImplementedError

    def _process(self, ref: Optional[str], line: str) -> None:
        pass

    def process(self, ref: Optional[str], line: str) -> None:
        if self.is_active:
            self._process(ref, line)
        elif self._activated(ref, line):
            self._activate()


class Default(State):
    def _activated(self, ref: Optional[str], line: str) -> bool:
        # if not self.all_active() and ref:
        #     print(">>>", ref, line)
        return False


class Requirements(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        pattern, flags = compact_pattern(parser.REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern} from '(?P<remote>[\w-]+)' +- +(?P<status>\w+)", flags
        )

    def _activated(self, ref: Optional[str], line: str) -> bool:
        if line in {"Requirements", "Build requirements"}:
            self.screen.print(line)
            return True
        return False

    def _process(self, ref: Optional[str], line: str) -> None:
        match = self.regex.match(line)
        if not match:
            self.deactivate()
            return

        self.screen.print(line)
        name, remote, status = match.group("name", "remote", "status")
        self.log.setdefault(name, {}).update(dict(remote=remote, recipe_from=status))


class Packages(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        pattern, flags = compact_pattern(parser.REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern}:(?P<package_id>[a-z0-9]+) +- +(?P<status>\w+)", flags
        )

    def _activated(self, ref: Optional[str], line: str) -> bool:
        if line in {"Packages", "Build requirements packages"}:
            self.screen.print(line)
            return True
        return False

    def _process(self, ref: Optional[str], line: str) -> None:
        match = self.regex.match(line)
        if not match:
            self.deactivate()
            return

        self.screen.print(line)
        name, package_id, status = match.group("name", "package_id", "status")
        self.log.setdefault(name, {}).update(
            dict(package_id=package_id, package_from=status)
        )


class Config(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.lines: List[str] = []
        self.log = parser.log.setdefault("config", {})

    def _activated(self, ref: Optional[str], line: str) -> bool:
        return line == "Configuration:"

    def _process(self, ref: Optional[str], line: str) -> None:
        if (
            "[env]" in self.lines
            and not re.match(r"\w+=", line)
            or not re.match(r"(\[[\w.-]+]$)|[^\s:]+\s*[:=]", line)
        ):
            self.deactivate()
        else:
            self.lines.append(line)

    def _deactivate(self, final=False):
        buffer = StringIO("\n".join(self.lines))
        config = StrictConfigParser()
        config.read_file(buffer, "profile.ini")

        for section in config.sections():
            self.log[section] = dict(config.items(section))

        super()._deactivate(final=True)


class Package(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.log

    def _activated(self, ref: Optional[str], line: str) -> bool:
        if line == "Calling package()":
            self.screen.print(f"Packaging {ref}")
            self.log = self.parser.ref_log
            self.log.setdefault("stdout", []).append(line)
            return True
        return False

    def _process(self, ref: Optional[str], line: str) -> None:
        match = re.match(
            r"(?P<prefix>[\w ]+) '?(?P<id>[a-z0-9]{32,40})(?:[' ]|$)", line
        )
        if not match:
            self.log.setdefault("package", []).append(line)
            return

        if match.group("prefix") == "Created package revision":
            self.log["package_revision"] = match.group("id")
            self.deactivate()
            return

        self.log["package_id"] = match.group("id")


class Build(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.log
        self.warnings = 0
        self.buildmon: Optional[BuildMonitor] = None

    def _activated(self, ref: Optional[str], line: str) -> bool:
        if line == "Calling build()":
            self.screen.print(f"Building {ref}")
            self.log = self.parser.ref_log
            self.log.setdefault("stdout", []).append(line)
            self.buildmon = BuildMonitor(self.parser.proc)
            self.buildmon.start()
            return True
        return False

    def _process(self, ref: Optional[str], line: str) -> None:
        match = re.fullmatch(r"Package '\w+' built", line)
        if match:
            self.deactivate()
            return

        if not line:
            return

        self.log.setdefault("build", []).append(line)
        match = self.parser.BUILD_STATUS_REGEX.fullmatch(
            line
        ) or self.parser.BUILD_STATUS_REGEX2.match(line)
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
            output = re.sub(
                r"\.\.\.[^/\\]+(?=[/\\])", "...", output
            )  # shorten at path separator
            if self.warnings:
                self.screen.print(
                    colorama.Fore.YELLOW + f"{self.warnings:4} warning(s)",
                    indent=40,
                )
            self.warnings = 0
            self.screen.print(output, overwrite=True)
        else:
            match = self.parser.SEVERITY_REGEX.match(line)
            info = match.group("severity")[0].upper() if match else ""
            if info == "E":
                self.screen.print(colorama.Fore.RED + f"{info} {line}")
            elif info == "W":
                self.warnings += 1
            elif info:
                self.screen.print(info, indent=0)

    def translation_units(self) -> List[Dict[str, Any]]:
        assert self.buildmon
        self.buildmon.finish.set()
        self.buildmon.join()
        tu_list = self.buildmon.translation_units

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
                list(self.buildmon.proc_cache.values()),
                proc_fh,
                indent=2,
            )

        self.buildmon = None
        return tu_list

    def _deactivate(self, final=False):
        self.parser.screen.reset()
        compiler_type = self.parser.compiler_type
        ref_log = self.log
        ref_log["translation_units"] = self.translation_units()

        warnings = ref_log.setdefault("warnings", [])
        build_stdout = "\n".join(ref_log["build"])
        warnings.extend(
            parse_compiler_warnings(
                build_stdout,
                compiler=compiler_type,
            ),
        )
        # NASM compiler is type GNU
        if compiler_type == "vs":
            warnings.extend(
                parse_compiler_warnings(
                    build_stdout,
                    compiler="gnu",
                ),
            )
        stderr_lines = ref_log.pop("stderr_lines", ())
        ref_log.setdefault("stderr", []).extend(chain(*stderr_lines))

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
            stderr_lines, compiler=compiler_type
        )
        compiler_warnings = parse_compiler_warnings(
            warning_output, compiler=compiler_type
        )
        cmake_warnings, stderr_lines = popwarnings(stderr_lines, parse_cmake_warnings)
        warnings.extend((*compiler_warnings, *cmake_warnings))

        filtered = unique(tuple(lines) for lines in stderr_lines)
        res_msg = "\n---\n".join(("\n".join(lines) for lines in filtered))
        res_msg = "\n" + res_msg.strip("\n")
        if res_msg.strip():
            LOG.warning("[STDERR] %s", res_msg)

        super()._deactivate(final=False)


class ConanParser:
    REF_PART_PATTERN = r"\w[\w\+\.\-]{1,50}"
    REF_REGEX = re.compile(
        rf"""
            (?P<ref>
            (?P<name>{REF_PART_PATTERN})/
            (?P<version>{REF_PART_PATTERN})
            (?:
                @
                (?:
                    (?P<user>{REF_PART_PATTERN})/
                    (?P<channel>{REF_PART_PATTERN})
                )?
             )?
         )
        """,
        re.VERBOSE,
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
                [\-.\w/\\]+ (?(status) $ | \.(?:asm|cpp|c)$ )
            )
    """
    )
    BUILD_STATUS_REGEX2 = re.compile(
        r"""(?x)
            (?P<status>(?!))? # should never match
            .*\ -c\           # compile but don't link
            (?P<file>
                [\-.\w/\\]+ \. (?:cpp|c) (?=\ )
            )
        """
    )
    WARNING_REGEX = re.compile(
        rf"""(?xm)
        ^(?:{REF_REGEX.pattern}:\ +)?
        (?P<severity>ERROR|WARN):\ ?
        (?P<info>.*)
        """
    )
    SEVERITY_REGEX = re.compile(r"(?xm).+?:\ (?P<severity>warning|error):?\ [a-zA-Z]")

    def __init__(self, process: psutil.Process):
        self.proc = process
        self.log: Dict[str, Any] = defaultdict(dict)
        self.ref = ""
        self.last_ref = ""
        self.rest: str
        self.screen = ScreenWriter()
        self._resolved = False
        State.add(Default, self)
        State.add(Requirements, self)
        State.add(Packages, self)
        State.add(Config, self)
        State.add(Build, self)
        State.add(Package, self)

    @property
    def compiler_type(self) -> str:
        profile = self.log.get("config", {})
        if "settings" not in profile:
            return "unknown"

        compiler = profile["settings"].get("compiler")
        if "clang-cl" in profile.get("env", {}).get("CC", ""):
            compiler_type = "clang-cl"
        elif compiler in {"clang", "gcc", "cc"}:
            compiler_type = "gnu"
        elif compiler == "Visual Studio":
            compiler_type = "vs"
        else:
            compiler_type = "unknown"

        return compiler_type

    def parse_reference(self, line) -> str:
        ref_match = re.fullmatch(
            rf"(?x)\.*{self.REF_REGEX.pattern}[\s:]{{1,2}}(?P<rest>.*)",
            line,
        )

        if ref_match:
            ref, rest = ref_match.group("ref"), ref_match.group("rest")
            self.ref = ref
            self.last_ref = ref
        elif State.all_active():
            rest = line
        else:
            rest = line
            self.ref = ""

        return rest

    @property
    def ref_log(self) -> Dict[str, Any]:
        if not self.ref:
            return self.log

        match = self.REF_REGEX.fullmatch(self.ref)
        assert match
        groupdict = match.groupdict()
        return self.log["requirements"].setdefault(groupdict["name"], groupdict)

    def handle_errors(self, lines, final=False):
        processed = []
        residue = []
        loglevel = logging.WARNING

        def flush():
            if processed:
                self.screen.reset()
                LOG.log(loglevel, "\n".join(processed).strip("\n"))

        stderr = self.ref_log.setdefault("stderr", [])
        for line in lines:
            line = line.rstrip()
            match = self.WARNING_REGEX.match(line)
            if match:
                flush()
                ref, severity, info = match.group("ref", "severity", "info")
                loglevel = getattr(logging, severity, logging.WARNING)
                prefix = f"{ref}: " if ref else ""
                processed = [f"{prefix}{info}"]
                stderr.append(line)
            elif processed or final:
                processed.append(line)
                stderr.append(line)
            else:
                residue.append(line)

        flush()
        if residue:
            self.ref_log.setdefault("stderr_lines", []).append(residue)

    def process(self, line: str, error_lines: Iterable[str] = ()):
        line = line.rstrip()
        rest = self.parse_reference(line)

        self.handle_errors(error_lines)
        if self.ref and self.ref in line and "is locked" in line:
            LOG.warning(line)

        for state in State.all_states():
            state.process(self.ref, rest)

        match_download = re.fullmatch(r"Downloading conan\w+\.[a-z]{2,3}", rest)
        if State.all_active():
            pass
        elif self.ref:
            # key = self.current_state or "stdout"
            # self.ref_log.setdefault(key, []).append(rest)
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

    def finalize(self, errs: List[str]):
        State.deactivate_all()
        self.screen.reset()
        self.handle_errors(errs, final=True)


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
    stderr = AsyncPipeReader(process.stderr)

    parser = ConanParser(process)
    parser.log.update(
        dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.version_info)),
            conan_version=conan_version,
        )
    )

    raw_fh = filehandler("CONMON_CONAN_LOG", hint="raw conan output")
    stopwatch = StopWatch()
    for line in iter(process.stdout.readline, ""):
        raw_fh.write(line)
        error_lines = list(stderr.readlines())
        raw_fh.write("".join(error_lines))
        if stopwatch.timespan_elapsed(1.0):
            raw_fh.flush()
        parser.process(DECOLORIZE_REGEX.sub("", line), error_lines)

    _, errors = process.communicate(input=None, timeout=None)
    returncode = process.wait()

    errors = [line.rstrip() for line in stderr.readlines()]
    parser.finalize(errors)
    raw_fh.write("\n".join(errors))
    raw_fh.close()

    tracelog = []
    if trace_path.exists():
        for line in trace_path.read_text(encoding="utf-8").splitlines():
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
