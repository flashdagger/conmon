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
from importlib import import_module
from importlib.util import find_spec
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
    Tuple,
    TextIO,
    Match,
)

import colorama  # type: ignore
import colorlog  # type: ignore
import psutil  # type: ignore

from conmon.utils import (
    StrictConfigParser,
    ScreenWriter,
    shorten,
    unique,
    compact_pattern,
    ProcessStreamHandler,
)
from . import __version__
from .buildmon import BuildMonitor, LOG as PLOG
from .compilers import (
    LOG as BLOG,
    parse_compiler_warnings,
    parse_cmake_warnings,
    filter_compiler_warnings,
)

CONMON_LOG = logging.getLogger("CONMON")
CONAN_LOG = logging.getLogger("CONAN")
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
            CONMON_LOG.debug("%s already deactivated", self.__class__.__name__)
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
            CONMON_LOG.debug("%s already active", self.__class__.__name__)
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
        self.log = parser.log.setdefault("requirements", defaultdict(dict))
        pattern, flags = compact_pattern(REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern} from '(?P<remote>[\w-]+)' +- +(?P<recipe_from>\w+)", flags
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
        mapping = {
            key: value for key, value in match.groupdict().items() if key not in {"ref"}
        }
        name = mapping.pop("name")
        self.log.setdefault(name, {}).update(mapping)


class Packages(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log.setdefault("requirements", defaultdict(dict))
        pattern, flags = compact_pattern(REF_REGEX)
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
            dict(package_id=package_id, package_status=status)
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
            and not re.match(r"\w+=|$", line)
            or not re.match(r"(\[[\w.-]+]$)|[^\s:]+\s*[:=]|$", line)
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
    WIDTH = 60
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
            self.log.setdefault("build", [])
            self.log.setdefault("stdout", []).append(line)
            self.buildmon = BuildMonitor(self.parser.process)
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

        self.log["build"].append(line)
        match = self.BUILD_STATUS_REGEX.fullmatch(
            line
        ) or self.BUILD_STATUS_REGEX2.match(line)
        if match:
            if self.warnings:
                self.screen.print(
                    colorama.Fore.YELLOW + f"{self.warnings:4} warning(s)",
                    indent=0,  # self.WIDTH,
                )
            self.warnings = 0

            status, file = match.groups()
            prefix = f"{status.strip()} " if status else ""
            output = shorten(
                file,
                width=self.WIDTH,
                template=f"{prefix}{{}} ",
                strip_left=True,
                placeholder="...",
            )
            output = re.sub(
                r"\.\.\.[^/\\]+(?=[/\\])", "...", output
            )  # shorten at path separator
            self.screen.print(f"{output:{self.WIDTH}}", overwrite=True)
        elif line.startswith("--") or line.startswith("checking"):
            self.screen.print(line, overwrite=True)
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
        if compiler_type == "msvc":
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
            CONMON_LOG.warning("[STDERR] %s", res_msg)

        super()._deactivate(final=False)


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
LINE_REGEX = re.compile(
    rf"(?:{compact_pattern(REF_REGEX)[0]}(?:: ?| ))?(?P<rest>[^\n]*)\n?"
)


class ConanParser:
    CONAN_VERSION = "<undefined>"
    WARNING_REGEX = re.compile(
        rf"""(?xm)
        ^(?:{compact_pattern(REF_REGEX)[0]}:\ +)?
        (?P<severity>ERROR|WARN):\ ?
        (?P<info>.*)
        """
    )
    SEVERITY_REGEX = re.compile(r"(?xm).+?:\ (?P<severity>warning|error):?\ [a-zA-Z]")

    def __init__(self, process: psutil.Popen):
        self.parsed_line: Match = self.parse_line("")
        self.process = process
        self.log: Dict[str, Any] = defaultdict(dict)
        self.ref = ""
        self.last_ref = ""
        self.screen = ScreenWriter()
        self._resolved = False

        self.log["conan"] = dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.implementation.version))
            + f" ({sys.implementation.name})",
            version=self.CONAN_VERSION,
            command=process.cmdline(),
        )

        State.add(Default, self)
        State.add(Config, self)
        State.add(Requirements, self)
        State.add(Packages, self)
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
            compiler_type = "msvc"
        else:
            compiler_type = "unknown"

        return compiler_type

    def parse_line(self, line) -> Match:
        match = LINE_REGEX.match(line)
        assert match

        self.ref = match.group("ref") or ""
        if self.ref:
            self.last_ref = self.ref

        return match

    @property
    def ref_log(self) -> Dict[str, Any]:
        name = self.parsed_line.group("name")
        if not name:
            return self.log

        return self.log["requirements"][name]

    def process_errors(self, lines: Iterable[str], final=False):
        def flush(level, _lines):
            if not _lines:
                return
            self.screen.reset()
            CONAN_LOG.log(level, "\n".join(_lines))

        processed: Tuple[int, List[str]] = logging.WARNING, []
        residue: List[str] = []
        stderr: List[str] = []

        for line in lines:
            line = line.rstrip()
            match = self.WARNING_REGEX.match(line)
            if match:
                flush(*processed)
                ref, severity, info = match.group("ref", "severity", "info")
                loglevel = getattr(logging, severity, logging.WARNING)
                prefix = f"{ref}: " if ref else ""
                processed = loglevel, [f"{prefix}{info}"]
                stderr.append(line)
            elif processed or final:
                processed[1].append(line)
                stderr.append(line)
            else:
                residue.append(line)

        flush(*processed)
        # if stderr:
        #     self.ref_log.setdefault("stderr", []).extend(stderr)
        # if residue:
        #     self.ref_log.setdefault("stderr_lines", []).append(residue)

    def process_line(self, line: str):
        line = line.rstrip()
        self.parsed_line = self.parse_line(line)
        rest = self.parsed_line.group("rest")

        if self.ref and "is locked" in rest:
            CONAN_LOG.warning(line)

        for state in State.all_states():
            state.process(self.ref, rest)

        match_download = re.fullmatch(r"Downloading conan\w+\.[a-z]{2,3}", rest)
        if State.all_active():
            pass
        elif self.ref:
            self.ref_log.setdefault("stdout", []).append(line)
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

    def process_streams(self, raw_fh: TextIO):
        streams = ProcessStreamHandler(self.process)
        marker = "{:-^80}\n"
        stderr_marker = marker.format(" stderr ")
        stdout_marker = marker.format(" stdout ")

        while not streams.exhausted:
            try:
                stdout, stderr = streams.readboth()
            except KeyboardInterrupt:
                self.screen.reset()
                CONMON_LOG.warning("Pressed Ctrl+C")
                break

            if stdout:
                raw_fh.write("".join((stdout_marker, *stdout)))
                raw_fh.flush()
                for line in stdout:
                    self.process_line(DECOLORIZE_REGEX.sub("", line))

            if stderr:
                raw_fh.write("".join((stderr_marker, *stderr)))
                raw_fh.flush()
                self.process_errors(stderr, final=False)

    def process_tracelog(self, trace_path: Path):
        self.log["conan"]["tracelog"] = tracelog = []
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
            requirement = self.log["requirements"][name]
            if len(pkg_id) == 2:
                requirement["package_id"] = pkg_id[1]
            actions = requirement.setdefault("actions", [])
            if action["_action"] not in actions:
                actions.append(action["_action"])

    def finalize(self):
        State.deactivate_all()
        self.screen.reset()
        self.log["conan"]["returncode"] = self.process.wait()


def check_conan() -> Tuple[List[str], str]:
    """determines the fastest method to get the version of conan"""

    regex = re.compile(r"[12](?:\.\d+){2}")
    conan_command = [sys.executable, "-m", "conans.conan"]

    try:
        # parse the sourcefile without importing it
        if not sys.modules.get("conans"):
            spec: Any = find_spec("conans")
            out = Path(spec.origin).read_text(encoding="utf-8") if spec else ""
            return conan_command, regex.findall(out)[0]
    except (ImportError, FileNotFoundError, IndexError):
        pass

    try:
        # import the conan module and get the version string
        module = import_module("conans")
        version = getattr(module, "__version__")
        return conan_command, version
    except (ModuleNotFoundError, AttributeError):
        pass

    # use the conan executable or python calling the module
    for command in [["conan"], conan_command]:
        try:
            out = check_output(
                [*command, "--version"],
                universal_newlines=True,
            )
            return command, regex.findall(out)[0]
        except CalledProcessError as exc:
            CONMON_LOG.error("%s", exc.output)
            sys.exit(1)
        except (FileNotFoundError, IndexError):
            pass

    CONMON_LOG.error("The 'conan' command cannot be executed.")
    sys.exit(1)


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

    conan_command, ConanParser.CONAN_VERSION = check_conan()
    conan_command.extend(args)
    process = psutil.Popen(
        conan_command, stdout=PIPE, stderr=PIPE, universal_newlines=True, bufsize=0
    )
    parser = ConanParser(process)
    with filehandler("CONMON_CONAN_LOG", hint="raw conan output") as fh:
        parser.process_streams(fh)
    parser.finalize()

    if trace_path.exists():
        parser.process_tracelog(trace_path)
        if trace_path.name.startswith("tmp"):
            for path in (trace_path, Path(str(trace_path) + ".lock")):
                if path.exists():
                    path.unlink()

    with filehandler("CONMON_REPORT_JSON", hint="report json") as fh:
        json.dump(parser.log, fh, indent=2)

    for hint in LOG_HINTS:
        CONMON_LOG.info(hint)

    return process.wait()


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

    # general conmon logger
    CONMON_LOG.addHandler(handler)
    CONMON_LOG.setLevel(logging.DEBUG)
    # conan logger for warnings/errors
    CONAN_LOG.addHandler(handler)
    CONAN_LOG.setLevel(logging.WARNING)
    # conan build logger
    BLOG.addHandler(handler)
    BLOG.setLevel(logging.INFO)
    # buildmon process logger
    PLOG.addHandler(handler)
    PLOG.setLevel(logging.INFO)

    if os.getenv("CI"):
        CONMON_LOG.info("Running in Gitlab CI")

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
