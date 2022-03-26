#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import logging
import os
import platform
import re
import shlex
import sys
import tempfile
from collections import defaultdict
from importlib import import_module
from importlib.util import find_spec
from io import StringIO
from itertools import chain
from operator import itemgetter
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
    Iterator,
)

import colorama  # type: ignore
import colorlog  # type: ignore
from psutil import Popen, Process

from conmon.regex import DECOLORIZE_REGEX, REF_REGEX, WARNING_REGEX, shorten_conan_path
from conmon.utils import (
    StrictConfigParser,
    ScreenWriter,
    shorten,
    unique,
    compact_pattern,
    ProcessStreamHandler,
    get_terminal_width,
)
from . import __version__
from . import json
from .buildmon import BuildMonitor, LOG as PLOG
from .compilers import (
    LOG as BLOG,
    parse_compiler_warnings,
    parse_cmake_warnings,
    filter_compiler_warnings,
    parse_bison_warnings,
)

CONMON_LOG = logging.getLogger("CONMON")
CONAN_LOG = logging.getLogger("CONAN")

PARENT_PROCS = [parent.name() for parent in Process(os.getppid()).parents()]
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
    def __init__(self, parser: "ConanParser"):
        self.finished = False
        self.stopped = False
        self.screen = parser.screen

    def deactivate(self):
        assert self.finished is False
        self._deactivate(final=False)
        assert self.finished is True

    def _deactivate(self, final=False):
        self.finished = True
        self.stopped = final

    def activated(self, parsed_line: Match) -> bool:
        raise NotImplementedError

    def process(self, parsed_line: Match) -> None:
        raise NotImplementedError


class StateMachine:
    def __init__(self, parser: "ConanParser"):
        self.screen = parser.screen
        self.parser = parser
        self._active: Set[State] = set()  # currently active
        self._running: List[State] = []  # can be executed
        self._default: Optional[State] = None

    def add(self, state: State):
        assert not state.stopped
        assert state not in self.running_instances()
        self._running.append(state)
        return state

    def setdefault(self, state: Optional[State]):
        self._default = state
        if state:
            self.add(state)

    @property
    def active_classes(self) -> Tuple[Type[State], ...]:
        return tuple(type(instance) for instance in self._active)

    def active_instance(self) -> Optional[State]:
        for state in self._active:
            return state
        return None

    def running_instances(self) -> Tuple[State, ...]:
        return tuple(self._running)

    def activate(self, state: State):
        state.finished = False
        self._active.add(state)

    def deactivate(self, state: State):
        if not state.finished:
            state.deactivate()
        self._active.remove(state)
        if state.stopped:
            self._running.remove(state)

    def deactivate_all(self):
        for state in tuple(self._active):
            self.deactivate(state)

    def process_hooks(self, parsed_line: Match) -> None:
        activated = []

        for state in tuple(self._active):
            if not state.finished:
                state.process(parsed_line)
            if state.finished:
                self.deactivate(state)

        for state in tuple(self._running):
            if state.activated(parsed_line):
                activated.append(state)

        if activated:
            if len(activated) > 1:
                CONMON_LOG.warning(
                    "overlapping states: %s",
                    ", ".join(type(state).__name__ for state in activated),
                )
            self.deactivate_all()
            for state in activated:
                self.activate(state)

        if not self._active and self._default and not self._default.stopped:
            self.activate(self._default)
            self._default.process(parsed_line)


class Default(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.overwrite = False
        self.last_ref = None

    def activated(self, parsed_line: Match) -> bool:
        return False

    def process(self, parsed_line: Match) -> None:
        line, ref, rest = parsed_line.group(0, "ref", "rest")
        match = re.fullmatch(r"Downloading conan\w+\.[a-z]{2,3}", line)

        if rest.startswith("Installing (downloading, building) binaries..."):
            self.overwrite = True

        if match:
            log = self.parser.getdefaultlog(self.last_ref)
            self.screen.print(f"{match.group()} for {self.last_ref} ", overwrite=True)
        elif ref:
            self.last_ref = ref
            log = self.parser.getdefaultlog(ref)
            self.screen.print(f"{line} ", overwrite=True)
        else:
            log = self.parser.log
            self.screen.print(f"{line} ", overwrite=self.overwrite)

        log.setdefault("stdout", []).append(line)
        self.deactivate()


class Requirements(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log.setdefault("requirements", defaultdict(dict))
        self.stdout = parser.log.setdefault("stdout", [])
        pattern, flags = compact_pattern(REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern} from '(?P<remote>[\w-]+)' +- +(?P<status>\w+)", flags
        )
        self.req: List[Dict[str, Optional[str]]] = []
        self.indent_ref = 0

    def activated(self, parsed_line: Match) -> bool:
        full_line, line = parsed_line.group(0, "rest")
        if line in {"Requirements", "Build requirements"}:
            self.screen.print(line)
            self.stdout.append(full_line)
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group(0)
        match = self.regex.match(line)
        if not match:
            self.deactivate()
            return

        self.req.append(match.groupdict())
        self.stdout.append(line)
        mapping = {
            key: value
            for key, value in match.groupdict().items()
            if key not in {"ref", "status"}
        }
        name = mapping.pop("name")
        self.log.setdefault(name, {}).update(mapping)

    def _deactivate(self, final=False):
        self.indent_ref = max(
            [self.indent_ref, *(len(item["ref"]) for item in self.req)]
        )
        for item in sorted(self.req, key=itemgetter("status", "remote", "ref")):
            self.screen.print(
                f"    {item['status']:^10} {item['ref']:{self.indent_ref}} from "
                f"{repr(item['remote'])}"
            )
        self.req.clear()
        super()._deactivate(final=False)


class Packages(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log.setdefault("requirements", defaultdict(dict))
        self.stdout = parser.log.setdefault("stdout", [])
        pattern, flags = compact_pattern(REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern}:(?P<package_id>[a-z0-9]+) +- +(?P<status>\w+)", flags
        )
        self.pkg: List[Dict[str, Optional[str]]] = []
        self.indent_ref = 0

    def activated(self, parsed_line: Match) -> bool:
        full_line, line = parsed_line.group(0, "rest")
        if line in {"Packages", "Build requirements packages"}:
            self.screen.print(line)
            self.stdout.append(full_line)
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group(0)
        match = self.regex.match(line)
        if not match:
            self.deactivate()
            return

        self.pkg.append(match.groupdict())
        self.stdout.append(line)
        name, package_id = match.group("name", "package_id")
        self.log.setdefault(name, {}).update(
            dict(package_id=package_id, package_revision=None)
        )

    def _deactivate(self, final=False):
        self.indent_ref = max(
            [self.indent_ref, *(len(item["ref"]) for item in self.pkg)]
        )
        for item in sorted(self.pkg, key=itemgetter("status", "ref")):
            self.screen.print(
                f"    {item['status']:^10} {item['ref']:{self.indent_ref}} {item['package_id']}"
            )
        self.pkg.clear()
        super()._deactivate(final=False)


class Config(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.lines: List[str] = []
        self.log = parser.log["config"]

    def activated(self, parsed_line: Match) -> bool:
        line = parsed_line.group("rest")
        return line == "Configuration:"

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group(0)
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

    def activated(self, parsed_line: Match) -> bool:
        line, ref, rest = parsed_line.group(0, "ref", "rest")
        if rest == "Calling package()":
            self.screen.print(f"Packaging {ref}")
            self.parser.setdefaultlog(ref).setdefault("stdout", []).append(line)
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group("rest")
        match = re.match(
            r"(?P<prefix>[\w ]+) '?(?P<id>[a-z0-9]{32,40})(?:[' ]|$)", line
        )
        log = self.parser.defaultlog
        if not match:
            log.setdefault("package", []).append(line)
            return

        if match.group("prefix") == "Created package revision":
            log["package_revision"] = match.group("id")
            self.deactivate()
            return

        log["package_id"] = match.group("id")

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class Build(State):
    MAX_WIDTH = 65
    BUILD_STATUS_REGEX = re.compile(
        r"""(?x)
            (?:
                (?P<status>
                    \[\ {0,2}\d+(?:%|/\d+) ] | \ +(?:CC|CCLD|CPPAS)(?=\ )
                )?  # ninja, cmake or automake
                .*? # msbuild prints only the filename
            )?
            (?P<file>
                [\-.\w/\\]+ (?(status) \.[a-z]{1,3}$ | \.(?:asm|cpp|c)$ )
            )
    """
    )
    BUILD_STATUS_REGEX2 = re.compile(
        r"""(?x)
            (?P<status>$)?    # should never match
            .*\ -c\           # compile but don't link
            (?P<file>
                [\-.\w/\\]+ \. (?:cpp|c) (?=\ )
            )
        """
    )

    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.warnings = 0
        self.compiler_types: Set[str] = set()
        self.tools: Set[str] = set()
        self.buildmon: Optional[BuildMonitor] = None

    def activated(self, parsed_line: Match) -> bool:
        full_line, ref, line = parsed_line.group(0, "ref", "rest")
        if line == "Calling build()":
            self.screen.print(f"Building {ref}")
            log = self.parser.setdefaultlog(ref)
            log.setdefault("build", [])
            log.setdefault("stdout", []).append(full_line)
            self.buildmon = BuildMonitor(self.parser.process)
            self.buildmon.start()
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group("rest")
        match = re.fullmatch(r"Package '\w+' built", line)
        if match:
            self.deactivate()
            return

        if not line:
            return

        self.parser.defaultlog.setdefault("build", []).append(line)
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
                width=self.MAX_WIDTH,
                template=f"{prefix}{{}} ",
                strip="left",
                placeholder="...",
            )
            # shorten at path separator
            output = re.sub(r"\.{3}[^/\\]+(?=[/\\])", "...", output)
            self.screen.print(f"{output:{self.MAX_WIDTH}}", overwrite=True)
        elif line.startswith("-- ") or line.startswith("checking "):
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

    def filtered_tus(
        self, tu_list: Iterable[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        src_filter = {
            "cmake": lambda path: set(path.parts) & {"CMake", "CMakeFiles", "cmake.tmp"}
            or re.match(r".*/cmake-[23].\d+/Modules/(CMake|Check)", path.as_posix()),
            "conftest": lambda path: path.stem == "conftest",
            "make": lambda path: path.stem in {"conftest", "dummy"},
        }
        active_filters = {
            key: value for key, value in src_filter.items() if key in self.tools
        }

        src_counter = 0
        set_counter = 0
        discarded_files: Set[str] = set()

        for unit in tu_list:
            discarded = False
            for test in active_filters.values():
                sources = unit["sources"]
                if any(test(Path(src)) for src in sources):
                    src_counter += len(sources)
                    set_counter += 1
                    discarded_files.update(src.name for src in sources)
                    discarded = True
                    break
            if not discarded:
                yield unit

        if src_counter:
            CONMON_LOG.debug(
                "Discarded %s source files and %s translation sets (%s)",
                src_counter,
                set_counter,
                ", ".join(discarded_files),
            )

    def processed_tus(self, tu_list: List[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
        def package_dir(path: Path) -> Optional[Path]:
            match = re.match(r"^.*?/(?:build|package)/[a-f0-9]{40}/", path.as_posix())
            return Path(match.group()) if match else None

        src_set = set()
        src_counter = 0
        set_counter = 0

        for unit in self.filtered_tus(tu_list):
            sources = unit.pop("sources", [])
            src_package_dir = package_dir(sources[0])
            for include in sorted(unit.pop("includes", [])):
                include_package_dir = package_dir(include)
                if include_package_dir is None or src_package_dir in include.parents:
                    unit.setdefault("includes", []).append(include)
                else:
                    unit.setdefault("system_includes", []).append(include)

            unit["sources"] = sources
            src_set.update(sources)
            src_counter += len(sources)
            set_counter += 1
            yield unit

        if set_counter:
            unique_msg = (
                "" if len(src_set) == src_counter else f"({len(src_set)} unique) "
            )
            CONMON_LOG.info(
                "Detected %s source file%s %sin %s translation set%s",
                src_counter,
                "s" if len(src_set) > 1 else "",
                unique_msg,
                set_counter,
                "s" if set_counter > 1 else "",
            )

    def translation_units(self) -> List[Dict[str, Any]]:
        assert self.buildmon
        self.buildmon.finish.set()
        self.buildmon.join()
        self.compiler_types.update(
            value for value in self.buildmon.compiler.values() if value is not None
        )
        self.tools.update(self.buildmon.executables)
        tu_list = self.processed_tus(self.buildmon.translation_units)

        with filehandler("CONMON_PROC_JSON", hint="process debug json") as proc_fh:
            json.dump(
                list(self.buildmon.proc_cache.values()),
                proc_fh,
                indent=2,
            )

        self.buildmon = None
        return list(tu_list)

    @staticmethod
    def _popwarnings(error_lines, parse_func):
        residue = []
        parsed_warnings = []

        for lines in error_lines:
            warnings_found = parse_func("\n".join(lines))
            if warnings_found:
                parsed_warnings.extend(warnings_found)
            else:
                residue.append(lines)

        return parsed_warnings, residue

    @staticmethod
    def emit_warnings(lines):
        more = len(lines) - 10
        if more > 0:
            lines = [
                *lines[:10],
                [f"... {more} more lines emitted ..."],
            ]
        filtered = unique(tuple(lines) for lines in lines)
        res_msg = "\n[...]\n".join(("\n".join(lines) for lines in filtered))
        res_msg = shorten_conan_path(res_msg)
        if res_msg.strip():
            CONMON_LOG.warning("STDERR: %s", res_msg.strip("\n"))

    def _deactivate(self, final=False):
        self.parser.screen.reset()
        ref_log = self.parser.defaultlog
        ref_log["translation_units"] = self.translation_units()
        warnings = ref_log.setdefault("warnings", [])
        build_stdout = "\n".join(ref_log["build"])
        self.compiler_types.add(self.parser.compiler_type)

        for compiler_type in self.compiler_types:
            warnings.extend(
                parse_compiler_warnings(
                    build_stdout,
                    compiler=compiler_type,
                ),
            )

        if self.tools & {"bison", "win_bison"}:
            bison_warnings = parse_bison_warnings(build_stdout)
            warnings.extend(bison_warnings)

        stderr_lines = ref_log.pop("stderr_lines", ())
        ref_log.setdefault("stderr", []).extend(chain(*stderr_lines))

        for compiler_type in self.compiler_types:
            warning_output, stderr_lines = filter_compiler_warnings(
                stderr_lines, compiler=compiler_type
            )
            compiler_warnings = parse_compiler_warnings(
                warning_output, compiler=compiler_type
            )
            warnings.extend(compiler_warnings)

        if "cmake" in self.tools:
            cmake_warnings, stderr_lines = self._popwarnings(
                stderr_lines, parse_cmake_warnings
            )
            warnings.extend(cmake_warnings)

        self.emit_warnings(stderr_lines)
        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class ConanParser:
    CONAN_VERSION = "<undefined>"
    SEVERITY_REGEX = re.compile(
        r"(?xm).+?:\ (?P<severity>warning|error)(?::\ |\ [a-zA-Z])"
    )
    LINE_REGEX = re.compile(
        rf"(?:{compact_pattern(REF_REGEX)[0]}(?:: ?| ))?(?P<rest>[^\r\n]*)"
    )

    def __init__(self, process: Popen):
        self.process = process
        self.log: Dict[str, Any] = defaultdict(dict)
        self.defaultlog: Dict[str, Any] = self.log
        self.screen = ScreenWriter()

        self.log["conan"] = dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.implementation.version))
            + f" ({sys.implementation.name})",
            version=self.CONAN_VERSION,
            command=process.cmdline(),
        )

        self.states = StateMachine(self)
        self.states.setdefault(Default(self))
        self.states.add(Config(self))
        self.states.add(Requirements(self))
        self.states.add(Packages(self))
        self.states.add(Build(self))
        self.states.add(Package(self))

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
        match = self.LINE_REGEX.match(line)
        assert match
        return match

    def getdefaultlog(self, name: Optional[str] = None) -> Dict[str, Any]:
        if name is None:
            log = self.log
        else:
            name, *_ = name.split("/", maxsplit=1)
            log = self.log["requirements"].setdefault(name, {})

        return log

    def setdefaultlog(self, name: Optional[str] = None) -> Dict[str, Any]:
        log = self.getdefaultlog(name)
        self.defaultlog = log
        return log

    def process_errors(self, lines: Iterable[str]):
        processed: List[str] = []
        loglevel: int = logging.WARNING
        residue: List[str] = []
        stderr: List[str] = []
        ref: Optional[str] = None
        is_defaultlog = self.defaultlog == self.log
        max_width = -1 if is_defaultlog else (get_terminal_width() or 140) - 20

        def flush():
            if not processed:
                return

            self.screen.reset()
            preq = -1 if ref or is_defaultlog else None

            if len(processed) == 1:
                CONAN_LOG.log(
                    loglevel,
                    shorten(processed[0], width=preq or max_width, strip="right"),
                )
            else:
                CONAN_LOG.log(
                    loglevel,
                    shorten("\n".join(processed), width=preq or 300, strip="middle"),
                )
            self.getdefaultlog(ref).setdefault("stderr", []).extend(stderr)

        for line in lines:
            line = line.rstrip()
            match = WARNING_REGEX.match(line)
            if match:
                flush()
                ref, severity_l, severity_r, info = match.group(
                    "ref", "severity_l", "severity", "info"
                )
                severity = severity_l or severity_r
                loglevel = getattr(logging, severity, logging.WARNING)
                prefix = f"{ref}: " if ref else ""
                processed = [f"{prefix}{info}"]
                stderr = [line]
            elif processed or is_defaultlog:
                processed.append(line)
                stderr.append(line)
            else:
                residue.append(line)

        flush()
        if residue:
            self.defaultlog.setdefault("stderr_lines", []).append(residue)

    def process_line(self, line: str):
        line = line.rstrip()
        parsed_line = self.parse_line(line)
        ref, rest = parsed_line.group("ref", "rest")

        if ref and "is locked" in rest:
            CONAN_LOG.warning(line)

        self.states.process_hooks(parsed_line)

    def process_streams(self, raw_fh: TextIO):
        streams = ProcessStreamHandler(self.process)
        marker = "{:-^120}\n"
        stderr_marker_start = marker.format(" <stderr> ")
        stdout_marker_start = marker.format(" <stdout> ")
        stderr_written = True

        while not streams.exhausted:
            try:
                stdout, stderr = streams.readboth()
            except KeyboardInterrupt:
                self.screen.reset()
                CONMON_LOG.warning("Pressed Ctrl+C")
                break

            if stdout:
                if stderr_written:
                    raw_fh.write(stdout_marker_start)
                    stderr_written = False

                for line in stdout:
                    self.process_line(DECOLORIZE_REGEX.sub("", line))
                    # state = self.states.active_instance()
                    # name = state and type(state).__name__
                    # raw_fh.write(f"[{name}] {line}")
                    raw_fh.write(line)
                raw_fh.flush()

            if stderr:
                raw_fh.write(
                    "".join(("" if stderr_written else stderr_marker_start, *stderr))
                )
                raw_fh.flush()
                stderr_written = True
                self.process_errors(stderr)

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
        self.states.deactivate_all()
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
    command = os.getenv("CONMON_CONAN_CMD", "conan")
    try:
        CONMON_LOG.debug("calling conan via %r", command)
        conan_cmd = shlex.split(command)
        out = check_output(
            [*conan_cmd, "--version"],
            universal_newlines=True,
        )
        return conan_cmd, regex.findall(out)[0]
    except CalledProcessError as exc:
        if exc.output:
            CONMON_LOG.error("%s", exc.output)
    except (FileNotFoundError, IndexError):
        pass

    CONMON_LOG.error("The %r command cannot be executed.", command)
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
    process = Popen(
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
        colorlog.ColoredFormatter(
            "%(log_color)s[%(name)s:%(levelname)s] %(message)s",
            log_colors={**colorlog.default_log_colors, **dict(DEBUG="light_black")},
        )
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
    PLOG.setLevel(logging.DEBUG)

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
