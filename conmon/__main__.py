#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import logging
import os
import platform
import re
import sys
import tempfile
from collections import UserDict
from contextlib import suppress
from functools import partial
from io import StringIO
from itertools import chain
from operator import itemgetter
from pathlib import Path
from subprocess import PIPE
from textwrap import indent
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Match,
    Optional,
    Set,
    TextIO,
    Tuple,
    cast,
)

from psutil import Popen, Process

from . import __version__, json
from .buildmon import BuildMonitor
from .conan import LOG as CONAN_LOG, call_cmd_and_version, conmon_setting
from .logging import (
    UniqueLogger,
    get_logger,
    level_from_name,
    logger_escape_code,
    init as initialize_logging,
)
from .regex import (
    BUILD_STATUS_REGEX,
    BUILD_STATUS_REGEX2,
    DECOLORIZE_REGEX,
    REF_REGEX,
    compact_pattern,
    filter_by_regex,
    shorten_conan_path,
)
from .replay import ReplayProcess, ReplayStreamHandler, replay_logfile
from .state import State, StateMachine
from .utils import (
    NullList,
    ProcessStreamHandler,
    ScreenWriter,
    StrictConfigParser,
    added_first,
    freeze_json_object,
    get_terminal_width,
    shorten,
    shorten_per_line,
    sorted_dicts,
    unique,
)
from .warnings import LOG as BLOG
from .warnings import Regex, levelname_from_severity, warnings_from_matches

CONMON_LOG = get_logger("CONMON")
CONAN_LOG_ONCE = UniqueLogger(CONAN_LOG)
PARENT_PROCS = [parent.name() for parent in Process(os.getppid()).parents()]
LOG_HINTS: Dict[str, Optional[int]] = {}
LOG_WARNING_COUNT = conmon_setting("log.warning_count", True)


def filehandler(key: str, mode="w", hint="") -> TextIO:
    path = conmon_setting(key)
    if isinstance(path, str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        if hint:
            LOG_HINTS.setdefault(f"saved {hint} to {path!r}", logging.DEBUG)
    elif hint:
        env_key = f"CONMON_{key.upper()}"
        hint_path = key.replace("_", ".")
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
        template = f"hint: execute {fmt!r} to save {{}}"
        LOG_HINTS.setdefault(template.format(env_key, hint_path, hint))

    return open(path or os.devnull, mode=mode, encoding="utf-8")


class DefaultDict(UserDict):
    STDOUT_LIST = list if conmon_setting("report.stdout", True) else NullList
    STDERR_LIST = list if conmon_setting("report.stderr", True) else NullList
    DEFAULT = {
        "stdout": STDOUT_LIST,
        "stderr": STDERR_LIST,
        "package": STDOUT_LIST,
        "export": STDOUT_LIST,
        "stderr_lines": list,
    }

    def __getitem__(self, item):
        data = self.data
        if item not in data:
            defaultcls = self.DEFAULT.get(item, self.__class__)
            value = data[item] = defaultcls()
            return value
        return data[item]

    def setdefault(self, key, *args):
        if args:
            return self.data.setdefault(key, *args)
        return self[key]


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

        log["stdout"].append(line)
        self.deactivate()


class Requirements(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        self.stdout = parser.log["stdout"]
        pattern, flags = compact_pattern(REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern} from (?P<remote>'?[\w\- ]+'?) +- +(?P<status>\w+)", flags
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
        self.log[name].update(mapping)

    def _deactivate(self, final=False):
        self.indent_ref = max(
            [self.indent_ref, *(len(item["ref"]) for item in self.req)]
        )
        for item in sorted(self.req, key=itemgetter("status", "remote", "ref")):
            self.screen.print(
                f"    {item['status']:^10} {item['ref']:{self.indent_ref}} from "
                f"{item['remote']}"
            )
        self.req.clear()
        super()._deactivate(final=False)


class Packages(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        self.stdout = parser.log["stdout"]
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
        self.log[name].update(dict(package_id=package_id, package_revision=None))

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
    SKIP_NEXT = True

    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.lines: List[str] = []
        self.profile_type = "host"
        self.log = parser.log["profile"]

    def activated(self, parsed_line: Match) -> bool:
        match = re.fullmatch(
            r"Configuration(?: \(profile_(?P<ptype>[a-z]+)\))?:",
            parsed_line.group("rest"),
        )
        if match:
            self.lines.clear()
            self.profile_type = match.group("ptype") or self.profile_type
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group(0)
        if not line:
            self.deactivate()
        else:
            self.lines.append(line)

    def _deactivate(self, final=False):
        buffer = StringIO("\n".join(self.lines))
        config = StrictConfigParser()
        config.read_file(buffer, "profile.ini")
        log = self.log[self.profile_type]

        for section in config.sections():
            log[section] = dict(config.items(section))

        super()._deactivate(final=False)


class Package(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.defaultlog

    def activated(self, parsed_line: Match) -> bool:
        line, ref, rest = parsed_line.group(0, "ref", "rest")
        if rest == "Calling package()":
            self.screen.print(f"Packaging {ref}")
            self.log = self.parser.getdefaultlog(ref)
            self.log["stdout"].append(line)
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line = parsed_line.group("rest")
        match = re.match(
            r"(?P<prefix>[\w ]+) '?(?P<id>[a-z0-9]{32,40})(?:[' ]|$)", line
        )
        if not match:
            self.log["package"].append(line)
            return

        if match.group("prefix") == "Created package revision":
            self.log["package_revision"] = match.group("id")
            self.deactivate()
            return

        self.log["package_id"] = match.group("id")

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class Export(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser

    def activated(self, parsed_line: Match) -> bool:
        rest = parsed_line.group("rest")
        if rest == "Exporting package recipe":
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        line, ref, rest = parsed_line.group(0, "ref", "rest")
        match = re.match("Exported revision: (?P<recipe_revision>[a-f0-9]{32})", rest)
        log = self.parser.getdefaultlog(ref)

        if match:
            log.update(match.groupdict())
            self.deactivate()
        else:
            log["export"].append(line)

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=True)


class Build(State):
    MAX_WIDTH = 65
    PROC_JSON_RESET = False
    _WARNINGS: Set[str] = set()
    REF_LOG_KEY = "build"

    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.warnings = 0
        self.buildmon = BuildMonitor(self.parser.process)
        self.log = parser.defaultlog
        self.ref = "???"
        self.force_status = False
        if not Build.PROC_JSON_RESET:
            with filehandler("proc_json", hint="process debug json") as fh:
                fh.write("{}")
            Build.PROC_JSON_RESET = True

    def _activated(self, parsed_line: Match) -> bool:
        line, self.ref = parsed_line.group("rest", "ref")
        if line == "Calling build()":
            self.screen.print(f"Building {self.ref}")
            return True
        return False

    @staticmethod
    def _deactivated(parsed_line: Match) -> bool:
        line = parsed_line.group("rest")
        match = re.fullmatch(r"Package '\w+' built", line)
        return bool(match) or line.startswith("ERROR:")

    def activated(self, parsed_line: Match) -> bool:
        full_line, ref = parsed_line.group(0, "ref")
        if self._activated(parsed_line):
            defaultlog = self.parser.getdefaultlog(ref)
            defaultlog["stdout"].append(full_line)
            self.log = self.parser.defaultlog = defaultlog[self.REF_LOG_KEY]
            self.buildmon.start()
            proc_json = getattr(self.parser.process, "proc_json", {})
            for proc_info in proc_json.get(ref, ()):
                self.buildmon.proc_cache[freeze_json_object(proc_info)] = None
            return True
        return False

    def flush_warning_count(self):
        if self.warnings and BLOG.isEnabledFor(logging.WARNING):
            esc = logger_escape_code(BLOG, "WARNING")
            self.screen.print(
                f"{esc}{self.warnings:4} warning(s)",
                indent=0,
            )
        self.warnings = 0

    def process(self, parsed_line: Match) -> None:
        if self._deactivated(parsed_line):
            self.deactivate()
            return

        line = parsed_line.group("rest")
        if not line:
            return

        self.log["stdout"].append(parsed_line.group())
        match = BUILD_STATUS_REGEX.fullmatch(line) or BUILD_STATUS_REGEX2.match(line)
        if match:
            status, file = match.groups()
            if status:
                self.force_status = True
            elif self.force_status:
                return
            self.flush_warning_count()
            with suppress(ValueError, AttributeError):
                _current, _total = status.strip("[]").split("/")
                status = f"[{_current:>{len(_total)}}/{_total}]"
            prefix = f"{status} " if status else ""
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
        elif line.startswith("-- ") or line.lower().startswith("checking "):
            self.screen.print(shorten_conan_path(line), overwrite=True)
        else:
            match = self.parser.SEVERITY_REGEX.match(line)
            if not (match and added_first(self._WARNINGS, match.group())):
                return
            level_name = levelname_from_severity(match.group("severity"))
            if level_name in {"ERROR", "CRITICAL"}:
                esc = logger_escape_code(BLOG, level_name)
                self.screen.print(f"{esc}E {line}")
            elif LOG_WARNING_COUNT and level_name == "WARNING":
                self.warnings += 1

    def filtered_tus(
        self, tu_list: Iterable[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        src_filter = {
            None: lambda path: "meson-private" in path.parts,
            "b2": lambda path: path.as_posix().endswith("/config/checks/test_case.cpp"),
            "cmake": lambda path: re.search(
                r"/(cmake-[23].\d{2}|CMakeTmp|CMakeFiles/(Check[a-zA-Z]+|CMakeScratch)"
                r"|CMakeFiles/[23](\.\d+){1,2})/",
                path.as_posix(),
            )
            or re.search(r"/cmake/test_[a-z]+\.c", path.as_posix()),
            "conftest": lambda path: path.stem == "conftest",
            "make": lambda path: path.stem in {"conftest", "dummy"}
            or path.parent.as_posix().endswith("/tools/build/feature"),
        }
        active_filters = {
            key: value
            for key, value in src_filter.items()
            if key in self.buildmon.executables or key is None
        }

        src_counter = 0
        set_counter = 0
        discarded_files: Set[str] = set()

        no_object_flags = {"-M", "-MM", "-MF", "-MT"}
        for unit in tu_list:
            flagset = set(unit.get("flags", ()))
            discarded = "RC_INVOKED" in unit.get(
                "defines", ()
            ) or not flagset.isdisjoint(no_object_flags)
            for test in active_filters.values():
                sources = unit["sources"]
                if not discarded and any(test(Path(src)) for src in sources):
                    src_counter += len(sources)
                    set_counter += 1
                    discarded_files.update(src.name for src in sources)
                    discarded = True
            if not discarded:
                yield unit

        if src_counter:
            CONMON_LOG.debug(
                "Discarded %s source files and %s translation sets (%s)",
                src_counter,
                set_counter,
                ", ".join(sorted(discarded_files)),
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

    def dump_debug_proc(self):
        proc_obj = {}
        with suppress(ValueError, OSError, TypeError):
            with filehandler(
                "proc_json", mode="r", hint="process debug json"
            ) as proc_fh:
                proc_obj.update(json.load(proc_fh))

        proc_obj[self.ref] = list(self.buildmon.proc_cache.values())
        with filehandler("proc_json", hint="process debug json") as proc_fh:
            json.dump(
                proc_obj,
                proc_fh,
                indent=2,
            )

    def _deactivate(self, final=False):
        self.force_status = False
        self.flush_warning_count()
        self.parser.screen.reset()
        self.buildmon.stop()
        self.dump_debug_proc()

        stderr_lines = self.log.pop("stderr_lines", ())
        self.log["stderr"].extend(chain(*stderr_lines))
        self.log["translation_units"] = list(
            self.processed_tus(self.buildmon.translation_units)
        )

        build_stdout = "\n".join(self.log["stdout"]) + "\n"
        build_stderr = "\n".join(self.log["stderr"]) + "\n"

        match_map = dict()  # pylint: disable=use-dict-literal
        filter_by_regex(build_stdout, match_map, **Regex.dict("gnu", "msvc", "build"))
        build_stderr = filter_by_regex(
            build_stderr, match_map, **Regex.dict("gnu", "msvc", "cmake", "autotools")
        )
        self.log["warnings"] = list(
            sorted_dicts(
                warnings_from_matches(**match_map),
                keys=(
                    "from",
                    "severity",
                    "file",
                    "line",
                    "column",
                    "category",
                    "info",
                    "hint",
                ),
                reorder_keys=True,
            )
        )

        build_stderr = filter_by_regex(
            build_stderr,
            {},
            empty_lines=re.compile(r"(?m)^\s*\n"),
            warnings_generated=re.compile(r"(?m)^\d+ warnings?.* generated\.\n"),
            stop="^Stop.\n",
            meson_status=re.compile(
                r"(?m)^(Generating targets|(Writing )?build\.ninja): +\d+ *%.+\n"
            ),
            msvc_tools=re.compile(r"(?m)^(Microsoft|Copyright) \([RC]\) .+\n"),
        )
        build_stderr = "".join(unique(build_stderr.splitlines(keepends=True))).rstrip()
        if build_stderr:
            CONMON_LOG.debug(
                "unprocessed stderr:\n%s",
                indent(shorten_conan_path(build_stderr), "  "),
            )

        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class BuildTest(Build):
    REF_LOG_KEY = "test_build"

    def _activated(self, parsed_line: Match) -> bool:
        line, ref = parsed_line.group("rest", "ref")
        if line == "(test package): Calling build()":
            self.ref = f"{ref} (test package)"
            self.screen.print(f"Building {self.ref}")
            return True
        return False

    @staticmethod
    def _deactivated(parsed_line: Match) -> bool:
        return parsed_line.group("rest") == "(test package): Running test()"


class RunTest(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.defaultlog

    def activated(self, parsed_line: Match) -> bool:
        full_line, ref, line = parsed_line.group(0, "ref", "rest")
        if line == "(test package): Running test()":
            self.screen.print(f"Running test for {ref}")
            defaultlog = self.parser.getdefaultlog(ref)
            defaultlog["stdout"].append(full_line)
            self.log = self.parser.defaultlog = defaultlog["test_run"]
            return True
        return False

    def process(self, parsed_line: Match) -> None:
        self.log["stdout"].append(parsed_line.group(0))

    def _deactivate(self, final=False):
        stderr_lines = self.log.pop("stderr_lines", ())
        self.log["stderr"].extend(chain(*stderr_lines))
        self.parser.setdefaultlog()
        super()._deactivate(final=True)


class ConanParser:
    CONAN_VERSION = "<undefined>"
    SEVERITY_REGEX = re.compile(
        r"(?xm).+?:\ (?P<severity>warning|error|fatal\ error)(?:\ ?:\ |\ [a-zA-Z])"
    )
    LINE_REGEX = re.compile(
        rf"(?:{compact_pattern(REF_REGEX)[0]}(?:: ?| ))?(?P<rest>[^\r\n]*)"
    )

    def __init__(self, process: Process):
        self.process = process
        self.log = DefaultDict()
        self.defaultlog = self.log
        self.screen = ScreenWriter()

        self.log["conan"] = dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.implementation.version))
            + f" ({sys.implementation.name})",
            version=self.CONAN_VERSION,
            command=process.cmdline(),
        )

        self.states = StateMachine(
            self,
            Export,
            Config,
            Requirements,
            Packages,
            Build,
            Package,
            BuildTest,
            RunTest,
            default=Default,
        )

    def parse_line(self, line) -> Match:
        match = self.LINE_REGEX.match(line)
        assert match
        return match

    def getdefaultlog(self, name: Optional[str] = None) -> DefaultDict:
        if name is None:
            log = self.log
        else:
            name, *_ = name.split("/", maxsplit=1)
            log = self.log["requirements"][name]

        return log

    def setdefaultlog(self, name: Optional[str] = None) -> DefaultDict:
        log = self.getdefaultlog(name)
        self.defaultlog = log
        return log

    def process_errors(self, lines: Iterable[str]):
        processed: List[str] = []
        loglevel: int = logging.WARNING
        residue: List[str] = []
        stderr: List[str] = []
        ref: Optional[str] = None

        def flush():
            if not processed:
                return

            self.screen.reset()
            max_width = (get_terminal_width() or 140) - 20

            if loglevel in {logging.ERROR, logging.CRITICAL}:
                _lines = processed
            else:
                _lines = [
                    shorten_per_line(
                        "\n".join(processed),
                        width=max_width,
                        strip="middle",
                        placeholder=" [...] ",
                        indent="  ",
                        keep_first=False,
                    )
                ]
            CONAN_LOG_ONCE.log(loglevel, "\n".join(_lines))
            self.getdefaultlog(ref)["stderr"].extend(stderr)

        if not "".join(lines).rstrip():
            return

        for line in lines:
            match = Regex.CONAN.match(line)
            line = line.rstrip("\n")
            if match:
                flush()
                ref, severity_l, severity_r, info = match.group(
                    "ref", "severity_l", "severity", "info"
                )
                severity = severity_l or severity_r
                loglevel = level_from_name(severity, logging.WARNING)
                prefix = f"{ref}: " if ref else ""
                processed = [f"{prefix}{shorten_conan_path(info)}"]
                stderr = [line]
            elif processed or self.defaultlog == self.log:
                processed.append(shorten_conan_path(line))
                stderr.append(line)
            else:
                residue.append(line)

        flush()
        if residue:
            self.defaultlog["stderr_lines"].append(residue)

    def process_line(self, line: str):
        line = line.rstrip()
        parsed_line = self.parse_line(line)
        ref, rest = parsed_line.group("ref", "rest")

        if ref and "is locked by another concurrent conan process" in rest:
            CONAN_LOG.warning(line)
            self.process.kill()

        self.states.process_hooks(parsed_line)

    def process_streams(self, raw_fh: TextIO):
        streams: Any = (
            ProcessStreamHandler(self.process)
            if isinstance(self.process, Popen)
            else ReplayStreamHandler()
        )
        marker = "{:-^120}\n"
        stderr_marker_start = marker.format(" <stderr> ")
        stdout_marker_start = marker.format(" <stdout> ")
        stderr_written = True
        log_states = conmon_setting("log_states", False)
        decolorize = cast(
            Callable[[Iterable[str]], Iterator[str]],
            partial(map, partial(DECOLORIZE_REGEX.sub, "")),
        )

        readmerged = os.name == "posix" and conmon_setting(
            "build.merge_stderr", default=False
        )
        while not streams.exhausted:
            try:
                if readmerged and isinstance(self.states.active_instance(), Build):
                    stderr: Tuple[str, ...] = ()
                    stdout = streams.readmerged()
                else:
                    stdout, stderr = streams.readboth()
            except KeyboardInterrupt:
                with suppress(KeyboardInterrupt):
                    self.screen.reset()
                    CONMON_LOG.warning("Pressed Ctrl+C")
                break

            if stdout:
                if stderr_written:
                    raw_fh.write(stdout_marker_start)
                    stderr_written = False

                for line in decolorize(stdout):
                    self.process_line(line)
                    if log_states and line:
                        state = self.states.active_instance()
                        name = state and type(state).__name__
                        raw_fh.write(f"[{name}] {line}")
                    else:
                        raw_fh.write(line)
                raw_fh.flush()

            if stderr:
                raw_fh.write(
                    "".join(
                        (
                            "" if stderr_written else stderr_marker_start,
                            *decolorize(stderr),
                        )
                    )
                )
                raw_fh.flush()
                stderr_written = True
                self.process_errors(stderr)

    def process_tracelog(self, trace_path: Path):
        actions: List[Dict[str, Any]] = []
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            action = json.loads(line)
            if action.get("_action") == "COMMAND":
                actions.clear()
            actions.append(action)

        self.log["conan"]["tracelog"] = tracelog = []
        for action in actions:
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
        try:
            self.log["conan"]["returncode"] = self.process.wait()
        except KeyboardInterrupt:
            if self.process.is_running():
                self.process.kill()
            self.log["conan"]["returncode"] = self.process.wait()


def monitor(args: List[str], replay=False) -> int:
    # prevent MsBuild from allocating workers
    # which are not children of the parent process
    os.environ["MSBUILDDISABLENODEREUSE"] = "1"
    # tell conan not to prompt for user input
    os.environ["CONAN_NON_INTERACTIVE"] = "1"
    # set conan logging level
    os.environ["CONAN_LOGGING_LEVEL"] = "FATAL"

    if conmon_setting("tracelog", False) and not os.getenv("CONAN_TRACE_FILE"):
        tmp_file, tmp_name = tempfile.mkstemp()
        os.environ["CONAN_TRACE_FILE"] = tmp_name
        os.close(tmp_file)

    conan_command, ConanParser.CONAN_VERSION = call_cmd_and_version()
    conan_command.extend(args)
    process = (
        ReplayProcess()
        if replay
        else Popen(
            conan_command, stdout=PIPE, stderr=PIPE, universal_newlines=True, bufsize=0
        )
    )
    cycle_time_s = conmon_setting("build.monitor", True)
    if isinstance(cycle_time_s, float):
        BuildMonitor.CYCLE_TIME_S = cycle_time_s
    elif not cycle_time_s:
        BuildMonitor.ACTIVE = False
    parser = ConanParser(process)
    for item in ("conan_log", "report_json", "proc_json"):
        # copy replay file before opening or delete old ones
        path = replay_logfile(item, create_if_not_exists=replay)
        if not replay and path and path.is_file():
            path.unlink()
    with filehandler("conan_log", hint="raw conan output") as fh:
        parser.process_streams(fh)
    parser.finalize()

    if conmon_setting("tracelog", False):
        trace_path = Path(os.getenv("CONAN_TRACE_FILE", "."))
        if trace_path.is_file():
            parser.process_tracelog(trace_path)
        if trace_path.name.startswith("tmp"):
            for path in (trace_path, Path(f"{trace_path}.lock")):
                with suppress(FileNotFoundError):
                    path.unlink()

    with filehandler("report_json", hint="report json") as fh:
        json.dump(parser.log, fh, indent=2)

    returncode = process.wait()
    if returncode:
        CONMON_LOG.error("conan exited with code %s", returncode)
    for hint, level in LOG_HINTS.items():
        CONMON_LOG.log(level or logging.INFO, hint)

    return returncode


def main(argv: Optional[List[str]] = None) -> int:
    """main entry point for console script"""
    initialize_logging()
    args = parse_args(argv or sys.argv[1:])

    if os.getenv("CI"):
        CONMON_LOG.info("Running in Gitlab CI")

    return monitor(args.cmd, args.replay)


def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "Run conan as monitored process with parsed JSON output"
    parser = argparse.ArgumentParser(
        description=description, prog="conmon", add_help=True, allow_abbrev=False
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s version {__version__}"
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="simulate last run based on written logs",
    )
    parser.add_argument(
        "cmd",
        metavar="<command>",
        help="conan command and options",
        nargs=argparse.REMAINDER,
    )

    known_args, unknown_args = parser.parse_known_args(args)
    known_args.cmd[:0] = unknown_args

    if not (known_args.cmd or known_args.replay):
        parser.print_help()
        parser.exit()

    return known_args


if __name__ == "__main__":
    sys.exit(main())
