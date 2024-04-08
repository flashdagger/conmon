#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import logging
import os
import platform
import re
import sys
import tempfile
from configparser import ParsingError
from contextlib import contextmanager, suppress
from functools import partial
from io import StringIO
from operator import itemgetter
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT
from typing import (
    IO,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    cast,
)

from . import __version__, json
from .buildmon import BuildMonitor
from .conan import LOG as CONAN_LOG
from .conan import call_cmd_and_version, conmon_setting, report_path
from .logging import UniqueLogger, get_logger
from .logging import init as initialize_logging
from .logging import level_from_name, logger_escape_code
from .regex import (
    CMAKE_BUILD_PATH_REGEX,
    DECOLORIZE_REGEX,
    REF_REGEX,
    MultiRegexFilter,
    ParsedLine,
    RegexFilter,
    build_status,
    compact_pattern,
    shorten_conan_path,
)
from .replay import ReplayCommand, replay_logfile
from .shell import Command
from .state import State, StateMachine
from .utils import (
    CachedLines,
    ScreenWriter,
    StopWatch,
    StrictConfigParser,
    added_first,
    freeze_json_object,
    get_terminal_width,
    shorten,
    shorten_per_line,
    sorted_mappings,
)
from .warnings import LOG as BLOG
from .warnings import (
    BuildRegex,
    IgnoreRegex,
    levelname_from_severity,
    warnings_from_matches,
)

CONMON_LOG = get_logger("CONMON")
CONAN_LOG_ONCE = UniqueLogger(CONAN_LOG)
LOG_WARNING_COUNT = conmon_setting("log:warning_count")


def log_stderr():
    value = conmon_setting("log:stderr")
    if not value:
        return DEVNULL
    if str(value).lower() == "stdout":
        return STDOUT
    return PIPE


@contextmanager
def filehandler(key: str, mode="w", hint=""):
    path = report_path(key)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        path = Path(os.devnull)

    with path.open(mode=mode, encoding="utf-8") as fh:
        yield fh

    if path != Path(os.devnull):
        CONMON_LOG.debug("saved %s to %s", hint, path)


class DefaultDict(dict):
    DEFAULT = {
        "stdout": CachedLines,
        "stderr": CachedLines,
        "_stderr": CachedLines,
        "_stdout": CachedLines,
        "export": CachedLines,
    }

    def __getitem__(self, item):
        try:
            return super().__getitem__(item)
        except KeyError:
            defaultcls = self.DEFAULT.get(item, self.__class__)
            value = self[item] = defaultcls()
            return value


class Default(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.overwrite = False
        self.last_ref = None

    def activated(self, parsed: ParsedLine) -> bool:
        return False

    def process(self, parsed: ParsedLine) -> None:
        line = parsed.line
        log = self.parser.log

        # rest = parsed.rest
        # if "is locked by another concurrent conan process" in rest:
        #     self.parser.command.wait(terminate=True)
        #     CONAN_LOG.warning(line)
        #     self.parser.defaultlog["stdout"].append(line)
        #     self.deactivate()
        #     return

        if re.match(r"[=-]{8}[ \w]+[=-]{8}", line):
            self.overwrite = True

        ref = parsed.ref
        if ref:
            self.last_ref = ref
            log = self.parser.getdefaultlog(ref)
            self.screen.print(f"{line} ", overwrite=True)
        elif line:
            self.screen.print(f"{line} ", overwrite=self.overwrite)

        log["stdout"].append(line)
        self.deactivate()


class Requirements(State):
    _pattern, _flags = compact_pattern(REF_REGEX)
    REGEX = re.compile(
        rf" +{_pattern}"
        r"#(?P<rrev>[0-9a-f]{32})"
        r"(?::(?P<package_id>[0-9a-f]{40}))?"
        r"(?:#(?P<prev>[0-9a-f]{32}))?"
        r" +- +(?P<status>\w+)(?: \((?P<remote>[\w\- ]+)\))?",
        flags=_flags,
    )

    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        self.stdout = parser.log["stdout"]
        self.req: List[Dict[str, Optional[str]]] = []
        self.indent_ref = 0
        self.is_tool = False

    def activated(self, parsed: ParsedLine) -> bool:
        rest = parsed.rest
        return "= Computing " in rest

    def process(self, parsed: ParsedLine) -> None:
        line = parsed.line
        if not line:
            self.is_tool = False
            self.deactivate()
            return

        if line == "Build requirements":
            self.is_tool = True
            return

        ref = parsed.ref
        if ref:
            name, *_ = ref.split("/", maxsplit=1)
            self.log[name]["stdout"].append(line)

        match = self.REGEX.match(line)
        if not match:
            return
        mapping = match.groupdict()
        if self.is_tool:
            mapping["ref"] = f'[{mapping["ref"]}]'
        self.req.append(mapping)
        self.log[mapping["name"]].update(
            (key, value)
            for key, value in mapping.items()
            if key not in {"name", "ref", "status"}
        )

    def _deactivate(self, final=False):
        self.indent_ref = max(
            [self.indent_ref, *(len(item["ref"]) for item in self.req)]
        )
        requirements = self.req
        if requirements:
            title = (
                "Package requirements:"
                if requirements[0]["package_id"]
                else "Recipe requirements:"
            )
            self.screen.print(title)
            for (
                item
            ) in (
                requirements
            ):  # sorted(requirements, key=itemgetter("status", "remote", "ref")):
                status = item["status"]
                if status == "Cache":
                    action = (
                        f"cached ({item['package_id']})"
                        if item["package_id"]
                        else "cached"
                    )

                elif status == "Build":
                    action = status.lower()
                else:
                    action = f"{status.lower():8} from {item['remote']!r}"

                req_id = item["package_id"] or item["rrev"]
                self.screen.print(
                    f"    {item['ref']:{self.indent_ref}} {req_id} {action}"
                )
            self.screen.print()
            self.req.clear()
        super()._deactivate(final=False)


class Packages(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.log = parser.log["requirements"]
        self.stdout = parser.log["stdout"]
        pattern, flags = compact_pattern(REF_REGEX)
        self.regex = re.compile(
            rf" +{pattern}:(?P<package_id>[a-zA-Z0-9]+) +- +(?P<status>\w+)", flags
        )
        self.pkg: List[Dict[str, Optional[str]]] = []
        self.indent_ref = 0

    def activated(self, parsed: ParsedLine) -> bool:
        rest = parsed.rest
        if rest in {"Packages", "Build requirements packages"}:
            self.screen.print(rest)
            self.stdout.append(parsed.line)
            return True
        return False

    def process(self, parsed: ParsedLine) -> None:
        line = parsed.line
        match = self.regex.match(line)
        if not match:
            self.deactivate()
            return

        self.pkg.append(match.groupdict())
        self.stdout.append(line)
        name, package_id = match.group("name", "package_id")
        self.log[name]["package_id"] = package_id

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
        self._final = True

    def activated(self, parsed: ParsedLine) -> bool:
        return "= Input profiles =" in parsed.rest

    def process(self, parsed: ParsedLine) -> None:
        match = re.fullmatch(
            r"Profile (?P<ptype>[a-z]+):",
            parsed.rest,
        )
        if match:
            self.lines.clear()
            self.profile_type = match.group("ptype") or self.profile_type
            self._final = match.group("ptype") in (None, "build")
            return

        line = parsed.line
        if not line:
            self._flush()
        else:
            self.lines.append(line)

    def _flush(self):
        if not self.lines:
            self._deactivate(final=self._final)
        buffer = StringIO("\n".join(self.lines))
        self.lines.clear()
        config = StrictConfigParser()
        try:
            config.read_file(buffer, "profile.ini")
            log = self.log[self.profile_type]

            for section in config.sections():
                log[section] = dict(config.items(section))
        except ParsingError as exc:
            CONMON_LOG.error("Config parsing error: %s", exc.message, exc_info=exc)
            for line in buffer.readlines():
                print(repr(line))


class Generate(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.defaultlog

    def activated(self, parsed: ParsedLine) -> bool:
        rest = parsed.rest
        if rest == "Calling generate()":
            ref = parsed.ref
            self.screen.print(f"Generating for {ref}", overwrite=True)
            defaultlog = self.parser.getdefaultlog(ref)
            defaultlog["stdout"].append(parsed.line)
            self.log = self.parser.defaultlog = defaultlog["generate"]
            return True
        return False

    def process(self, parsed: ParsedLine) -> None:
        rest = parsed.rest
        if rest.startswith("Calling "):
            self.deactivate()
        else:
            self.log["stdout"].append(rest)


class Package(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.defaultlog

    def activated(self, parsed: ParsedLine) -> bool:
        rest = parsed.rest
        if rest == "Calling package()":
            ref = parsed.ref
            self.screen.print(f"Packaging {ref}")
            defaultlog = self.parser.getdefaultlog(ref)
            defaultlog["stdout"].append(parsed.line)
            self.log = self.parser.defaultlog = defaultlog["package"]
            return True
        return False

    def process(self, parsed: ParsedLine) -> None:
        rest = parsed.rest
        match = re.match(
            r"(?P<prefix>[\w ]+) '?(?P<id>[a-z0-9]{32,40})(?:[' ]|$)", rest
        )
        if not match:
            self.log["stdout"].append(rest)
            return

        if match.group("prefix") == "Created package revision":
            self.log["created_revision"] = match.group("id")
            self.deactivate()
            return

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class Export(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser

    def activated(self, parsed: ParsedLine) -> bool:
        if parsed.line.endswith("Exporting package recipe"):
            return True
        return False

    def process(self, parsed: ParsedLine) -> None:
        match = re.match(
            "Exported revision: (?P<recipe_revision>[a-f0-9]{32})", parsed.rest
        )
        log = self.parser.getdefaultlog(parsed.ref)

        if match:
            log.update(match.groupdict())
            self.deactivate()
        else:
            log["export"].append(parsed.line)

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=True)


class Build(State):
    MAX_WIDTH = 65
    _WARNINGS: Set[str] = set()
    REF_LOG_KEY = "build"

    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.warnings = 0
        self.buildmon = BuildMonitor(self.parser.command.proc.pid)
        self.log = parser.defaultlog
        self.refspec = self.stopline = "???"
        self.force_status = False
        self.warning_filter = MultiRegexFilter(
            dict(
                gnu=RegexFilter(BuildRegex.GNU, 20),
                msvc=RegexFilter(BuildRegex.MSVC, 20),
                cmake=RegexFilter(BuildRegex.CMAKE, 20),
                autotools=RegexFilter(BuildRegex.AUTOTOOLS, 10),
            ),
            uniquematches=True,
        )

    def activated(self, parsed: ParsedLine) -> bool:
        if not parsed.line.endswith("Calling build()"):
            return False

        ref = parsed.ref
        assert ref, repr(parsed.line)
        defaultlog = self.parser.getdefaultlog(ref)
        defaultlog["stdout"].append(parsed.line)
        if parsed.refspec:
            ref = f"{ref} ({parsed.refspec})"
            log_key = f"build_{parsed.refspec.replace(' ', '_')}"
            self.stopline = "Running test()"
        else:
            self.stopline = f"Package '{defaultlog['package_id']}' built"
            log_key = "build"

        self.refspec = ref
        self.log = self.parser.defaultlog = defaultlog[log_key]
        self.log["stderr"].saveposition(self)
        self.log["stdout"].saveposition(self)
        self.buildmon.start()
        self.screen.print(f"Building {ref}")
        return True

    def flush_warning_count(self):
        if self.warnings and BLOG.isEnabledFor(logging.WARNING):
            esc = logger_escape_code(BLOG, "WARNING")
            self.screen.print(
                f"{esc}{self.warnings:4} warning(s)",
                indent=self.MAX_WIDTH,
            )
        self.warnings = 0

    def process(self, parsed: ParsedLine) -> None:
        rest = parsed.rest
        if rest == self.stopline or rest.startswith("ERROR:"):
            self.deactivate()
            return

        self.log["stdout"].append(parsed.line)
        status, file = build_status(rest)
        if file:
            if status:
                self.force_status = True
            elif self.force_status:
                return
            self.flush_warning_count()
            with suppress(ValueError, AssertionError):
                assert status
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
            self.screen.print(output, overwrite=True)
        elif rest.startswith("-- ") or rest.lower().startswith("checking "):
            self.screen.print(shorten_conan_path(rest), overwrite=True)
        elif LOG_WARNING_COUNT:
            match = self.parser.SEVERITY_REGEX.match(rest)
            if not (match and added_first(self._WARNINGS, match.group())):
                return
            level_name = levelname_from_severity(match.group("severity"))
            if level_name in {"ERROR", "CRITICAL"}:
                esc = logger_escape_code(BLOG, level_name)
                self.screen.print(f"{esc}E {rest}")
            elif level_name == "WARNING":
                self.warnings += 1

    def filtered_tus(
        self, tu_list: Iterable[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        src_filter = {
            None: lambda path: "meson-private" in path.parts
            or Path(tempfile.gettempdir()) in path.parents,
            "b2": lambda path: path.as_posix().endswith("/config/checks/test_case.cpp"),
            "cmake": lambda path: CMAKE_BUILD_PATH_REGEX.search(path.as_posix()),
            "conftest": lambda path: path.stem == "conftest",
            "make": lambda path: path.stem in {"conftest", "dummy"}
            or path.parent.as_posix().endswith("/tools/build/feature"),
        }
        key_set: Set = {None}
        key_set.update(self.buildmon.executables)
        active_filters = {
            key: value for key, value in src_filter.items() if key in key_set
        }

        src_counter = set_counter = 0
        discarded_files: Set[str] = set()
        for unit in tu_list:
            discarded = "RC_INVOKED" in unit.get("defines", ()) or not {
                "-M",
                "-MM",
            }.isdisjoint(unit.get("flags", ()))
            for test in active_filters.values():
                sources = unit["sources"]
                if discarded or any(test(Path(src)) for src in sources):
                    src_counter += len(sources)
                    set_counter += 1
                    discarded_files.update(src.name for src in sources)
                    break
            else:
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
        proc_list = list(self.buildmon.proc_cache.values())
        if not (self.buildmon.ACTIVE or proc_list):
            return
        path = report_path("proc.json")
        if not path:
            return

        if path.is_file():
            json.update({(): {self.refspec: proc_list}}, path, indent=2)
            CONMON_LOG.debug("updated %r with %s items", str(path), len(proc_list))
        elif not path.exists():
            hint = f"debug process dump with {len(proc_list)} items"
            with filehandler("proc.json", "w", hint=hint) as fh:
                json.dump({self.refspec: proc_list}, fh, indent=2)

    def flush(self, final=False):
        for name in ("stderr", "stdout"):
            pipe = self.log[name]
            if not (final or pipe.size(self)):
                continue
            self.warning_filter.context = name
            residue_str = self.warning_filter(pipe.read(marker=self), final=final)
            if not conmon_setting(f"report:build_{name}"):
                pipe.clear()
            pipe.saveposition(self)
            if name == "stderr":
                residue_str = MultiRegexFilter(IgnoreRegex.dict(), uniquematches=False)(
                    residue_str, final=True
                )
                if residue_str:
                    self.log[f"_{name}"].write(residue_str)

    def _deactivate(self, final=False):
        self.force_status = False
        self.flush_warning_count()
        self.parser.screen.reset()

        proc_json = getattr(self.parser.command, "proc_json", {})
        for proc_info in proc_json.get(self.refspec, ()):
            self.buildmon.proc_cache[freeze_json_object(proc_info)] = None

        self.buildmon.stop()
        self.dump_debug_proc()
        self.flush(final=True)
        self.log["translation_units"] = list(
            self.processed_tus(self.buildmon.translation_units)
        )
        self.log["warnings"] = list(
            sorted_mappings(
                warnings_from_matches(**self.warning_filter.matches),
                keys=(
                    "from",
                    "severity",
                    "file",
                    "function",
                    "line",
                    "column",
                    "category",
                    "info",
                    "hint",
                ),
                reorder_keys=True,
            )
        )
        self.warning_filter.clear()
        self.parser.setdefaultlog()
        super()._deactivate(final=False)


class RunTest(State):
    def __init__(self, parser: "ConanParser"):
        super().__init__(parser)
        self.parser = parser
        self.log = parser.defaultlog

    def activated(self, parsed: ParsedLine) -> bool:
        if parsed.line.endswith("Running test()"):
            ref = parsed.ref
            self.screen.print(f"Running test for {ref}")
            defaultlog = self.parser.getdefaultlog(ref)
            defaultlog["stdout"].append(parsed.line)
            self.log = self.parser.defaultlog = defaultlog["test_run"]
            return True
        return False

    def process(self, parsed: ParsedLine) -> None:
        self.log["stdout"].append(parsed.line)

    def _deactivate(self, final=False):
        self.parser.setdefaultlog()
        super()._deactivate(final=True)


class ConanParser:
    CONAN_VERSION = "<undefined>"
    SEVERITY_REGEX = re.compile(
        r"(?xm).+?:\ (?P<severity>warning|error|fatal\ error)(?:\ ?:\ |\ [a-zA-Z])"
    )

    def __init__(self, command: Command):
        self.command = command
        self.log = DefaultDict()
        self.defaultlog = self.log
        self.screen = ScreenWriter()

        self.log["conan"] = dict(
            build_platform=platform.platform(),
            python_version=".".join(map(str, sys.implementation.version))
            + f" ({sys.implementation.name})",
            version=self.CONAN_VERSION,
            command=command.proc.args,
        )

        self.states = StateMachine(
            self,
            Export,
            Config,
            Requirements,
            Packages,
            Generate,
            Build,
            Package,
            RunTest,
            default=Default,
        )

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
        stderr: List[str] = []
        ref: Optional[str] = None
        residue = self.defaultlog["stderr"]

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
            msg = "\n".join(_lines)
            if msg.rstrip():
                CONAN_LOG_ONCE.log(loglevel, msg)
                self.getdefaultlog(ref)["stderr"].extend(stderr)

        for line in lines:
            match = BuildRegex.CONAN.match(line)
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

    def process_streams(self, raw_fh: IO[str]):
        def marker(pipestr: str, timestamp_s=None):
            _marker = f" <{pipestr}> "
            if timestamp_s:
                _marker = f" <{pipestr}@{timestamp_s}> "
            return f"{_marker:-^120}\n"

        decolorize = cast(
            Callable[[Iterable[str]], Iterator[str]],
            partial(map, partial(DECOLORIZE_REGEX.sub, "")),
        )

        log_states = conmon_setting("report:log_states")
        flush_timer = StopWatch()
        streams = self.command.streams
        while not streams.exhausted:
            for pipe, timestamp, lines in streams.iterpipes(timeout=0.1, total=False):
                raw_fh.write(marker(pipe, timestamp_s=timestamp))
                errors: List[str] = []

                for line in decolorize(lines):
                    parsed_line = ParsedLine(line)
                    rest = parsed_line.rest
                    if (
                        rest.startswith("WARN: ")
                        or rest.startswith("ERROR: ")
                        or (
                            errors
                            and (
                                errors[-1].endswith(": \n")
                                or line.startswith(" ")
                                or line.startswith("\t")
                            )
                        )
                    ):
                        errors.append(line)
                        raw_fh.write(line)
                        continue

                    if errors:
                        self.process_errors(errors)
                        errors.clear()

                    self.states.process_hooks(parsed_line)
                    if log_states and line:
                        state = self.states.active_instance()
                        name = state and state.name
                        raw_fh.write(f"[{name}] {line}")
                    else:
                        raw_fh.write(line)

                if errors:
                    self.process_errors(errors)

                state = self.states.active_instance()
                if state:
                    state.flush()
                if flush_timer.timespan_elapsed(1.0):
                    raw_fh.flush()

    def finalize(self):
        self.states.deactivate_all()
        self.screen.reset()
        try:
            self.command.wait()
        except KeyboardInterrupt:
            self.command.wait(kill=True)
        finally:
            self.log["conan"]["returncode"] = self.command.returncode


def monitor(args: List[str], replay=False) -> int:
    # prevent MsBuild from allocating workers
    # which are not children of the parent process
    os.environ["MSBUILDDISABLENODEREUSE"] = "1"
    # set conan logging level
    os.environ["CONAN_LOG_LEVEL"] = "debug"

    conan_command, ConanParser.CONAN_VERSION = call_cmd_and_version()
    conan_command.extend(args)
    try:
        command = ReplayCommand() if replay else Command()
    except FileNotFoundError as exc:
        CONMON_LOG.error(exc)
        return -1
    command.run(conan_command, stderr=log_stderr(), errors="ignore")

    cycle_time_s = conmon_setting("build:monitor")
    if isinstance(cycle_time_s, float):
        BuildMonitor.CYCLE_TIME_S = float(cycle_time_s)
    BuildMonitor.ACTIVE = not (replay or cycle_time_s is False)
    if replay or cycle_time_s is not False:
        proc_json = report_path("proc.json")
        if proc_json and proc_json.is_file():
            proc_json.unlink()

    parser = ConanParser(command)
    for item in ("conan.log", "report.json", "proc.json"):
        # copy replay file before opening or delete old ones
        path = replay_logfile(item, create_if_not_exists=replay)
        if not replay and path and path.is_file():
            path.unlink()

    with filehandler("conan.log", "w", hint="raw conan output") as fh:
        try:
            parser.process_streams(fh)
        except KeyboardInterrupt:
            with suppress(KeyboardInterrupt):
                parser.screen.reset()
                CONMON_LOG.warning("Pressed Ctrl+C")
            parser.command.wait(terminate=True)
            CONMON_LOG.debug("process terminated")
            parser.command.streams.join()
            CONMON_LOG.debug("stopped streaming")
    parser.finalize()

    returncode = command.wait()
    if returncode:
        CONMON_LOG.error("conan exited with code %s", returncode)

    with filehandler("report.json", "w", hint="report json") as fh:
        json.dump(parser.log, fh, indent=2)

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
