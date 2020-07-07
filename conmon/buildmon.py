import argparse
import logging
import os
import re
import shlex
import time
from contextlib import suppress
from pathlib import Path
from statistics import mean, median
from textwrap import shorten
from threading import Event, Thread
from typing import Any, Dict, FrozenSet, List, Optional, Set

import psutil  # type: ignore

LOG = logging.getLogger("BUILDMON")


class WinShlex(shlex.shlex):
    """ class for splitting VS cl.exe response file commands """

    def __init__(self, input_string: str):
        super().__init__(instream=input_string.replace('\\"', '"'), posix=True)
        self.whitespace_split = True
        self.commenters = ""
        self.escape = ""

    @classmethod
    def split(cls, text: str) -> List[str]:
        """Split the string *s* using shell-like syntax."""
        lex = WinShlex(text)
        return list(lex)


class CompilerParser(argparse.ArgumentParser):
    IGNORE_FLAGS_LONG = {"-diagnostics", "-nologo", "-showIncludes"}
    IGNORE_FLAGS_SHORT = {"-o", "-s"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)
        self.add_argument(
            "-isystem",
            help="system includes",
            dest="system_includes",
            action="append",
            default=[],
        )
        self.add_argument(
            "-include",
            "-FI",
            help="forced include file",
            dest="forced_includes",
            action="append",
            default=[],
        )
        self.add_argument(
            "-I",
            "-i",
            help="include paths",
            dest="includes",
            action="append",
            default=[],
        )
        self.add_argument(
            "-c",
            help="compile sources but do not link",
            dest="compile_not_link",
            action="store_true",
        )
        self.add_argument(
            "-D", "-d", help="defines", dest="defines", action="append", default=[]
        )
        self.add_argument(
            "-U", "-u", help="undefines", dest="undefines", action="append", default=[]
        )
        self.add_argument(
            "-cc1", help="compiler frontend", dest="cc_frontend", action="store_true"
        )

    def cleanup_args(self, args):
        options = set(self.IGNORE_FLAGS_LONG)

        for action in self._actions:
            options.update(set(action.option_strings))
            if isinstance(action.default, list):
                action.default.clear()

        options = {option.lower() for option in options if not option.startswith("--")}
        options = tuple(sorted(options, reverse=True, key=len))

        new_args = []
        for arg in args:
            if arg in self.IGNORE_FLAGS_SHORT:
                continue
            for option in options:
                if not arg.lower().startswith(option):
                    continue
                prefix, rest = arg[: len(option)], arg[len(option) :]
                if prefix in self.IGNORE_FLAGS_LONG:
                    break
                assert prefix.lower() == option
                if rest:
                    new_args.extend((prefix, rest))
                else:
                    new_args.append(arg)
                break
            else:
                new_args.append(arg)

        return new_args

    def parse_known_args(self, args=None, namespace=None):
        return super().parse_known_args(
            args=self.cleanup_args(args), namespace=namespace
        )


def identify_compiler(name: str) -> Optional[str]:
    parts = set(name.replace("+", "").replace(".exe", "").split("-"))
    if parts & {"gcc", "g", "cc", "c", "clang"}:
        return "gnu"

    if "cl" in parts:
        return "msvc"

    return None


class BuildMonitor(Thread):
    PARSER = CompilerParser()

    def __init__(self, proc: psutil.Process):
        super().__init__(daemon=True)
        self.proc = proc
        self.proc_cache: Dict = dict()
        self.rsp_cache: Dict = dict()
        self.translation_units: Dict[FrozenSet, Dict] = {}
        self.flags: Set[str] = set()
        self.finish = Event()
        self.timing: List[float] = []

    @staticmethod
    def canonical_option(option: str) -> str:
        if option.startswith("/"):
            return "-" + option[1:]
        return option

    @staticmethod
    def make_absolute(path: str, cwd: str) -> str:
        if not os.path.isabs(path):
            path = os.path.join(cwd, path)
        return os.path.abspath(path)

    @staticmethod
    def is_valid_tu(file: str) -> bool:
        path = Path(file)
        if (
            path.suffix not in {".c", ".cpp", ".cxx", ".cc"}
            or set(path.parts) & {"CMakeFiles", "cmake.tmp"}
            or re.match(r".*/cmake-[23].\d+/Modules/(CMake|Check)", path.as_posix())
        ):
            return False

        return True

    def cache_responsefile(self, info: Dict):
        for arg in info["cmdline"]:
            if not arg.startswith("@"):
                continue

            response_file = Path(self.make_absolute(arg[1:], info["cwd"]))

            if response_file.exists():
                self.rsp_cache[response_file] = response_file.read_bytes()

    def parse_responsefile(
        self, cmdline: List[str], *, cwd="", posix=True
    ) -> List[str]:
        split: Any = shlex.split if posix else WinShlex.split
        encoding = "utf-8" if posix else "utf-16"
        new_cmdline = []
        for arg in cmdline:
            if not arg.startswith("@"):
                new_cmdline.append(arg)
                continue

            response_file = Path(self.make_absolute(arg[1:], cwd))
            rsp_txt = self.rsp_cache.get(response_file)

            if rsp_txt is None:
                LOG.warning("Missing response file %s", response_file)
                continue

            new_cmdline.extend(split(rsp_txt.decode(encoding=encoding)))
        return new_cmdline

    def check_process(self, process_map: Dict[str, Any]):
        compiler_type = identify_compiler(process_map["name"])
        if (
            compiler_type is None
            or process_map["cwd"] is None
            or not process_map["cmdline"]
        ):
            return

        exe = process_map["cmdline"][0]
        process_map["cmdline"] = process_map["cmdline"][1:]
        if Path(exe).is_absolute():
            process_map["exe"] = exe

        if compiler_type == "msvc":
            process_map["cmdline"] = [
                self.canonical_option(option)
                for option in self.parse_responsefile(
                    process_map["cmdline"], posix=False
                )
            ]
        elif compiler_type == "gnu":
            process_map["cmdline"] = self.parse_responsefile(
                process_map["cmdline"], cwd=process_map["cwd"]
            )
        else:
            raise Exception("Unknown compiler type %s" % compiler_type)

        self.parse_tus(process_map)

    def parse_tus(self, proc: Dict) -> None:
        args, unknown_args = self.PARSER.parse_known_args(proc["cmdline"])

        if args.cc_frontend:
            return

        if not args.compile_not_link:
            return

        args.sources = []
        args.compiler = proc["exe"]
        data = vars(args)
        for key in ("cc_frontend", "compile_not_link"):
            del data[key]

        for file in reversed(unknown_args):
            if file.startswith("-"):
                continue
            abs_file = self.make_absolute(file, proc["cwd"])
            if self.is_valid_tu(abs_file):
                data["sources"].append(abs_file)

        if not data["sources"]:
            return

        for key in ("includes", "system_includes"):
            data[key] = [self.make_absolute(path, proc["cwd"]) for path in data[key]]

        self.flags.update((arg for arg in unknown_args if re.match(r"^-[-\w=]+$", arg)))
        self.append_data(data, value_key="sources")

    def append_data(self, mapping: Dict, value_key: str):
        hash_set = set()
        for key, value in mapping.items():
            if key == value_key:
                continue
            hash_set.add((key, frozenset(value)))

        hash_set_frozen = frozenset(hash_set)
        value = self.translation_units.get(hash_set_frozen)
        if value:
            key_set = set(value[value_key])
            for next_value in mapping[value_key]:
                if next_value in key_set:
                    continue
                value[value_key].append(next_value)
        else:
            self.translation_units[hash_set_frozen] = mapping

    def scan(self) -> None:
        t_start = time.monotonic()
        try:
            children = self.proc.children(recursive=True)
        except psutil.NoSuchProcess as exc:
            LOG.error(str(exc))
            return
        for child in children:
            child_id = hash(child)
            with suppress(psutil.NoSuchProcess):
                info = child.as_dict(attrs=["exe", "cmdline", "cwd"])
                if not (info["cmdline"] and info["cwd"]):
                    continue
                info["name"] = Path(info["cmdline"][0]).name.lower()
                if identify_compiler(info["name"]):
                    if info["exe"] == "/bin/dash":
                        LOG.debug("\n")
                        LOG.warning(
                            "Async capture (%r)", shorten(info["cmdline"][-1], 60)
                        )
                        continue
                    self.proc_cache[child_id] = info
                    self.cache_responsefile(info)
        self.timing.append(time.monotonic() - t_start)

    def run(self):
        while not self.finish.is_set():
            start = time.monotonic()
            self.scan()
            sleep_time_s = 0.025 - (time.monotonic() - start)
            if sleep_time_s > 0.0:
                time.sleep(sleep_time_s)

        for info_map in self.proc_cache.values():
            self.check_process(info_map)

        num_tus = sum(len(unit["sources"]) for unit in self.translation_units.values())
        if num_tus:
            LOG.info("Detected %s translation units", num_tus)
        LOG.debug(
            "Timings: max=%.3e min=%.3e mean=%.3e median=%.3e",
            max(self.timing),
            min(self.timing),
            mean(self.timing),
            median(self.timing),
        )
