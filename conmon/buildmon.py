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
from typing import Any, Dict, List, Optional, Set, Hashable

import psutil  # type: ignore

LOG = logging.getLogger("BUILDMON")


class MappingPair(tuple):
    pass


def freeze_json_object(obj) -> Hashable:
    if isinstance(obj, set):
        return tuple((freeze_json_object(value) for value in sorted(obj)))
    if isinstance(obj, (list, tuple)):
        return tuple(freeze_json_object(value) for value in obj)
    if isinstance(obj, dict):
        return MappingPair(
            (key, freeze_json_object(value)) for key, value in obj.items()
        )
    assert isinstance(obj, Hashable), type(obj)
    return obj


def unfreeze_json_object(obj: Hashable) -> Any:
    if isinstance(obj, tuple) and not isinstance(obj, MappingPair):
        return [unfreeze_json_object(item) for item in obj]
    if isinstance(obj, MappingPair):
        return {key: unfreeze_json_object(value) for key, value in obj}
    return obj


def append_to_set(
    obj: Dict[str, Any], mapping: Dict[Hashable, Any], value_key: str
) -> None:
    keyitem = obj.pop(value_key)
    frozen_obj = freeze_json_object(obj)
    if isinstance(keyitem, list):
        mapping.setdefault(frozen_obj, []).extend(keyitem)
    elif isinstance(keyitem, set):
        mapping.setdefault(frozen_obj, set()).update(keyitem)
    else:
        raise ValueError("keyitem must be list() or set()")


def merge_mapping(mapping: Dict[Hashable, Set], value_key: str) -> List[Dict[str, Any]]:
    def sort_if_set(_value):
        if isinstance(_value, set):
            return list(sorted(_value))
        return _value

    return [
        {**unfreeze_json_object(key), **{value_key: sort_if_set(value)}}
        for key, value in mapping.items()
    ]


class WinShlex(shlex.shlex):
    """class for splitting VS cl.exe response file commands"""

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
    IGNORE_FLAGS_SHORT = {"-s", "-TP", "-TC", "-FS"}

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

        clean_args = []
        unknown_args = []
        for arg in args:
            if arg in self.IGNORE_FLAGS_SHORT:
                continue
            for option in options:
                if not arg.lower().startswith(option):
                    continue
                prefix, rest = arg[: len(option)], arg[len(option) :]
                if prefix in self.IGNORE_FLAGS_LONG:
                    break
                if rest.startswith("-"):
                    unknown_args.append(arg)
                    break
                assert prefix.lower() == option
                if rest:
                    clean_args.extend((prefix, rest))
                else:
                    clean_args.append(arg)
                break
            else:
                clean_args.append(arg)

        return clean_args, unknown_args

    def parse_known_args(self, args=None, namespace=None):
        clean_args, unknown_args = self.cleanup_args(args)
        args, _unknown_args = super().parse_known_args(
            args=clean_args, namespace=namespace
        )
        unknown_args.extend(_unknown_args)
        return args, unknown_args


def identify_compiler(name: str) -> Optional[str]:
    parts = set(name.replace("+", "").replace(".exe", "").split("-"))
    if "cl" in parts:
        return "msvc"

    if parts & {"gcc", "g", "cc", "c", "clang"}:
        return "gnu"

    return None


class BuildMonitor(Thread):
    PARSER = CompilerParser(prog=Path(__file__).stem)
    ERRORS: Set[str] = set()

    def __init__(self, proc: psutil.Process):
        super().__init__(daemon=True)
        self.proc = proc
        self.proc_cache: Dict = {}
        self.rsp_cache: Dict = {}
        self._translation_units: Dict[Hashable, Set] = {}
        self.finish = Event()
        self.timing: List[float] = []

    @property
    def translation_units(self):
        return merge_mapping(self._translation_units, value_key="sources")

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
            LOG.error("Unknown compiler type %s", compiler_type)
            return

        self.parse_tus(process_map)

    def parse_tus(self, proc: Dict) -> None:
        args, unknown_args = self.PARSER.parse_known_args(proc["cmdline"])

        if args.cc_frontend:
            return

        if not args.compile_not_link:
            return

        data = dict(compiler=proc["exe"])
        data["flags"] = {
            first
            for first, second in zip(unknown_args, unknown_args[1:])
            if re.match(r"^-[-\w=]+$", first) and second.startswith("-")
        }
        for key, value in sorted(vars(args).items()):
            if not value:
                continue
            if key in {"includes", "system_includes"}:
                data[key] = {self.make_absolute(path, proc["cwd"]) for path in value}
            elif key not in {"cc_frontend", "compile_not_link"}:
                data[key] = set(value) if isinstance(value, list) else value

        for file in reversed(unknown_args):
            if file.startswith("-"):
                continue
            abs_file = self.make_absolute(file, proc["cwd"])
            if self.is_valid_tu(abs_file):
                data.setdefault("sources", set()).add(abs_file)

        if not data.get("sources"):
            return

        append_to_set(data, self._translation_units, value_key="sources")

    def scan(self) -> None:
        t_start = time.monotonic()
        try:
            children = self.proc.children(recursive=True)
        except psutil.NoSuchProcess as exc:
            LOG.error(str(exc))
            return
        for child in children:
            child_id = hash(child)
            with suppress(psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
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
            try:
                self.check_process(info_map)
            except BaseException as exc:
                errmsg = repr(exc)
                if errmsg not in self.ERRORS:
                    self.ERRORS.add(errmsg)
                    LOG.error(errmsg)

        translation_units = self.translation_units
        num_tus = sum(len(unit["sources"]) for unit in translation_units)
        if num_tus:
            LOG.info(
                "Detected %s translation units in %s sets",
                num_tus,
                len(translation_units),
            )
        LOG.debug(
            "Timings: max=%.3e min=%.3e mean=%.3e median=%.3e",
            max(self.timing),
            min(self.timing),
            mean(self.timing),
            median(self.timing),
        )
