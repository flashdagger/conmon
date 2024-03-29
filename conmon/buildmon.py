#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import argparse
import os.path as os_path
import re
import shlex
import time
from contextlib import suppress
from functools import partial
from pathlib import Path
from statistics import mean, median
from threading import Event, Thread
from typing import Any, Dict, Hashable, Iterator, List, Optional, Sequence, Set, Tuple

from psutil import AccessDenied, NoSuchProcess, Process

from .logging import UniqueLogger, get_logger
from .shell import Command
from .utils import (
    WinShlex,
    append_to_set,
    freeze_json_object,
    human_readable_byte_size,
    human_readable_size,
    merge_mapping,
    shorten,
    unfreeze_json_object,
)

LOG = get_logger("PROC")
LOG_ONCE = UniqueLogger(LOG)


class ScanPS(Command):
    LOG = get_logger("MSYSPS")
    LOG_ONCE = UniqueLogger(LOG)

    def __init__(self):
        super().__init__()
        self.ps_exe = None

    def __bool__(self):
        return self.ps_exe is not None

    def setps(self, path: Path):
        if path.is_dir():
            path = path / "ps.exe"
        assert path.is_file()
        self.ps_exe = path

    def receive(self, timeout):
        if not (self.is_running() or self.returned_error):
            assert self.ps_exe, "ps.exe is not set"
            self.run([self.ps_exe])
        return self.streams.assert_stdout(timeout=timeout)

    def add_msys_procs(self, children: Set[Process]) -> None:
        if self.returned_error:
            self.LOG_ONCE.warning("Returned error %s", self.returncode)
            return
        try:
            output = self.receive(timeout=0.1)
            if not output:
                return
            for parent, procs in self.scan_msys(output).items():
                if parent in children:
                    children.update(procs)
        except RuntimeError as exc:
            self.LOG.error("%s: %s", self.__class__.__name__, exc)

    @staticmethod
    def scan_msys(ps_lines: Sequence[str]):
        procs: Dict[Process, Set[Process]] = {}
        # mapping pid -> ppid, winpid
        ppid_map: Dict[int, Tuple[int, int]] = {}

        def root_process(child_pid: int) -> Process:
            parent_pid, win_pid = ppid_map[child_pid]
            if parent_pid == 1:
                return Process(win_pid)
            return root_process(parent_pid)

        for info in ScanPS.parse_ps(ps_lines):
            if info.get("COMMAND", "/ps").endswith("/ps"):
                continue
            try:
                ppid_map[int(info["PID"])] = int(info["PPID"]), int(info["WINPID"])
            except ValueError:
                ppid_map.clear()

        for pid, (_, winpid) in ppid_map.items():
            with suppress(NoSuchProcess, KeyError):
                root_proc = root_process(pid)
                procs.setdefault(root_proc, set()).add(Process(winpid))

        return procs

    @staticmethod
    def parse_ps(lines: Sequence[str]) -> Iterator[Dict[str, str]]:
        if len(lines) < 2:
            return

        header = lines[0].split()
        for line in lines[1:]:
            if not line.startswith(" "):
                continue
            entries = line.rstrip("\n").split(maxsplit=len(header) - 1)
            yield dict(zip(header, entries))


class CompilerParser(argparse.ArgumentParser):
    IGNORED_FLAGS = {
        "-diagnostics",
        "-nologo",
        "-showIncludes",
        "-c",
        "-s",
        "-TP",
        "-TC",
        "-FS",
    }
    IGNORED_FLAGS_AFTER = {"-link"}
    UNSPLIT_FLAGS = {"-I", "-external:I", "-U", "-D", "-FI", "-Fo", "-Fd"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)
        self.add_argument(
            "-isystem",
            "-external:I",
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
            help="include paths",
            dest="includes",
            action="append",
            default=[],
        )
        self.add_argument(
            "-f",
            help="specifying the output file format (nasm/yasm specific)",
            dest="object_format",
            default=None,
            action="store",
        )
        self.add_argument(
            "-o",
            "-Fo",
            help="specifying the output file",
            dest="output",
            action="store",
        )
        self.add_argument(
            "-D", help="defines", dest="defines", action="append", default=[]
        )
        self.add_argument(
            "-U", help="undefines", dest="undefines", action="append", default=[]
        )
        self.add_argument(
            "-E",
            help="Preprocesses C and C++ source files to stdout",
            dest="preprocess_only",
            action="store_true",
        )
        self.add_argument(
            "-cc1", help="compiler frontend", dest="cc_frontend", action="store_true"
        )
        self.add_argument(
            "-cc1as",
            help="assembly frontend",
            dest="ccas_frontend",
            action="store_true",
        )

    def cleanup_args(self, args: Sequence[str]) -> List[str]:
        options: Set[str] = set()

        for action in self._actions:
            options.update(set(action.option_strings))
            if isinstance(action.default, list):
                action.default.clear()

        options = {option for option in options if not option.startswith("--")}
        sorted_options = tuple(sorted(options, reverse=True, key=len))

        clean_args = []
        for arg in args:
            if arg in self.IGNORED_FLAGS_AFTER:
                break
            if arg in self.IGNORED_FLAGS:
                continue
            for option in sorted_options:
                if arg == option:
                    clean_args.append(arg)
                    break
                if arg.startswith(option):
                    if option in self.UNSPLIT_FLAGS:
                        k = len(option)
                        clean_args.extend((arg[:k], arg[k:]))
                    else:
                        # masquerade option as unknown
                        clean_args.append(f"@{arg}")
                    break
            else:
                clean_args.append(arg)

        return clean_args

    def parse_known_args(self, args=None, namespace=None):
        clean_args = self.cleanup_args(args)
        args, unknown_args = super().parse_known_args(
            args=clean_args, namespace=namespace
        )
        return args, [arg[1:] if arg.startswith("@") else arg for arg in unknown_args]


def identify_compiler(name: str) -> Optional[str]:
    parts = set(name.replace("+", "").split("-"))

    if parts == {"cl"} or parts & {"rc"}:
        return "msvc"

    if parts & {"gcc", "g", "cc", "c", "clang", "nasm", "yasm"}:
        return "gnu"

    return None


# pylint: disable=too-many-instance-attributes
class BuildMonitor(Thread):
    ACTIVE = True
    CYCLE_TIME_S = 0.025
    PARSER = CompilerParser(prog=Path(__file__).stem, add_help=False)

    def __init__(self, pid: Optional[int] = None):
        super().__init__(daemon=True)
        self.proc = Process(pid)
        self.proc_cache: Dict = {}
        self.rsp_cache: Dict = {}
        self.compiler: Set[str] = set()
        self._translation_units: Dict[Hashable, Set] = {}
        self.finish = Event()
        self.timing: List[float] = []
        self.executables: Set[str] = set()
        self.shell = ScanPS()
        self.seen_proc: Set[Process] = set()

    def start(self) -> None:
        if self.is_alive():
            self.stop()

        if not self.proc.is_running():
            LOG.error(self.proc)
            return

        # we abuse init to clear all member variables
        self.__class__.__init__(self, self.proc.pid)

        if not self.ACTIVE:
            return

        super().start()
        LOG.debug("scanning subprocesses of pid %s", self.proc.pid)

    def stop(self):
        self.shell.ps_exe = None
        if not self.is_alive():
            self.finalize()
            return
        self.finish.set()
        self.join()
        self.finalize()

    @property
    def translation_units(self):
        return merge_mapping(self._translation_units, value_key="sources")

    @staticmethod
    def make_absolute(path: str, cwd: str) -> Path:
        if not os_path.isabs(path):
            assert os_path.isabs(cwd), cwd
            path = os_path.join(cwd, path)
        return Path(os_path.abspath(path))

    @staticmethod
    def is_valid_tu(file: Path) -> bool:
        return file.suffix.lower() in {".c", ".cpp", ".cxx", ".cc", ".asm", ".s", ".rc"}

    def cache_responsefile(self, info: Dict):
        for arg in info["cmdline"]:
            if not arg.startswith("@"):
                continue

            response_file = self.make_absolute(arg[1:], info["cwd"])
            if response_file in self.rsp_cache:
                return
            if response_file.exists():
                self.rsp_cache[response_file] = response_file.read_bytes()

    def parse_responsefile(self, cmdline: List[str], *, cwd, posix=True) -> List[str]:
        new_cmdline = []
        for arg in cmdline:
            if not arg.startswith("@"):
                new_cmdline.append(arg)
                continue

            response_file = self.make_absolute(arg[1:], cwd)
            rsp_data = self.rsp_cache.get(response_file)

            if rsp_data is None:
                LOG_ONCE.warning("Missing response file %s", response_file)
                new_cmdline.append(arg)
            else:
                split = (
                    partial(shlex.split, comments=False, posix=True)
                    if posix
                    else partial(WinShlex.split)
                )
                encoding = "utf-16" if set(rsp_data[0:2]) == {0xFE, 0xFF} else "utf-8"
                new_cmdline.extend(split(rsp_data.decode(encoding=encoding)))
                LOG_ONCE.debug(
                    "Read response file %s (encoding=%r, size=%s)",
                    response_file,
                    encoding,
                    human_readable_byte_size(len(rsp_data)),
                )
        return new_cmdline

    def check_process(self, process_map: Dict[str, Any]):
        compiler_type = identify_compiler(process_map["name"])
        self.compiler.add(process_map["name"])
        if (
            compiler_type is None
            or process_map["cwd"] is None
            or not process_map["cmdline"]
        ):
            return

        exe = Path(process_map["cmdline"][0])
        if not exe.is_absolute():
            exe = self.make_absolute(process_map["exe"], process_map["cwd"])
        process_map["exe"] = exe

        if process_map["name"] in {"cl", "clang-cl"}:
            # replace '/' with '-' for windows style args
            convert = partial(re.sub, r"^/(.*)", r"-\1")
            posix = False
        else:
            assert compiler_type is not None
            convert = partial(str)
            posix = True

        process_map["cmdline"] = [
            convert(option)
            for option in self.parse_responsefile(
                process_map["cmdline"],
                cwd=process_map["cwd"],
                posix=posix,
            )
        ]

        self.parse_tus(process_map)

    def parse_tus(self, proc: Dict) -> None:
        args, unknown_args = self.PARSER.parse_known_args(proc["cmdline"])

        if args.cc_frontend or args.ccas_frontend or args.preprocess_only:
            return

        data = dict(compiler=proc["exe"])
        data["flags"] = {
            first
            for first, second in zip(unknown_args[:], unknown_args[1:-1] + ["-"])
            if re.match(r"^-[-\w:=+]+$", first) and second.startswith("-")
        }
        for key, value in sorted(vars(args).items()):
            if not value:
                continue
            if key in ("forced_includes", "system_includes", "includes"):
                data[key] = {self.make_absolute(path, proc["cwd"]) for path in value}
            elif key in {"defines", "undefines", "object_format"}:
                data[key] = set(value) if isinstance(value, list) else value

        for file in reversed(unknown_args):
            if file.startswith("-"):
                continue
            abs_file = self.make_absolute(file, proc["cwd"])
            if self.is_valid_tu(abs_file):
                data.setdefault("sources", set()).add(Path(abs_file))

        if not data.get("sources"):
            return

        append_to_set(data, self._translation_units, value_key="sources")

    def scan(self) -> None:
        try:
            children: Set[Process] = set(self.proc.children(recursive=True))
        except NoSuchProcess as exc:
            LOG_ONCE.error(str(exc))
            return

        if self.shell:
            self.shell.add_msys_procs(children)

        for child in children - self.seen_proc:
            with suppress(NoSuchProcess, AccessDenied, OSError, FileNotFoundError):
                info = child.as_dict(attrs=["exe", "cmdline", "cwd"])
                if not (info["cmdline"] and info["cwd"]):
                    continue

                path = Path(info["exe"])
                name = info["name"] = Path(info["cmdline"][0]).stem.lower()
                if not self.shell and path.name in {
                    "make.exe",
                    "bash.exe",
                    "sh.exe",
                }:
                    self.shell.setps(path.parent)
                    LOG.debug(
                        "scanning processes via MSYS ps because %r was detected.",
                        path.name,
                    )
                elif identify_compiler(name) and info["exe"] == "/bin/dash":
                    LOG.warning(
                        "Async capture: %r",
                        shorten(" ".join(info["cmdline"]), width=60, strip="middle"),
                    )
                    continue
                self.proc_cache[freeze_json_object(info)] = None
                self.cache_responsefile(info)
        self.seen_proc = children

    # noinspection PyBroadException
    def finalize(self):
        for frozen_info in self.proc_cache:
            info_map = self.proc_cache[frozen_info] = unfreeze_json_object(frozen_info)
            name = info_map["name"]
            if not identify_compiler(name):
                self.executables.add(name)
                continue
            try:
                self.check_process(info_map)
            except BaseException:  # pylint: disable=broad-except
                LOG.exception("Exception while processing...")
                continue

        if self.compiler:
            LOG.info("Detected compiler: %s", ", ".join(self.compiler))
        if self.executables:
            LOG.info("Detected executables: %s", ", ".join(sorted(self.executables)))

        if not self.timing:
            return

        hrs = partial(human_readable_size, unit="seconds")
        LOG.debug(
            "Time consumed per process scan: max=%s, min=%s, mean=%s, median=%s",
            hrs(max(self.timing)),
            hrs(min(self.timing)),
            hrs(mean(self.timing)),
            hrs(median(self.timing)),
        )

    def run(self):
        while self.proc.is_running() and not self.finish.is_set():
            t_start = time.monotonic()
            self.scan()
            t_diff = time.monotonic() - t_start
            if t_diff:
                self.timing.append(t_diff)
            sleep_time_s = self.CYCLE_TIME_S - t_diff
            if sleep_time_s > 0.0:
                time.sleep(sleep_time_s)
