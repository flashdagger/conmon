import argparse
import re
import shlex
import time
from contextlib import suppress
from functools import partial
from pathlib import Path
from statistics import mean, median
from subprocess import check_output, CalledProcessError
from threading import Event, Thread
from typing import Any, Dict, List, Optional, Set, Hashable, Iterator, Union, Tuple

from psutil import AccessDenied, Process, NoSuchProcess

from conmon.utils import (
    append_to_set,
    merge_mapping,
    WinShlex,
    human_readable_size,
    human_readable_byte_size,
)
from .logging import get_logger, UniqueLogger
from .utils import shorten

LOG = get_logger("PROC")
LOG_ONCE = UniqueLogger(LOG)


def parse_ps(output: str) -> Iterator[Dict[str, str]]:
    lines = output.splitlines(keepends=False)
    header = lines[0].split()

    for line in lines[1:]:
        if not line.startswith(" "):
            continue
        entries = line.split(maxsplit=len(header) - 1)
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
    IGNORED_FLAGS_AFTER = {
        "-link",
    }

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
            help="include paths",
            dest="includes",
            action="append",
            default=[],
        )
        self.add_argument(
            "-f",
            help="specifying the output file format (nasm specific)",
            dest="nasm_output",
            default=None,
            action="store",
        )
        self.add_argument(
            "-D", help="defines", dest="defines", action="append", default=[]
        )
        self.add_argument(
            "-U", help="undefines", dest="undefines", action="append", default=[]
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

    def cleanup_args(self, args):
        options: Set[str] = set()

        for action in self._actions:
            options.update(set(action.option_strings))
            if isinstance(action.default, list):
                action.default.clear()

        options = {option for option in options if not option.startswith("--")}
        sorted_options = tuple(sorted(options, reverse=True, key=len))

        clean_args = []
        unknown_args = []
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
                    if option[1].isupper():
                        k = len(option)
                        clean_args.extend((arg[:k], arg[k:]))
                    else:
                        unknown_args.append(arg)
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
    parts = set(name.replace("+", "").split("-"))

    if parts == {"cl"}:
        return "msvc"

    if parts & {"gcc", "g", "cc", "c", "clang", "nasm"}:
        return "gnu"

    return None


# pylint: disable=too-many-instance-attributes
class BuildMonitor(Thread):
    CYCLE_TIME_S = 0.025
    PARSER = CompilerParser(prog=Path(__file__).stem, add_help=False)

    def __init__(self, proc: Process):
        super().__init__(daemon=True)
        self.proc = proc
        self.proc_cache: Dict = {}
        self.rsp_cache: Dict = {}
        self.compiler: Set[str] = set()
        self._translation_units: Dict[Hashable, Set] = {}
        self.finish = Event()
        self.timing: List[float] = []
        self.executables: Set[str] = set()
        self.msys_bin: Union[None, bool, Path] = None

    @property
    def translation_units(self):
        return merge_mapping(self._translation_units, value_key="sources")

    @staticmethod
    def make_absolute(path: str, cwd: str) -> Path:
        ppath = Path(path)
        if not ppath.is_absolute():
            ppath = Path(cwd, path).absolute()
        try:
            return ppath.resolve()
        except OSError:
            return ppath

    @staticmethod
    def is_valid_tu(file: Path) -> bool:
        return file.suffix.lower() in {".c", ".cpp", ".cxx", ".cc", ".asm", ".s"}

    def cache_responsefile(self, info: Dict):
        for arg in info["cmdline"]:
            if not arg.startswith("@"):
                continue

            response_file = self.make_absolute(arg[1:], info["cwd"])
            if response_file.exists():
                self.rsp_cache[response_file] = response_file.read_bytes()

    def parse_responsefile(self, cmdline: List[str], *, cwd, posix=True) -> List[str]:
        new_cmdline = []
        for arg in cmdline:
            if not arg.startswith("@"):
                new_cmdline.append(arg)
                continue

            response_file = self.make_absolute(arg[1:], cwd)
            rspf_data = self.rsp_cache.get(response_file)

            if rspf_data is None:
                LOG.warning("Missing response file %s", response_file)
                new_cmdline.append(arg)
            else:
                split = shlex.split if posix else WinShlex.split
                encoding = "utf-16" if set(rspf_data[0:2]) == {0xFE, 0xFF} else "utf-8"
                new_cmdline.extend(split(rspf_data.decode(encoding=encoding)))
                LOG.debug(
                    "Read response file %s (encoding=%r, size=%s)",
                    response_file,
                    encoding,
                    human_readable_byte_size(len(rspf_data)),
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
            convert = str
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

        if args.cc_frontend or args.ccas_frontend:
            return

        data = dict(compiler=proc["exe"])
        data["flags"] = {
            first
            for first, second in zip(unknown_args, unknown_args[1:])
            if re.match(r"^-[-\w:=]+$", first) and second.startswith("-")
        }
        for key, value in sorted(vars(args).items()):
            if not value:
                continue
            if key in ("forced_includes", "system_includes", "includes"):
                data[key] = {self.make_absolute(path, proc["cwd"]) for path in value}
            elif key not in {"cc_frontend", "ccas_frontend"}:
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

        for parent, procs in self.scan_msys().items():
            if parent in children:
                children.update(procs)

        for child in children:
            child_id = hash(child)
            with suppress(NoSuchProcess, AccessDenied, OSError, FileNotFoundError):
                info = child.as_dict(attrs=["exe", "cmdline", "cwd"])
                if not (info["cmdline"] and info["cwd"]):
                    continue

                path = Path(info["cmdline"][0])
                if (
                    path.name.lower() in {"bash.exe", "sh.exe"}
                    and self.msys_bin is not False
                ):
                    if self.msys_bin is None:
                        LOG.debug("Detected %s on Windows", path.stem)
                    self.msys_bin = path.parent
                name = info["name"] = path.stem.lower()
                if not identify_compiler(name):
                    self.executables.add(name)
                    continue

                if info["exe"] == "/bin/dash":
                    LOG.warning(
                        "Async capture (%r)",
                        shorten(" ".join(info["cmdline"]), width=60, strip="middle"),
                    )
                    continue
                self.proc_cache[child_id] = info
                self.cache_responsefile(info)

    # noinspection PyBroadException
    def run(self):
        while self.proc.is_running() and not self.finish.is_set():
            t_start = time.monotonic()
            self.scan()
            t_end = time.monotonic()
            self.timing.append(t_end - t_start)
            sleep_time_s = self.CYCLE_TIME_S - (t_end - t_start)
            if sleep_time_s > 0.0:
                time.sleep(sleep_time_s)

        for info_map in self.proc_cache.values():
            try:
                self.check_process(info_map)
            except BaseException:
                LOG.exception("Exception while processing...")
                continue

        if self.compiler:
            LOG.info("Detected compiler: %s", ", ".join(self.compiler))
        if self.executables:
            LOG.info("Detected executables: %s", ", ".join(sorted(self.executables)))

        hrs = partial(human_readable_size, unit="seconds")
        LOG.debug(
            "Time consumed per process scan: max=%s, min=%s, mean=%s, median=%s",
            hrs(max(self.timing)),
            hrs(min(self.timing)),
            hrs(mean(self.timing)),
            hrs(median(self.timing)),
        )

    def scan_msys(self):
        procs: Dict[Process, Set[Process]] = {}
        if not isinstance(self.msys_bin, Path):
            return procs

        ps_path = self.msys_bin / "ps.exe"
        if not ps_path.is_file():
            LOG.warning("Cannot execute ps.exe to scan for MSYS executables.")
            self.msys_bin = False
            return procs

        try:
            output = check_output([str(ps_path)], encoding="utf8")
        except CalledProcessError as exc:
            LOG.error("call to ps.exe failed (%s)", exc.returncode)
            self.msys_bin = False
            return procs

        # mapping pid -> ppid, winpid
        ppid_map: Dict[int, Tuple[int, int]] = {}

        def root_process(child_pid: int) -> Process:
            parent_pid, win_pid = ppid_map[child_pid]
            if parent_pid == 1:
                return Process(win_pid)
            return root_process(parent_pid)

        for info in parse_ps(output):
            if info["COMMAND"].endswith("/ps"):
                continue
            ppid_map[int(info["PID"])] = int(info["PPID"]), int(info["WINPID"])

        for pid, (_, winpid) in ppid_map.items():
            with suppress(NoSuchProcess, KeyError):
                root_proc = root_process(pid)
                procs.setdefault(root_proc, set()).add(Process(winpid))

        return procs
