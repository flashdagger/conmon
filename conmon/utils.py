#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import re
import shlex
import sys
import time
from configparser import ConfigParser
from contextlib import suppress
from inspect import stack, FrameInfo
from io import TextIOBase
from math import log
from pathlib import Path
from queue import Queue, Empty
from select import select
from threading import Thread
from typing import (
    Hashable,
    Any,
    Dict,
    Set,
    List,
    Iterable,
    TypeVar,
    Iterator,
    Tuple,
    Optional,
    Union,
    IO,
)

import colorama
from psutil import Popen

T = TypeVar("T", bound=Hashable)


class StopWatch:
    INSTANCES: Dict[FrameInfo, "StopWatch"] = {}

    def __init__(self):
        self._last_ts = time.time()

    @classmethod
    def at_location(cls) -> "StopWatch":
        frame = stack(context=0)[1]
        if frame not in cls.INSTANCES:
            cls.INSTANCES[frame] = cls()
        return cls.INSTANCES[frame]

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self._last_ts

    def timespan_elapsed(self, timespan_s: float) -> bool:
        if self.elapsed_seconds >= timespan_s:
            self._last_ts = time.time() - self.elapsed_seconds % timespan_s
            return True

        return False

    def reset(self):
        self._last_ts = time.time()


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


class StrictConfigParser(ConfigParser):
    OPTCRE = re.compile(
        # allow only = or : for option separator
        r"(?P<option>[^=\n\s]+)\s*"
        r"(?P<vi>[=:]\s*)"
        r"(?P<value>.*)"
    )

    def optionxform(self, optionstr):
        return optionstr


def get_terminal_width():
    try:
        return os.get_terminal_size()[0]
    except OSError:
        return None


class ScreenWriter:
    CLEAR_LINE = colorama.ansi.clear_line(2)
    RESET_LINE = "\r" if os.name == "nt" else colorama.ansi.CSI + "1G"

    def __init__(self):
        self._last_line = ""
        self.skip_overwrite = not sys.stdout.isatty()

    @staticmethod
    def fit_width(line: str):
        size = len(line)
        columns = get_terminal_width() or size + 1
        return line[: min(size, columns - 1)]

    def reset(self):
        if self._last_line:
            print(self.CLEAR_LINE + self.RESET_LINE, end="")
            self._last_line = ""

    def print(self, line: str, overwrite=False, indent=-1):
        if overwrite and self.skip_overwrite:
            self._last_line = line
            return

        append = indent >= 0
        spaces = " " * max(0, indent - len(self._last_line)) if append else ""

        if overwrite:
            line = self.fit_width(line)

        if self._last_line and not append:
            printed_line = self.CLEAR_LINE + self.RESET_LINE + line
        elif self.skip_overwrite:
            printed_line = self._last_line + spaces + line
        else:
            printed_line = spaces + line

        if overwrite:
            self._last_line = line
            print(printed_line, end="")
            sys.stdout.flush()
        else:
            self._last_line = ""
            print(printed_line)


class AsyncPipeReader:
    def __init__(self, pipe: IO):
        self.queue: Queue[str] = Queue()
        self.thread = Thread(target=self.reader, args=[pipe, self.queue])
        self.thread.start()

    @staticmethod
    def reader(pipe: TextIOBase, queue: Queue) -> None:
        with suppress(ValueError):
            for line in iter(pipe.readline, ""):
                queue.put(line)
        queue.put("")

    @property
    def exhausted(self) -> bool:
        return self.queue.empty() and not self.thread.is_alive()

    @property
    def not_empty(self) -> bool:
        return not self.queue.empty()

    def readlines(
        self, block_all=False, block_first=False, timeout=None
    ) -> Iterator[str]:
        if self.exhausted:
            return

        if block_first:
            try:
                line = self.queue.get(block=True, timeout=timeout)
            except Empty:
                return

            if line:
                yield line

        while block_all or not self.queue.empty():
            try:
                line = self.queue.get(block=block_all, timeout=timeout)
            except Empty:
                return

            if not line:
                break
            yield line

    def readline(self) -> str:
        return self.queue.get(block=True)


class ProcessStreamHandler:
    def __init__(self, proc: Popen):
        assert proc.stdout and proc.stderr, "stdout and stderr must be set"
        self.stdout = AsyncPipeReader(proc.stdout)
        self.stderr = AsyncPipeReader(proc.stderr)
        self.select = (
            lambda: select([proc.stdout, proc.stderr], [], [])
            if os.name == "posix"
            else lambda: None
        )

    @property
    def exhausted(self) -> bool:
        return self.stdout.exhausted and self.stderr.exhausted

    def readboth(self) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        stdout_lines = tuple(self.stdout.readlines(block_first=True))
        stderr_lines = tuple(self.stderr.readlines())
        return stdout_lines, stderr_lines

    def readmerged(self) -> Tuple[str, ...]:
        while not self.exhausted:
            stdout_lines = tuple(self.stdout.readlines())
            stderr_lines = tuple(self.stderr.readlines())
            if stderr_lines or stdout_lines:
                return stdout_lines + stderr_lines
            self.select()
        return ()


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


def shorten(
    string: str, width: int, *, template="{}", strip="right", placeholder="[...]"
):
    assert strip in {"left", "right", "middle"}
    full_text = template.format(string)
    diff_size = width - len(full_text)
    if diff_size >= 0 or width < 0:
        return full_text
    diff_size -= len(placeholder)
    if strip == "right":
        stripped_string = f"{string[:diff_size]}{placeholder}"
    elif strip == "middle":
        diff_size += len(string)
        div, res = divmod(diff_size, 2)
        stripped_string = (
            f"{string[:div+res]}{placeholder}{string[len(string)-div:]}"
            if diff_size > 0
            else placeholder
        )
    else:
        stripped_string = f"{placeholder}{string[-diff_size:]}"

    return template.format(stripped_string)


def shorten_per_line(
    string: str, width: int, *, strip="right", placeholder="[...]", keep_first=False
):
    return "".join(
        line
        if idx == 0 and keep_first
        else shorten(line, width=width, strip=strip, placeholder=placeholder)
        for idx, line in enumerate(string.splitlines(keepends=True))
    )


def added_first(container: Set, item: Hashable) -> bool:
    if item in container:
        return False
    container.add(item)
    return True


def unique(items: Iterable[T]) -> Iterator[T]:
    seen: Set[Hashable] = set()
    for item in items:
        if added_first(seen, freeze_json_object(item)):
            yield item


def common_parent(*paths: Union[str, os.PathLike]) -> Optional[Path]:
    def iter_parts(_path):
        ppath = Path(_path)
        yield from reversed(ppath.parents)
        yield ppath

    last_parent = None
    for parents in zip(*(iter_parts(path) for path in paths)):
        p_set = set(parents)
        if len(p_set) > 1:
            return last_parent
        last_parent = p_set.pop()

    return last_parent


def human_readable_size(
    size: Union[int, float], unit: str, factor=1000, min_precision: int = 0
) -> str:
    assert min_precision >= 0
    si_map = {-2: "\u03bc", -1: "m", 0: "", 1: "k", 2: "M", 3: "G", 4: "T"}

    try:
        index = int(log(abs(size)) / log(factor)) - (1 if abs(size) < 1.0 else 0)
    except ValueError:
        index = 0

    index = max(min(index, max(si_map)), min(si_map))
    sized = size / factor**index

    if sized <= 100:
        min_precision += 2
    elif sized <= 10:
        min_precision += 1

    if index == 0:
        if isinstance(size, int):
            min_precision = 0
    else:
        unit = unit[0]

    return f"{sized:.{min_precision}f} {si_map[index]}{unit}"


def human_readable_byte_size(size: int) -> str:
    return human_readable_size(size, "Bytes", factor=1024)
