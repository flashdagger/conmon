#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import re
import shlex
import sys
import time
from configparser import ConfigParser
from contextlib import suppress
from functools import cmp_to_key
from inspect import FrameInfo, stack
from io import TextIOBase
from math import log
from pathlib import Path
from queue import Empty, Queue
from tempfile import SpooledTemporaryFile
from threading import Thread
from typing import (
    IO,
    Any,
    Dict,
    Hashable,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
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
    CLEAR_LINE = colorama.ansi.clear_line(0)
    NOT_A_TTY = not sys.stdout.isatty()

    def __init__(self):
        self._last_line = ""

    def ansi_cursor(self, show=True):
        if self.NOT_A_TTY:
            return
        code = "h" if show else "l"
        sys.stdout.write(f"{colorama.ansi.CSI}?25{code}")

    @staticmethod
    def fit_width(line: str):
        size = len(line)
        columns = get_terminal_width() or size + 1
        return line[: min(size, columns - 1)]

    def reset(self):
        self.ansi_cursor(show=True)
        if self._last_line:
            print(self.CLEAR_LINE, end="\r", flush=True)
            self._last_line = ""

    def print(self, line: str = "", overwrite=False, indent=-1):
        if overwrite and self.NOT_A_TTY:
            self._last_line = line
            return

        last_line = self._last_line
        if indent >= 0:
            spaces = max(0, indent - len(last_line)) * " "
            line = last_line + spaces + line

        if overwrite:
            if not last_line:
                self.ansi_cursor(show=False)
            line = self.fit_width(line)
            self._last_line = line
            print(self.CLEAR_LINE + line, end="\r", flush=True)
        else:
            if last_line:
                self.ansi_cursor(show=True)
                self._last_line = ""
            print(self.CLEAR_LINE + line)

    def __del__(self):
        self.ansi_cursor(show=True)


class AsyncPipeReader:
    def __init__(self, pipe: Optional[IO]):
        self.queue: Queue[str] = Queue()
        self.thread = Thread(target=self.reader, args=[pipe, self.queue])
        self.thread.start()

    @staticmethod
    def reader(pipe: TextIOBase, queue: Queue) -> None:
        with suppress(ValueError, AttributeError):
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
    def __init__(self, proc: Optional[Popen] = None):
        self.stdout: AsyncPipeReader = proc and AsyncPipeReader(proc.stdout)  # type: ignore
        self.stderr: AsyncPipeReader = proc and AsyncPipeReader(proc.stderr)  # type: ignore

    @property
    def exhausted(self) -> bool:
        return self.stdout.exhausted and self.stderr.exhausted

    def readboth(self, timeout=None) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        stdout_lines = tuple(
            self.stdout.readlines(block_first=timeout is not None, timeout=timeout)
        )
        stderr_lines = tuple(self.stderr.readlines())
        return stdout_lines, stderr_lines


class MappingPair(tuple):
    pass


class NullList(list):
    def __init__(self, _iterable=None):
        super().__init__()

    def _ignore(self, *args):
        """this method takes no action"""

    def __add__(self, other):
        return self

    __iadd__ = __add__
    append = _ignore
    extend = _ignore
    insert = _ignore


# pylint: disable=consider-using-with
class CachedLines:
    def __init__(self, max_size=2**12):
        args = self._args = dict(
            mode="w+", max_size=max_size, buffering=1, encoding="utf-8", newline="\n"
        )
        self._fh = SpooledTemporaryFile(**args)

    @property
    def name(self):
        return self._fh.name

    def writelines(self, *lines, end="\n"):
        fh = self._fh
        fh.seek(0, 2)
        fh.writelines(line + end for line in lines)

    def append(self, line, end="\n"):
        fh = self._fh
        fh.seek(0, 2)
        fh.write(line + end)

    def read(self):
        fh = self._fh
        fh.seek(0)
        return fh.read()

    def readlines(self, keepends=True):
        fh = self._fh
        fh.seek(0)
        if not keepends:
            return [line[:-1] for line in fh.readlines()]
        return fh.readlines()

    def clear(self):
        self._fh = SpooledTemporaryFile(**self._args)

    def __iter__(self):
        fh = self._fh
        fh.seek(0)
        return iter(fh)

    def __del__(self):
        fh = self._fh
        print("SpooledFile", "name:", fh.name, "size:", fh.tell())


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
    full_text = template.format(string)
    diff_size = width - len(full_text)
    if diff_size >= 0 or width < 0:
        return full_text
    diff_size -= len(placeholder)

    if strip == "left":
        stripped_string = f"{placeholder}{string[-diff_size:]}"
    elif strip == "right":
        stripped_string = f"{string[:diff_size]}{placeholder}"
    elif strip == "middle":
        diff_size += len(string)
        div, res = divmod(diff_size, 2)
        stripped_string = (
            f"{string[:div+res]}{placeholder}{string[len(string)-div:]}"
            if diff_size > 0
            else placeholder
        )
    elif strip == "outer":
        diff_size = len(placeholder) - diff_size
        div, res = divmod(diff_size, 2)
        stripped_string = (
            f"{placeholder}{string[div+res:-div]}{placeholder}"
            if diff_size < len(string)
            else placeholder
        )
    else:
        raise ValueError(f"strip={strip!r} is not supported")

    return template.format(stripped_string)


def shorten_per_line(
    string: str,
    width: int,
    *,
    strip="right",
    placeholder="[...]",
    indent="",
    keep_first=False,
):
    lines = [
        line
        if idx == 0 and keep_first
        else shorten(
            line,
            width=width,
            strip=strip,
            placeholder=placeholder,
            template="{}" if idx == 0 else f"{indent}{{}}",
        )
        for idx, line in enumerate(string.splitlines(keepends=True))
    ]

    return "".join(lines)


def shorten_lines(text: str, maxlines: int) -> str:
    total_lines = text.count("\n") + 1
    offset = 0
    with suppress(ValueError):
        for _ in range(maxlines):
            offset = text.index("\n", offset) + 1
        return f"{text[:offset]}\n[ {total_lines-maxlines} more line(s) ]\n"
    return text


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


def _compare_everything(obj, other):
    if obj == other:
        return 0

    if all(
        isinstance(item, Sequence) and not isinstance(item, str)
        for item in (obj, other)
    ):
        for _obj, _other in zip(obj, other):
            ret = _compare_everything(_obj, _other)
            if ret != 0:
                return ret
        return min(1, max(len(obj) - len(other), -1))

    with suppress(TypeError):
        if other is None or obj < other:
            return -1
    with suppress(TypeError):
        if obj is None or obj > other:
            return 1
    return -1 if str(obj) < str(other) else 1


# pylint: disable=invalid-name
compare_everything = cmp_to_key(_compare_everything)


def sorted_dicts(
    items: Iterable[Mapping], *, keys: Sequence, reorder_keys=False, reverse=False
):
    assert len(set(keys)) == len(keys), "keys must be unique"

    def reorder(mapping: Mapping) -> Mapping:
        new_mapping = {}
        for key in keys:
            if key not in mapping:
                continue
            new_mapping[key] = mapping[key]
        for key in mapping.keys():
            if key in new_mapping:
                continue
            new_mapping[key] = mapping[key]
        return new_mapping

    def transform(mapping: Mapping):
        sortable_keys = (mapping.get(key) for key in keys)
        return tuple((*sortable_keys, reorder(mapping) if reorder_keys else mapping))

    for item in sorted(
        (transform(item) for item in items), key=compare_everything, reverse=reverse
    ):
        yield item[-1]
