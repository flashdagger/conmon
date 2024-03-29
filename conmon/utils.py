#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import re
import shlex
import sys
import time
from configparser import ConfigParser
from contextlib import suppress
from inspect import FrameInfo, stack
from math import log
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import (
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
    Type,
    TypeVar,
    Union,
)

import colorama
from json_stream.base import StreamingJSONList, StreamingJSONObject

T = TypeVar("T", bound=Hashable)
NoneType = type(None)


class StopWatch:
    INSTANCES: Dict[FrameInfo, "StopWatch"] = {}
    _time = staticmethod(time.monotonic)

    def __init__(self):
        self._last_ts = self._time()

    @classmethod
    def at_location(cls) -> "StopWatch":
        frame = stack(context=0)[1]
        if frame not in cls.INSTANCES:
            cls.INSTANCES[frame] = cls()
        return cls.INSTANCES[frame]

    def elapsed_seconds(self, reset=False) -> float:
        _time = self._time()
        delta = _time - self._last_ts
        if reset:
            self._last_ts = _time
        return delta

    def timespan_elapsed(self, timespan_s: float) -> bool:
        _time = self._time()
        delta = _time - self._last_ts
        if delta >= timespan_s:
            self._last_ts = _time - delta % timespan_s
            return True

        return False

    def reset(self):
        self._last_ts = self._time()


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


class MappingPair(tuple):
    pass


# pylint: disable=consider-using-with
class CachedLines:
    """this class mimics a list of string lines
    supporting append(), extend() and iter()
    Once the data reaches max_size it is swapped to
    disk saving memory consumption
    """

    def __init__(self, max_size=2**12) -> None:
        args = self._args = dict(
            mode="w+", max_size=max_size, buffering=1, encoding="utf-8", newline="\n"
        )
        self._len = 0
        self._positions: Dict[int, int] = {}
        self._fh = SpooledTemporaryFile(**args)

    @property
    def name(self):
        return self._fh.name

    def saveposition(self, obj: Hashable):
        self._positions[hash(obj)] = self._fh.tell()

    def write(self, string: str):
        fh = self._fh
        # fh.seek(0, 2)
        fh.write(string)
        self._len += string.count("\n")

    def extend(self, lines: Iterator[str], end="\n"):
        fh = self._fh
        # fh.seek(0, 2)
        count = 0
        for line in lines:
            fh.write(line + end)
            count += 1
        self._len += count

    def append(self, line: str, end="\n"):
        fh = self._fh
        # fh.seek(0, 2)
        fh.write(line + end)
        self._len += 1

    def read(self, *, marker: Hashable = None):
        fh = self._fh
        position = 0 if marker is None else self._positions[hash(marker)]
        fh.seek(position)
        return fh.read()

    def iterlines(self, marker: Hashable = None):
        fh = self._fh
        position = 0 if marker is None else self._positions[hash(marker)]
        fh.seek(position)
        return iter(fh)

    def size(self, marker: Hashable = None):
        position = 0 if marker is None else self._positions[hash(marker)]
        return self._fh.tell() - position

    def clear(self):
        self._fh = SpooledTemporaryFile(**self._args)
        self._positions.clear()
        self._len = 0

    def __bool__(self):
        return bool(self._len)

    def __len__(self):
        return self._len

    def __iter__(self):
        fh = self._fh
        fh.seek(0)
        return iter(fh)


def freeze_json_object(obj) -> Hashable:
    if isinstance(obj, set):
        return tuple((freeze_json_object(value) for value in sorted(obj)))
    if isinstance(obj, (list, tuple, StreamingJSONList)):
        return tuple(freeze_json_object(value) for value in obj)
    if isinstance(obj, (dict, StreamingJSONObject)):
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


class AnyComparable:
    PRECEDENCE = {
        typ: idx
        for idx, typ in enumerate(
            (
                NoneType,
                bool,
                int,
                float,
                str,
            )[::-1],
            1,
        )
    }

    __slots__ = ["obj"]

    def __init__(self, obj):
        self.obj = obj

    def precedence(self, typ: Type) -> str:
        rank = self.PRECEDENCE.get(typ, 0)
        return rank * "_" + typ.__name__.lower()

    def lt_seq(self, seq_a, seq_b):
        for obj_a, obj_b in zip(seq_a, seq_b):
            if self.lt_impl(obj_a, obj_b):
                return True
            if obj_a != obj_b:
                return False
        return len(seq_a) < len(seq_b)

    def lt_impl(self, obj_a, obj_b):
        type_a, type_b = type(obj_a), type(obj_b)
        typeset = {type_a, type_b}
        if typeset not in ({bool, int}, {bool, float}):
            with suppress(TypeError):
                return obj_a < obj_b

        if not NoneType in typeset:
            with suppress(TypeError):
                return self.lt_seq(obj_a, obj_b)

        return self.precedence(type_a) < self.precedence(type_b)

    def __lt__(self, other: "AnyComparable") -> bool:
        return self.lt_impl(self.obj, other.obj)


def orderkeys(mapping: Mapping, *keys: Hashable) -> Mapping:
    """returns a sorted dict according to order in keys
    other keys order are left untouched

    example:
    dict(a=0, b=0, x=0, y=0) == orderkeys(dict(x=0, b=0, y=0, a=0), 'a', 'b')
    """
    # optimize for already ordered mappings
    # mkeys = tuple(islice(mapping.keys(), len(keys)))
    # if mkeys == keys:
    #     return mapping

    omap: Dict = {}
    for key in keys:
        if key in mapping:
            omap[key] = None

    omap.update(mapping)
    return omap


def sorted_mappings(
    items: Iterable[Mapping], *, keys: Sequence, reorder_keys=False, reverse=False
) -> List[Mapping]:
    def mappingkey(mapping: Mapping):
        return AnyComparable(tuple(mapping.get(key) for key in keys))

    if reorder_keys:
        items = (orderkeys(item, *keys) for item in items)

    return sorted(items, key=mappingkey, reverse=reverse)
