import os
import re
import shlex
import sys
import time
from configparser import ConfigParser
from contextlib import suppress
from queue import Queue
from threading import Thread
from typing import Hashable, Any, Dict, Set, List

import colorama


class StopWatch:
    def __init__(self):
        self._last_ts = time.time()

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


class ScreenWriter:
    CLEAR_LINE = colorama.ansi.clear_line(2)
    RESET_LINE = "\r" if os.name == "nt" else colorama.ansi.CSI + "1G"

    def __init__(self):
        self._last_line = ""

    def reset(self):
        self._last_line = ""

    @staticmethod
    def fit_width(line: str):
        size = columns = len(line)
        with suppress(OSError):
            (columns, _lines), _ = os.get_terminal_size(), columns
        return line[: min(size, columns - 1)]

    def print(self, line: str, overwrite=False, indent=-1):
        append = indent >= 0
        spaces = " " * max(0, indent - len(self._last_line)) if append else ""
        if overwrite:
            line = self.fit_width(line)

        if self._last_line and not append:
            printed_line = self.CLEAR_LINE + self.RESET_LINE + line
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
    def __init__(self, pipe):
        self.pipe = pipe
        self.queue = Queue()
        self.thread = Thread(target=self.reader, args=[self.pipe, self.queue])
        self.thread.start()

    @staticmethod
    def reader(pipe, queue):
        with suppress(ValueError):
            for line in iter(pipe.readline, ""):
                queue.put(line)

    def readlines(self):
        while not self.queue.empty():
            yield self.queue.get()


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
    string: str, width: int, *, template="{}", strip_left=False, placeholder="[...]"
):
    full_text = template.format(string)
    diff_size = width - len(full_text)
    if diff_size >= 0:
        return full_text
    diff_size -= len(placeholder)
    stripped_string = (
        f"{placeholder}{string[-diff_size:]}"
        if strip_left
        else f"{string[:diff_size]}{placeholder}"
    )
    return template.format(stripped_string)
