import re
import shlex
import sys
import time
from configparser import ConfigParser
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
    def __init__(self):
        self._last_line = ""

    def reset(self):
        self._last_line = ""

    def print(self, line: str, overwrite=False, indent=-1):
        append = indent >= 0
        spaces = " " * max(0, indent - len(self._last_line)) if append else ""

        if self._last_line and not append:
            printed_line = "\r" + colorama.ansi.clear_line(2) + line
        else:
            printed_line = spaces + line

        if overwrite:
            self._last_line = line
            print(printed_line, end="")
            sys.stdout.flush()
        else:
            self._last_line = ""
            print(printed_line)


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
