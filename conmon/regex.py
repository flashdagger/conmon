#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from collections import deque
from typing import Dict, List, Match, Optional, Pattern, Tuple, Union, Set, Deque

from .conan import storage_path


class Regex:
    @classmethod
    def get(cls, key: str) -> Pattern:
        key = key.replace("-", "_").upper()
        return getattr(cls, key)

    @classmethod
    def dict(cls, *keys: str) -> Dict[str, Pattern]:
        if not keys:
            keys = tuple(
                key.lower().replace("_", "-") for key in dir(cls) if key.isupper()
            )
        return {key: cls.get(key) for key in keys}


DECOLORIZE_REGEX = re.compile(r"\x1B\[([\d;]*m|K)", re.UNICODE)
CONAN_DATA_PATH = re.compile(
    r"""(?x)
        (?P<path>
            ([a-zA-Z]:)?
            (?P<sep>[\\/])
            (?:[\w\-.]+(?P=sep)){5,}  # conservative choice of characters in path names
            (?:
                (?:build|package)(?P=sep)[a-f0-9]{40}
                | source
            )
            (?P=sep)
        )
    """
)
REF_PART_PATTERN = r"\w[\w.+-]{1,50}"
REF_REGEX = re.compile(
    rf"""(?x)
    (?P<ref>
        (?P<name>{REF_PART_PATTERN})/
        (?P<version>{REF_PART_PATTERN})
        (?:
            @
            (?:
                (?P<user>{REF_PART_PATTERN})/
                (?P<channel>{REF_PART_PATTERN})
            )?
         )?
     )
    """
)
CMAKE_BUILD_PATH_REGEX = re.compile(
    r"""(?x)
        (^|/)
        (
          cmake-[23]\.\d{2}/
          | cmake/test_[a-z]+\.c(pp)?$  # from Poco
          | CMake/CurlTests\.c
          | CMakeFiles/
            (
              [23](\.\d+){1,2}/
              | CMakeScratch/
              | ShowIncludes/
              | CMakeTmp/
              | [\w/-]+\.c(c|pp|xx)?$
              # | Check[a-zA-Z]+
            )
        )
    """
)
FILEPATH = re.compile(
    r"""(?x)
        ^(?:.*\ )?
        (?P<path>
          [\-.\w/\\]+
          \.(?i:c(?:pp|xx|c)?|asm|s)
          (?:\.[a-z]{1,3})?
        )
    """
)
BUILDSTATUS = re.compile(r"\[ {0,2}\d+(?:%|[/\d]+)]| {2}(?:CC|CCLD|CPPAS)(?= )")
HASH_SET: Set[int] = set()


def shorten_conan_path(text: str, placeholder=r"...\g<sep>", count=0) -> str:
    storage = str(storage_path())
    text = CONAN_DATA_PATH.sub(placeholder, text, count=count)
    if len(storage) > 20:
        text = text.replace(storage, "(storage)")
    return text


def compact_pattern(regex: Pattern) -> Tuple[str, int]:
    """take verbose pattern and remove all whitespace and comments"""
    flags = regex.flags
    # remove inline flags
    pattern = re.sub(r"\(\?([aiLmsux])+\)", "", regex.pattern, flags=re.ASCII)
    # remove whitespace in verbose pattern
    if flags & re.VERBOSE:
        pattern = re.sub(r"(?<!\\)\s+|\\(?= )|#.*\n", "", pattern, flags=re.ASCII)
        flags -= re.VERBOSE

    return pattern, flags


def filter_by_regex(
    string: str, mapping: Dict[str, List[Match]], **patterns: Union[Pattern[str], str]
) -> str:
    for name, pattern in patterns.items():
        span_end = 0
        residues = []
        match_list = mapping.setdefault(name, [])

        for match in re.finditer(pattern, string):
            _hash = hash(match.group().lstrip())
            if _hash not in HASH_SET:
                HASH_SET.add(_hash)
                match_list.append(match)
            residues.append(string[span_end : match.start()])
            span_end = match.end()

        if residues:
            residues.append(string[span_end:])
            string = "".join(residues)

    return string


def build_status(line: str) -> Tuple[Optional[str], Optional[str]]:
    match = BUILDSTATUS.match(line)
    if match:
        return match.group().lstrip(), line.rsplit(maxsplit=1)[1]

    if line.startswith(" "):
        return None, None

    idx = 0 if " " not in line else line.replace("/", "-").find(" -c ")
    if idx >= 0:
        match = FILEPATH.match(line[idx:])
        if match:
            return None, match.group("path")

    return None, None


class ParsedLine:
    REF_REGEX = re.compile(
        rf"^{compact_pattern(REF_REGEX)[0]}(?: \((?P<spec>[a-z ]+)\))?"
    )

    def __init__(self, line: str):
        self.line = line.rstrip("\r\n")
        self.refspec = self._ref = self._rest = None

    def _split(self):
        line = self.line
        *prefix, rest = line.split(":", maxsplit=1)
        if prefix and "/" in prefix[0]:
            match = self.REF_REGEX.match(prefix[0])
            if match:
                self._ref, self.refspec = match.group("ref", "spec")
                line = rest[1:]

        self._rest = line

    @property
    def ref(self):
        if self._rest is None:
            self._split()
        return self._ref

    @property
    def rest(self):
        if self._rest is None:
            self._split()
        return self._rest


class RegexFilter:
    def __init__(self, regex: Union[str, Pattern[str]], minlines: int):
        assert minlines > 0, "minlines must be a positive integer"
        self.regex: Pattern[str] = re.compile(regex)
        self.minlines: int = minlines
        self.buffer: Deque[str] = deque(maxlen=minlines - 1)
        self.residue: List[str] = []

    # pylint: disable=too-many-branches
    def feedlines(self, *lines: str, final=False) -> List[Match[str]]:
        buffer, residue = self.buffer, self.residue
        string = "".join((*self.buffer, *lines))
        matches = list(self.regex.finditer(string))

        if not matches:
            if final:
                buffer.clear()
                residue_string = string
            else:
                idx = string.rfind("\n", None, None)
                for _ in range(self.minlines - 1):
                    idx = string.rfind("\n", None, idx)
                    if idx == -1:
                        break
                residue_string = string[: idx + 1]
                buffer.extend(lines)
            if residue_string:
                residue.append(residue_string)
            return []

        endpos = 0
        for match in matches:
            if endpos < match.start():
                residue.append(string[endpos : match.start()])
            endpos = match.end()

        buffer.clear()
        last_match = matches[-1]
        if final:
            endpos = last_match.end()
            if endpos < len(string):
                residue.append(string[endpos:])
        else:
            start = last_match.start()
            if string.count("\n", start) >= self.minlines:
                next_lines = string[last_match.end() :].splitlines(keepends=True)
                residue_string = "".join(next_lines[: 1 - self.minlines])
                if residue_string:
                    residue.append(residue_string)
            else:
                matches.pop()
                next_lines = string[start:].splitlines(keepends=True)
            buffer.extend(next_lines)

        return matches
