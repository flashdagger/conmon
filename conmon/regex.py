#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from typing import Dict, Iterator, List, Match, Optional, Pattern, Tuple, Union, Set

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


DECOLORIZE_REGEX = re.compile(r"\x1B\[\d{1,2}m", re.UNICODE)
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
REF_PART_PATTERN = r"\w[\w\+\.\-]{1,50}"
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
BUILD_STATUS_REGEX = re.compile(
    r"""(?x)
        (?P<status>
            \[\ {0,2}\d+(?:%|[/\d]+) ] | \ +(?:CC|CCLD|CPPAS)(?=\ )
        )?  # ninja, cmake or automake
        .*? # msbuild prints only the filename
        (?P<file>
            [\-.\w/\\]+ (?(status) \.[a-z]{1,3}$ | \.(?:asm|cpp|cxx|cc?|[sS])$ )
        )
"""
)
BUILD_STATUS_REGEX2 = re.compile(
    r"""(?x)
        (?P<status>$)?    # should never match
        .*\ [-/]c\ .*?    # compile but don't link
        (?P<file>
            (?:[a-zA-Z]:)? [\-.\w/\\]+ \. (?:asm|cpp|cxx|cc?|[sS])
            \b
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


def finditer(
    pattern: Union[Pattern[str], str], string: str, flags=0
) -> Iterator[Tuple[Optional[Match], str]]:
    span_end = 0
    for match in re.finditer(pattern, string, flags):
        yield match, string[span_end : match.start()]
        span_end = match.end()
    yield None, string[span_end:]


def unique_matches(matches: List[Optional[Match]]) -> Iterator[Match]:
    for match in matches:
        if not match:
            continue
        _hash = hash(match.group().lstrip())
        if _hash not in HASH_SET:
            HASH_SET.add(_hash)
            yield match


def filter_by_regex(
    string: str, mapping: Dict[str, List[Match]], **patterns: Union[Pattern[str], str]
) -> str:
    for name, pattern in patterns.items():
        matches, strings = zip(*finditer(pattern, string))
        string = "".join(strings)
        mapping.setdefault(name, []).extend(unique_matches(matches))

    return string
