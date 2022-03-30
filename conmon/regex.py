#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from typing import Pattern, Tuple

DECOLORIZE_REGEX = re.compile(r"[\u001b]\[\d{1,2}m", re.UNICODE)
CONAN_DATA_PATH = re.compile(
    r"""(?x)
        (?P<path>
            ([a-zA-Z]:)?
            (?P<sep>[\\/])
            (?:[\w\-.]+(?P=sep)){5,}  # conservative choice of characters in path names
            (?:build|package)(?P=sep)
            [a-f0-9]{40}
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


def shorten_conan_path(text: str, placeholder=r"...\g<sep>", count=0) -> str:
    return CONAN_DATA_PATH.sub(placeholder, text, count=count)


def compact_pattern(regex: Pattern) -> Tuple[str, int]:
    """take verbose pattern and remove all whitespace and comments"""
    flags = regex.flags
    # remove inline flags
    pattern = re.sub(r"\(\?([aiLmsux])+\)", "", regex.pattern, flags=re.ASCII)
    # remove whitespace in verbose pattern
    if flags & re.VERBOSE:
        pattern = re.sub(r"(?<!\\)\s+|\\(?= )|#[^\n]+\n", "", pattern, flags=re.ASCII)
        flags -= re.VERBOSE

    return pattern, flags
