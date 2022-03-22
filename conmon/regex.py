#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re

from conmon.utils import compact_pattern

DECOLORIZE_REGEX = re.compile(r"[\u001b]\[\d{1,2}m", re.UNICODE)
CONAN_DATA_PATH = re.compile(
    r"""(?x)
        (?P<path>
            ([a-zA-Z]:)?
            (?P<sep>[\\/])
            (?:[\w.]+(?P=sep)){5,}  # conservative choice of characters in path names
            (?:build|package)(?P=sep)
            [a-f0-9]{40}
            (?P=sep)
        )
    """
)
REF_PART_PATTERN = r"\w[\w\+\.\-]{1,50}"
REF_REGEX = re.compile(
    rf"""
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
    """,
    re.VERBOSE,
)
WARNING_REGEX = re.compile(
    rf"""(?xm)
    (?:(?P<severity_l>ERROR|WARN):\ )?    
    (?:{compact_pattern(REF_REGEX)[0]}:\ +)?
    (?(severity_l)
    | (?P<severity>ERROR|WARN):\ ?)
    (?P<info>.*)
    """
)


def shorten_conan_path(text: str, placeholder=r"...\g<sep>", count=0) -> str:
    return CONAN_DATA_PATH.sub(placeholder, text, count=count)
