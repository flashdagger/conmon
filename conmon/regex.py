#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re

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


def shorten_conan_path(text: str, placeholder=r"...\g<sep>", count=0) -> str:
    return CONAN_DATA_PATH.sub(placeholder, text, count=count)
