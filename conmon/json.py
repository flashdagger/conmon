#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from json import JSONEncoder, loads, load
from pathlib import Path
from typing import TextIO

loads = loads  # pylint: disable=self-assigning-variable
load = load  # pylint: disable=self-assigning-variable


class Encoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, Path):
            return str(o)
        # Let the base class default method raise the TypeError
        return super().default(o)


def dump(obj, fh: TextIO, *args, **kwargs):
    encoder = Encoder(*args, **kwargs)
    fh.write(encoder.encode(obj))
