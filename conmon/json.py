#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
from collections import UserDict
from pathlib import Path
from typing import TextIO

from json_stream.base import StreamingJSONObject, StreamingJSONList
from json_stream import streamable_list
from json_stream.dump import JSONStreamEncoder

from .utils import CachedLines

loads = json.loads  # pylint: disable=self-assigning-variable
load = json.load  # pylint: disable=self-assigning-variable


def manifest(obj):
    if isinstance(obj, StreamingJSONList):
        return [manifest(item) for item in obj]
    if isinstance(obj, StreamingJSONObject):
        return {key: manifest(value) for key, value in obj.items()}
    return obj


class Encoder(JSONStreamEncoder):
    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, UserDict):
            return obj.data
        if isinstance(obj, CachedLines):
            return streamable_list(line[:-1] for line in obj)
        # Let the base class default method raise the TypeError
        return super().default(obj)


def dump(obj, fh: TextIO, *args, **kwargs):
    json.dump(obj, fh, *args, **kwargs, cls=Encoder)
