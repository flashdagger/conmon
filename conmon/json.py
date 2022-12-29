#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
from collections import UserDict
from pathlib import Path
from typing import Iterable, Mapping, Optional, TextIO, Tuple, Union

import json_stream
from json_stream import streamable_dict, streamable_list
from json_stream.base import (
    StreamingJSONList,
    StreamingJSONObject,
    TransientStreamingJSONList,
    TransientStreamingJSONObject,
)
from json_stream.dump import JSONStreamEncoder

from .utils import CachedLines

NoneType = type(None)
PathType = Tuple[Union[str, int], ...]
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


def update(
    infile: Path,
    updates: Mapping[PathType, Optional[Union[Mapping, Iterable]]],
    **kwargs,
):
    # pylint: disable=too-few-public-methods
    class Streamable:
        def __init__(self, iterable, path=()):
            self._path = path
            if path and isinstance(path[-1], int):
                super().__init__(iterable)
            else:
                super().__init__(self._wrapped(iterable))

        def __repr__(self):  # pragma: no cover
            return f"<{type(self).__name__} path={self._path}>"

        def _wrapped(self, iterable):
            raise NotImplementedError()

    class StreamableDict(Streamable, json_stream.writer.StreamableDict):
        def _wrapped(self, iterable):
            path = self._path
            umap = updates.get(path, {})
            assert isinstance(umap, Mapping), "callback must return Mapping or None"
            updated_keys = set()
            for key, value in iterable:
                if key in umap:
                    updated_keys.add(key)
                    yield key, umap[key]
                    continue
                if isinstance(value, TransientStreamingJSONObject):
                    value = self.__class__(value.items(), path=path + (key,))
                if isinstance(value, TransientStreamingJSONList):
                    value = StreamableList(value, path=path + (key,))
                yield key, value

            for key, value in umap.items():
                if key in updated_keys:
                    continue
                yield key, value

    class StreamableList(Streamable, json_stream.writer.StreamableList):
        def _wrapped(self, iterable):
            path = self._path
            data = updates.get(path, ())
            assert isinstance(data, Iterable), "callback must return an iterable"
            for idx, value in enumerate(iterable):
                if isinstance(value, TransientStreamingJSONObject):
                    value = StreamableDict(value.items(), path=path + (idx,))
                if isinstance(value, TransientStreamingJSONList):
                    value = self.__class__(value, path=path + (idx,))
                yield value
            for value in data:
                yield value

    kwargs.pop("check_circular", None)
    if "default" in kwargs:
        default = kwargs.pop("default")
    else:
        default = kwargs.pop("cls", Encoder)().default

    def transient(obj):
        if isinstance(obj, TransientStreamingJSONObject):
            return streamable_dict(obj.items())
        if isinstance(obj, TransientStreamingJSONList):
            return streamable_list(obj)
        return default(obj)

    outfile = infile.with_name(f"{infile.stem}.out{infile.suffix}")
    with infile.open(encoding="utf-8") as fh_in:
        instream = json_stream.load(fh_in, persistent=False)
        if isinstance(instream, TransientStreamingJSONObject):
            instream = StreamableDict(instream.items())
        elif isinstance(instream, TransientStreamingJSONList):
            instream = StreamableList(instream)
        with outfile.open("w", encoding="utf-8") as fh_out:
            json.dump(
                instream, fh_out, check_circular=False, default=transient, **kwargs
            )

    infile.unlink()
    outfile.rename(infile)
