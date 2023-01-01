#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import json
import os
from pathlib import Path
from typing import Any, Callable, IO, Iterable, Mapping, Optional, Tuple, Union

import json_stream
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
        if isinstance(obj, CachedLines):
            return obj.read().splitlines(keepends=False)
        # Let the base class default method raise the TypeError
        return super().default(obj)


def dump(obj, fh: IO[str], *args, **kwargs):
    kwargs.setdefault("cls", Encoder)
    json.dump(obj, fh, *args, **kwargs)


# pylint: disable=consider-using-with
def update(
    updates: Union[Callable[[PathType], Any], Mapping[PathType, Any]],
    infile: Union[IO[str], Path, str],
    outfile: Optional[Union[IO[str], Path, str]] = None,
    **kwargs,
):
    if callable(updates):
        callback = updates
    else:
        callback = updates.get

    def wrap(item, path):
        if isinstance(item, TransientStreamingJSONObject):
            return StreamableDict(item.items(), path=path)
        if isinstance(item, TransientStreamingJSONList):
            return StreamableList(item, path=path)
        return item

    def update_dict(iterable, path):
        umap = dict(callback(path) or ())
        for key, item in iterable:
            yield key, umap.pop(key) if key in umap else wrap(item, path + (key,))
        yield from umap.items()

    def update_list(iterable, path):
        for idx, item in enumerate(iterable):
            yield wrap(item, path + (idx,))
        data = callback(path) or ()
        assert isinstance(data, Iterable), "expected an iterable"
        for value in data:
            yield value

    class StreamableDict(json_stream.writer.StreamableDict):
        def __init__(self, iterable, path=()):
            super().__init__(update_dict(iterable, path))

    class StreamableList(json_stream.writer.StreamableList):
        def __init__(self, iterable, path=()):
            super().__init__(update_list(iterable, path))

    swapfiles = True
    fh_in = (
        open(infile, encoding="utf-8") if isinstance(infile, (str, Path)) else infile
    )
    with fh_in:
        instream = json_stream.load(fh_in, persistent=False)

        if isinstance(instream, TransientStreamingJSONObject):
            instream = StreamableDict(instream.items())
        elif isinstance(instream, TransientStreamingJSONList):
            instream = StreamableList(instream)

        if outfile is None:
            name_in = Path(fh_in.name)
            outfile = name_in.with_name(f"{name_in.stem}.tmp{name_in.suffix}")
        else:
            swapfiles = False
        fh_out = (
            open(outfile, "w", encoding="utf-8")
            if isinstance(outfile, (str, Path))
            else outfile
        )

        kwargs.update(dict(check_circular=False, cls=Encoder))
        with fh_out:
            json.dump(instream, fh_out, **kwargs)

    if swapfiles:
        assert isinstance(outfile, (Path, str))
        if not isinstance(infile, (Path, str)):
            infile = infile.name
        os.remove(infile)
        os.rename(outfile, infile)
