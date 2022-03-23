from json import JSONEncoder, loads
from pathlib import Path
from typing import TextIO

loads = loads  # pylint: disable=self-assigning-variable


class Encoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, Path):
            return str(o)
        # Let the base class default method raise the TypeError
        return super().default(o)


def dump(obj, fp: TextIO, *args, **kwargs):
    encoder = Encoder(*args, **kwargs)
    fp.write(encoder.encode(obj))
