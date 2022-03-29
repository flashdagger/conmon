from pathlib import Path

from conmon.utils import common_parent, human_readable_byte_size, human_readable_size


def test_common_parent():
    assert common_parent() is None
    assert common_parent(Path.cwd()) == Path.cwd()
    assert common_parent(Path.cwd().as_posix()) == Path.cwd()
    assert common_parent("/a/b/c", "/a/b/c/d", "/a/b/d/") == Path("/a/b")


def test_human_readable_size():
    assert human_readable_size(3.01, "seconds") == "3.0 seconds"
    assert human_readable_size(-3.01, "seconds") == "-3.0 seconds"
    assert human_readable_size(333.75e-3, "seconds") == "333.8 ms"
    assert human_readable_size(2.2e-6, "seconds", precision=3) == "2.200 us"
    assert human_readable_size(0.0, "seconds", precision=3) == "0.000 seconds"


def test_human_readable_byte_size():
    assert human_readable_byte_size(3) == "3 Bytes"
    assert human_readable_byte_size(333) == "333 Bytes"
    assert human_readable_byte_size(3333, precision=1) == "3.3 kB"
    assert human_readable_byte_size(3333333, precision=2) == "3.18 MB"
    assert human_readable_byte_size(3333333333, precision=3) == "3.104 GB"
    assert human_readable_byte_size(int(33e15), precision=0) == "30013 TB"
