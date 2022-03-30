from pathlib import Path

from conmon.utils import common_parent, human_readable_byte_size, human_readable_size


def test_common_parent():
    assert common_parent() is None
    assert common_parent(Path.cwd()) == Path.cwd()
    assert common_parent(Path.cwd().as_posix()) == Path.cwd()
    assert common_parent("/a/b/c", "/a/b/c/d", "/a/b/d/") == Path("/a/b")


def test_human_readable_size():
    assert human_readable_size(3, "seconds") == "3 seconds"
    assert human_readable_size(-3.01, "seconds") == "-3.01 seconds"
    assert human_readable_size(333.75e-3, "seconds", min_precision=1) == "333.8 ms"
    assert human_readable_size(2.2e-6, "seconds", min_precision=1) == "2.200 us"
    assert human_readable_size(0.0, "seconds", min_precision=1) == "0.000 seconds"


def test_human_readable_byte_size():
    assert human_readable_byte_size(3) == "3 Bytes"
    assert human_readable_byte_size(333) == "333 Bytes"
    assert human_readable_byte_size(3333) == "3.25 kB"
    assert human_readable_byte_size(3333333) == "3.18 MB"
    assert human_readable_byte_size(3333333333) == "3.10 GB"
    assert human_readable_byte_size(int(33e15)) == "30013 TB"
