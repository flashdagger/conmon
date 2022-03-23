from pathlib import Path

from conmon.utils import common_parent


def test_common_parent():
    assert common_parent() is None
    assert common_parent(Path.cwd()) == Path.cwd()
    assert common_parent(Path.cwd().as_posix()) == Path.cwd()
    assert common_parent("/a/b/c", "/a/b/c/d", "/a/b/d/") == Path("/a/b")
