from pathlib import Path

import pytest

from conmon.utils import (
    common_parent,
    human_readable_byte_size,
    human_readable_size,
    compare_everything,
    sorted_dicts,
)


def test_common_parent():
    assert common_parent() is None
    assert common_parent(Path.cwd()) == Path.cwd()
    assert common_parent(Path.cwd().as_posix()) == Path.cwd()
    assert common_parent("/a/b/c", "/a/b/c/d", "/a/b/d/") == Path("/a/b")


def test_human_readable_size():
    assert human_readable_size(3, "seconds") == "3 seconds"
    assert human_readable_size(-3.01, "seconds") == "-3.01 seconds"
    assert human_readable_size(333.75e-3, "seconds", min_precision=1) == "333.8 ms"
    assert human_readable_size(2.2e-6, "seconds", min_precision=1) == "2.200 μs"
    assert human_readable_size(0.0, "seconds", min_precision=1) == "0.000 seconds"


def test_human_readable_byte_size():
    assert human_readable_byte_size(3) == "3 Bytes"
    assert human_readable_byte_size(333) == "333 Bytes"
    assert human_readable_byte_size(3333) == "3.25 kB"
    assert human_readable_byte_size(3333333) == "3.18 MB"
    assert human_readable_byte_size(3333333333) == "3.10 GB"
    assert human_readable_byte_size(int(33e15)) == "30013 TB"


def test_compare_everything():
    assert tuple(
        sorted((3, None, 2, None, 1, 2.5, "4", "3"), key=compare_everything)
    ) == (
        1,
        2,
        2.5,
        3,
        "3",
        "4",
        None,
        None,
    )


def test_compare_everything_2():
    assert tuple(
        sorted(
            (
                (20, "A"),
                (1, "BBB"),
                (1, "A"),
                (1, None),
                (2, None, "X"),
                (2, None, "S"),
            ),
            key=compare_everything,
        )
    ) == (
        (1, "A"),
        (1, "BBB"),
        (1, None),
        (2, None, "S"),
        (2, None, "X"),
        (20, "A"),
    )


def test_sorted_dicts():
    items = (dict(a=3, b=2), dict(a=2), dict(c=3, a=0), dict(a=2, c="x"))

    with pytest.raises(AssertionError) as exc_info:
        next(sorted_dicts(items, keys=("a", "b", "c", "b")))
    assert exc_info.match("keys must be unique")

    assert tuple(sorted_dicts(items, keys=("a", "b", "c"))) == (
        {"a": 0, "c": 3},
        {"a": 2, "c": "x"},
        {"a": 2},
        {"a": 3, "b": 2},
    )


def test_sorted_dicts_reordered():
    items = (dict(a=2, b=2), dict(a=2), dict(c=3, a=0), dict(a=2, c="x"))
    assert [
        tuple(mapping.items())
        for mapping in sorted_dicts(items, keys=("c", "a", "b"), reorder_keys=True)
    ] == [
        (("c", 3), ("a", 0)),
        (("c", "x"), ("a", 2)),
        (("a", 2), ("b", 2)),
        (("a", 2),),
    ]
