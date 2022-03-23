from collections.abc import Hashable
from pathlib import Path

import pytest
from psutil import Process

from conmon.buildmon import BuildMonitor, CompilerParser
from conmon.utils import (
    freeze_json_object,
    unfreeze_json_object,
    append_to_set,
    merge_mapping,
)

cases = [
    {
        "proc": {
            "cmdline": [
                "clang++",
                "-c",
                "-x",
                "c++",
                "-fvisibility-inlines-hidden",
                "-fPIC",
                "-pthread",
                "-O0",
                "-fno-inline",
                "-g",
                "-Zc:forScope",
                "-Wall",
                "-include-pch",
                "-fvisibility=hidden",
                "-Iinclude",
                "-fPIC",
                "-stdlib=libstdc++",
                "-DBOOST_STACKTRACE_ADDR2LINE_LOCATION=/usr/bin/addr2line",
                "-DBOOST_ALL_NO_LIB=1",
                "-D_GLIBCXX_USE_CXX11_ABI=1",
                "-I.",
                "-o",
                "power.cpp",
            ],
            "exe": "clang",
            "cwd": "source",
            "name": "clang++",
        },
        "translation_unit": {
            "compiler": "clang",
            "flags": [
                "-O0",
                "-Wall",
                "-Zc:forScope",
                "-fPIC",
                "-fno-inline",
                "-fvisibility-inlines-hidden",
                "-fvisibility=hidden",
                "-g",
                "-include-pch",
                "-pthread",
            ],
            "defines": [
                "BOOST_ALL_NO_LIB=1",
                "BOOST_STACKTRACE_ADDR2LINE_LOCATION=/usr/bin/addr2line",
                "_GLIBCXX_USE_CXX11_ABI=1",
            ],
            "includes": ["source", "source/include"],
            "sources": ["source/power.cpp"],
        },
    }
]


@pytest.mark.parametrize("case", cases)
def test_buildmon_process(case):
    monitor = BuildMonitor(Process())
    monitor.check_process(case["proc"])
    translation_units = monitor.translation_units
    assert len(translation_units) == 1

    for key in ("includes", "system_includes", "sources"):
        for tu in translation_units:
            if key not in tu:
                continue
            tu[key] = [
                str(Path(path).relative_to(Path.cwd()).as_posix()) for path in tu[key]
            ]

    assert translation_units[0] == case["translation_unit"]


def test_frozen_json_obj():
    submap = dict(
        int=1, float=2.0, str="3", bool=True, none=None, subdict={}, sublist=[]
    )
    json_obj = dict(list=list(submap.values()), dict=submap, **submap)
    frozen_json_obj = freeze_json_object(json_obj)
    assert isinstance(frozen_json_obj, Hashable)
    unfrozen_json_obj = unfreeze_json_object(frozen_json_obj)
    assert unfrozen_json_obj == json_obj


def test_group_and_merge_json_with_list():
    mapping = {}
    append_to_set(
        dict(foo={"z", "x", "y", "x"}, bar=["a", "b", "c"], baz=[1, 2, 3]),
        mapping,
        value_key="baz",
    )
    append_to_set(
        dict(foo=["x", "y", "z"], bar=["a", "b", "c"], baz=[4, 5, 6]),
        mapping,
        value_key="baz",
    )
    append_to_set(
        dict(foo=["x", "y", "z"], bar=["a", "b", "c"], baz=[1, 2, 3]),
        mapping,
        value_key="baz",
    )
    result = merge_mapping(mapping, value_key="baz")
    assert len(result) == 1
    assert result[0] == dict(
        foo=["x", "y", "z"], bar=["a", "b", "c"], baz=[1, 2, 3, 4, 5, 6, 1, 2, 3]
    )


def test_group_and_merge_json_with_set():
    mapping = {}
    append_to_set(
        dict(foo={"x", "y", "z"}, bar=["a", "b", "c"], baz={4, 5, 6}),
        mapping,
        value_key="baz",
    )
    append_to_set(
        dict(foo=["z", "x", "y", "x"], bar=["a", "b", "c"], baz={1, 2, 3}),
        mapping,
        value_key="baz",
    )
    append_to_set(
        dict(foo={"x", "y", "z"}, bar=["a", "b", "c"], baz={6, 5, 4}),
        mapping,
        value_key="baz",
    )
    result = merge_mapping(mapping, value_key="baz")
    assert len(result) == 2
    assert result[0] == dict(foo=["x", "y", "z"], bar=["a", "b", "c"], baz=[4, 5, 6])


def test_compiler_arg_parsing():
    parser = CompilerParser()
    args, unknown_args = parser.parse_known_args(
        "-cc1 -Iinclude -Ddefine -include-pch -diagnostics".split()
    )
    assert args.includes == ["include"]
    assert args.defines == ["define"]
    assert "-include-pch" in unknown_args
    assert "-diagnostics" not in unknown_args
    assert "-cc1" not in unknown_args
    assert not args.compile_not_link
    assert args.cc_frontend
