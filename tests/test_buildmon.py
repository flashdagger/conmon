#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
from collections.abc import Hashable
from pathlib import Path
from unittest.mock import patch

import pytest
from psutil import Process

from conmon.buildmon import BuildMonitor, CompilerParser
from conmon.utils import (
    append_to_set,
    freeze_json_object,
    merge_mapping,
    unfreeze_json_object,
)

cases = [
    {
        "proc": {
            "cmdline": [
                "clang++",
                "-x",
                "c++",
                "-EHsc",
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
                "-external:Isystem_include",
                "-fPIC",
                "-f",
                "win",
                "-stdlib=libstdc++",
                "-DBOOST_STACKTRACE_ADDR2LINE_LOCATION=/usr/bin/addr2line",
                "-DBOOST_ALL_NO_LIB=1",
                "-D_GLIBCXX_USE_CXX11_ABI=1",
                "-I.",
                "-o",
                "power.o",
                "-c",
                "power.cpp",
                "-link",  # ignore all options after
                "-DLL",
                "-IMPLIB:libltdl\\.libs\\ltdl.dll.lib",
            ],
            "exe": "clang",
            "cwd": Path.cwd() / "source",
            "name": "clang++",
        },
        "translation_unit": {
            "compiler": Path.cwd() / "source/clang",
            "flags": [
                "-EHsc",
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
                "-stdlib=libstdc++",
            ],
            "defines": [
                "BOOST_ALL_NO_LIB=1",
                "BOOST_STACKTRACE_ADDR2LINE_LOCATION=/usr/bin/addr2line",
                "_GLIBCXX_USE_CXX11_ABI=1",
            ],
            "system_includes": ["source/system_include"],
            "includes": ["source", "source/include"],
            "sources": ["source/power.cpp"],
            "object_format": "win",
        },
    }
]


@pytest.mark.parametrize("case", cases)
def test_buildmon_process(case):
    monitor = BuildMonitor()
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


def test_group_and_merge_json_with_path():
    mapping = {}
    append_to_set(
        dict(foo=Path("Foo.exe"), baz={4, 5, 6}),
        mapping,
        value_key="baz",
    )
    append_to_set(
        dict(foo=Path("foo.EXE"), baz={1, 2, 3, 4}),
        mapping,
        value_key="baz",
    )
    result = merge_mapping(mapping, value_key="baz")
    if os.name == "nt":
        assert len(result) == 1
        assert result[0] == dict(foo=Path("foo.exe"), baz=[1, 2, 3, 4, 5, 6])
    else:
        assert len(result) == 2
        assert result[0] == dict(foo=Path("Foo.exe"), baz=[4, 5, 6])
        assert result[1] == dict(foo=Path("foo.EXE"), baz=[1, 2, 3, 4])


def test_compiler_arg_parsing():
    parser = CompilerParser()
    args, unknown_args = parser.parse_known_args(
        "-cc1 -Iinclude -Ddefine -cc1as -include-pch -diagnostics".split()
    )
    assert args.includes == ["include"]
    assert args.defines == ["define"]
    assert "-include-pch" in unknown_args
    assert "-diagnostics" not in unknown_args
    assert "-cc1" not in unknown_args
    assert args.cc_frontend
    assert args.ccas_frontend


paths = [
    (
        r".libs\testlib-0.dll.exp",
        r"D:\build\bin_autotools",
        r"D:\build\bin_autotools\.libs\testlib-0.dll.exp",
    ),
    (
        r"C:\.libs\testlib-0.dll.exp",
        r"D:\build\bin_autotools",
        r"C:\.libs\testlib-0.dll.exp",
    ),
    ("/mnt/foo/bar", "/mnt/baz", "/mnt/foo/bar"),
    ("/mnt/foo/../bar", "", "/mnt/bar"),
    ("../bar", "/mnt/foo", "/mnt/bar"),
    ("../../bar/../..", "/mnt/foo", "/"),
]


@pytest.mark.parametrize("path", paths)
def test_make_absolute(path):
    path, cwd, expected = path
    if os.name != "nt" and ("\\" in path or "\\" in cwd):
        return
    assert BuildMonitor.make_absolute(path, cwd) == Path(expected).resolve()


class MockProcess(Process):
    def children(self, recursive=False):
        return [MockProcess()]

    def as_dict(self, attrs=None, ad_value=None):
        mapping = super().as_dict(attrs=attrs, ad_value=ad_value)
        if "exe" in mapping:
            mapping["exe"] = None
        return mapping


def test_scan_accepts_dict_with_falsy_values():
    with patch("psutil.Process", new=MockProcess):
        from psutil import Process

        monitor = BuildMonitor()
        monitor.proc = Process()
        monitor.scan()
