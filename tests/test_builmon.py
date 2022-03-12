from pathlib import Path

import pytest

from conmon.buildmon import BuildMonitor

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
                "-Wall",
                "-g",
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
                "-fPIC",
                "-fno-inline",
                "-fvisibility-inlines-hidden",
                "-fvisibility=hidden",
                "-g",
                "-pthread",
        ],
            "defines": [
                "BOOST_STACKTRACE_ADDR2LINE_LOCATION=/usr/bin/addr2line",
                "BOOST_ALL_NO_LIB=1",
                "_GLIBCXX_USE_CXX11_ABI=1",
            ],
            "sources": ["source/power.cpp"],
            "includes": ["source/include", "source"],
            "forced_includes": [],
            "system_includes": [],
            "undefines": [],
        },
    }
]


@pytest.mark.parametrize("case", cases)
def test_buildmon_process(case):
    monitor = BuildMonitor()
    monitor.check_process(case["proc"])
    translation_units = tuple(monitor.translation_units.values())
    assert len(translation_units) == 1

    for key in ("includes", "system_includes", "sources"):
        for tu in translation_units:
            tu[key] = [
                str(Path(path).relative_to(Path.cwd()).as_posix()) for path in tu[key]
            ]

    assert translation_units[0] == case["translation_unit"]
