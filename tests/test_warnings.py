#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from conmon.compilers import COMPILER_REGEX_MAP, parse_warnings

output = [
    "text before",
    "src/main/src/Em_FilteringQmFu.c: In function \u2018Em_FilteringQmFu_processSensorSignals\u2019:",
    "src/main/src/Em_FilteringQmFu.c:266:5: warning: implicit declaration of function \u2018memset\u2019 [-Wimplicit-function-declaration]",
    "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));",
    "     ^~~~~~",
    "src/main/src/Em_FilteringQmFu.c:266:5: warning: incompatible implicit declaration of built-in function \u2018memset\u2019",
    "src/main/src/Em_FilteringQmFu.c:266:5: note: include \u2018<string.h>\u2019 or provide a declaration of \u2018memset\u2019",
    "text after",
]

expected_items = [
    dict(
        file="src/main/src/Em_FilteringQmFu.c",
        category="-Wimplicit-function-declaration",
        column="5",
        line="266",
        severity="warning",
        info="implicit declaration of function ‘memset’",
        context="src/main/src/Em_FilteringQmFu.c: In function ‘Em_FilteringQmFu_processSensorSignals’:\n",
        hint="     memset(&reicevedSignals, 0, sizeof(reicevedSignals));\n"
             "     ^~~~~~",
    ),
    dict(
        file="src/main/src/Em_FilteringQmFu.c",
        category=None,
        column="5",
        line="266",
        severity="warning",
        info="incompatible implicit declaration of built-in function ‘memset’",
        context="",
        hint=None,
    ),
    dict(
        file="src/main/src/Em_FilteringQmFu.c",
        category=None,
        column="5",
        line="266",
        severity="note",
        info="include ‘<string.h>’ or provide a declaration of ‘memset’",
        context="",
        hint=None,
    )
]


def test_warnings_gnu():
    warnings = list(COMPILER_REGEX_MAP["gnu"].finditer("\n".join(output)))

    assert len(warnings) == 3
    assert warnings[0].groupdict() == expected_items[0]
    assert warnings[1].groupdict() == expected_items[1]
    assert warnings[2].groupdict() == expected_items[2]


def test_parsing_gnu():
    warnings = parse_warnings(output="\n".join(output), compiler="gnu")

    assert len(warnings) == 2

    for idx, warning in enumerate(warnings):
        expected_item = dict(expected_items[idx])
        expected_item["line"] = int(expected_item["line"])
        expected_item["column"] = int(expected_item["column"])
        expected_item["from"] = "compiler"
        assert warning == expected_item
