#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import re
import textwrap

import pytest

from conmon.compilers import WarningRegex, parse_compiler_warnings

output = [
    "src/main/src/Em_FilteringQmFu.c: In function \u2018Em_FilteringQmFu_processSensorSignals\u2019:",
    "src/main/src/Em_FilteringQmFu.c:266:5: warning: implicit declaration of function \u2018memset\u2019 [-Wimplicit-function-declaration]",
    "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));",
    "     ^~~~~~",
    r" C:\source_subfolder\source\common\x86\seaintegral.asm:92: warning: improperly calling multi-line macro `SETUP_STACK_POINTER' with 0 parameters [-w+macro-params-legacy]",
    "some text",
]


dataset = [
    pytest.param(
        [
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
                category="-w+macro-params-legacy",
                column=None,
                context="",
                file="C:\\source_subfolder\\source\\common\\x86\\seaintegral.asm",
                hint=None,
                info="improperly calling multi-line macro `SETUP_STACK_POINTER' with 0 parameters",
                line="92",
                severity="warning",
            ),
        ],
        id="gnu",
    ),
    pytest.param([], id="msvc"),
    pytest.param([], id="clang-cl"),
    pytest.param([], id="cmake"),
]


@pytest.mark.parametrize("expected", dataset)
def test_warnings_regex(expected, request):
    compiler = request.node.callspec.id
    matches = list(
        match.groupdict()
        for match in re.finditer(WarningRegex.get(compiler), "\n".join(output))
    )
    assert matches == expected


def test_gnu_hint():
    warning_output = """
    /build/source_subfolder/bzip2.c: In function ‘applySavedFileAttrToOutputFile’:
    /build/source_subfolder/bzip2.c:1073:11: warning: ignoring return value of ‘fchown’, declared with attribute warn_unused_result [-Wunused-result]
     1073 |    (void) fchown ( fd, fileMetaInfo.st_uid, fileMetaInfo.st_gid );
          |           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    """

    lines = textwrap.dedent(warning_output).splitlines()
    warnings = parse_compiler_warnings(output="\n".join(lines), compiler="gnu")
    assert len(lines) == 6
    assert warnings, "No warnings parsed"
    assert warnings[0]["hint"].splitlines() == lines[3:5]


def test_conan_warning():
    match = WarningRegex.CONAN.fullmatch("libjpeg/1.2.3: WARN: package is corrupted")
    assert match
    expected = {
        "ref": "libjpeg/1.2.3",
        "severity": "WARN",
        "severity_l": None,
        "info": "package is corrupted",
    }
    assert {key: match.group(key) for key in expected.keys()} == expected

    match = WarningRegex.CONAN.fullmatch(
        "WARN: libmysqlclient/8.0.25: requirement openssl/1.1.1m "
        "overridden by poco/1.11.1 to openssl/1.1.1l"
    )
    assert match
    expected = {
        "ref": "libmysqlclient/8.0.25",
        "severity_l": "WARN",
        "severity": None,
        "info": "requirement openssl/1.1.1m overridden by poco/1.11.1 to openssl/1.1.1l",
    }
    assert {key: match.group(key) for key in expected.keys()} == expected
