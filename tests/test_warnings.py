#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import re

import pytest

from conmon.compilers import WarningRegex

output = [
    "src/main/src/Em_FilteringQmFu.c: In function "
    "\u2018Em_FilteringQmFu_processSensorSignals\u2019:",
    "src/main/src/Em_FilteringQmFu.c:266:5: warning: implicit declaration of function "
    "\u2018memset\u2019 [-Wimplicit-function-declaration]",
    "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));",
    "     ^~~~~~",
    r"C:\source_subfolder\source\common\x86\seaintegral.asm:92: warning: improperly calling "
    r"multi-line macro `SETUP_STACK_POINTER' with 0 parameters [-w+macro-params-legacy]",
    "some text",
    r"In file included from C:\conan\data\source_subfolder\zutil.c:10:",
    r"C:\conan\data\source_subfolder/gzguts.h(146,52): warning: extension used "
    r"[-Wlanguage-extension-token]",
    "ZEXTERN z_off64_t ZEXPORT gzseek64 OF((gzFile, z_off64_t, int));",
    "                                               ^",
    "/build/source_subfolder/bzip2.c: In function ‘applySavedFileAttrToOutputFile’:",
    "/build/source_subfolder/bzip2.c:1073:11: warning: ignoring return value of ‘fchown’, declared "
    "with attribute warn_unused_result [-Wunused-result]",
    " 1073 |    (void) fchown ( fd, fileMetaInfo.st_uid, fileMetaInfo.st_gid );",
    "      |           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
    "/source_subfolder/src/constexp.y:35.1-25: warning: deprecated directive: ‘%name-prefix "
    '"constexpYY"’, use ‘%define api.prefix {constexpYY}’ [-Wdeprecated]',
    '   35 | %name-prefix "constexpYY"',
    "      | ^~~~~~~~~~~~~~~~~~~~~~~~~" "      | %define api.prefix {constexpYY}",
    "/source_subfolder/src/constexp.y: warning: fix-its can be applied.  Rerun with option "
    "'--update'. [-Wother]",
    "/source_subfolder/common/socket_utils.cc(43): warning C4312: 'reinterpret_cast': conversion "
    "from 'int' to 'HANDLE' of greater size",
    r"C:\source_subfolder\bzlib.c(1418,10): warning C4996: 'strcat': This function or variable may "
    r"be unsafe. Consider using strcat_s instead. To disable deprecation, use "
    r"_CRT_SECURE_NO_WARNINGS. See online help for details.",
    '   strcat(mode2,"b");   /* binary mode */',
    "         ^",
    "CMake Warning:",
    "  Manually-specified variables were not used by the project:",
    "",
    "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY",
    "",
    "",
]


dataset = [
    pytest.param(
        [
            {
                "context": "src/main/src/Em_FilteringQmFu.c: In function "
                "‘Em_FilteringQmFu_processSensorSignals’:\n",
                "file": "src/main/src/Em_FilteringQmFu.c",
                "category": "-Wimplicit-function-declaration",
                "line": "266",
                "column": "5",
                "severity": "warning",
                "info": "implicit declaration of function ‘memset’",
                "hint": "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));\n"
                "     ^~~~~~",
            },
            {
                "context": "",
                "file": "C:\\source_subfolder\\source\\common\\x86\\seaintegral.asm",
                "line": "92",
                "column": None,
                "severity": "warning",
                "info": "improperly calling multi-line macro `SETUP_STACK_POINTER' with 0 "
                "parameters",
                "category": "-w+macro-params-legacy",
                "hint": None,
            },
            {
                "context": "In file included from "
                "C:\\conan\\data\\source_subfolder\\zutil.c:10:\n",
                "file": "C:\\conan\\data\\source_subfolder/gzguts.h",
                "line": "146",
                "column": "52",
                "severity": "warning",
                "info": "extension used",
                "category": "-Wlanguage-extension-token",
                "hint": "ZEXTERN z_off64_t ZEXPORT gzseek64 OF((gzFile, z_off64_t, int));\n"
                "                                               ^",
            },
            {
                "context": "/build/source_subfolder/bzip2.c: In function "
                "‘applySavedFileAttrToOutputFile’:\n",
                "file": "/build/source_subfolder/bzip2.c",
                "line": "1073",
                "column": "11",
                "severity": "warning",
                "info": "ignoring return value of ‘fchown’, declared with attribute "
                "warn_unused_result",
                "category": "-Wunused-result",
                "hint": " 1073 |    (void) fchown ( fd, fileMetaInfo.st_uid, fileMetaInfo.st_gid );"
                "\n"
                "      |           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
            },
            {
                "context": "",
                "file": "/source_subfolder/src/constexp.y",
                "line": "35",
                "column": "1-25",
                "severity": "warning",
                "info": 'deprecated directive: ‘%name-prefix "constexpYY"’, use ‘%define '
                "api.prefix {constexpYY}’",
                "category": "-Wdeprecated",
                "hint": '   35 | %name-prefix "constexpYY"\n'
                "      | ^~~~~~~~~~~~~~~~~~~~~~~~~      | %define api.prefix "
                "{constexpYY}",
            },
            {
                "context": "",
                "file": "/source_subfolder/src/constexp.y",
                "line": None,
                "column": None,
                "severity": "warning",
                "info": "fix-its can be applied.  Rerun with option '--update'.",
                "category": "-Wother",
                "hint": None,
            },
        ],
        id="gnu",
    ),
    pytest.param(
        [
            {
                "file": "/source_subfolder/common/socket_utils.cc",
                "line": "43",
                "column": None,
                "severity": "warning",
                "info": "'reinterpret_cast': conversion from 'int' to 'HANDLE' of greater size",
                "category": "C4312",
                "project": None,
                "hint": None,
            },
            {
                "file": "C:\\source_subfolder\\bzlib.c",
                "line": "1418",
                "column": "10",
                "category": "C4996",
                "severity": "warning",
                "info": "'strcat': This function or variable may be unsafe. Consider using "
                "strcat_s instead. To disable deprecation, use "
                "_CRT_SECURE_NO_WARNINGS. See online help for details.",
                "project": None,
                "hint": '   strcat(mode2,"b");   /* binary mode */\n' "         ^",
            },
        ],
        id="msvc",
    ),
    pytest.param(
        [
            {
                "context": None,
                "severity": "Warning",
                "file": None,
                "line": None,
                "function": None,
                "info": "  Manually-specified variables were not used by the project:\n\n"
                "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY\n\n",
            },
        ],
        id="cmake",
    ),
]


@pytest.mark.parametrize("expected", dataset)
def test_warnings_regex(expected, request):
    compiler = request.node.callspec.id
    matches = list(
        match.groupdict()
        for match in re.finditer(WarningRegex.get(compiler), "\n".join(output) + "\n")
    )
    assert matches == expected


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
