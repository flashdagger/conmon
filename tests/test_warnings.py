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
    "Makefile.config:565: No sys/sdt.h found, no SDT events are defined, please install "
    "systemtap-sdt-devel or systemtap-sdt-dev",
    "CMake Warning:",
    "  Manually-specified variables were not used by the project:",
    "",
    "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY",
    "",
    "",
    "libjpeg/1.2.3: WARN: package is corrupted",
    "WARN: libmysqlclient/8.0.25: requirement openssl/1.1.1m "
    "overridden by poco/1.11.1 to openssl/1.1.1l",
    "In file included from ../../src/include/c.h:54,",
    "                 from ../../src/include/postgres_fe.h:25,",
    "                 from archive.c:19:",
    "../../src/include/pg_config.h:772:24: warning: ISO C does not support \u2018__int128\u2019 "
    "types [-Wpedantic]",
    "  772 | #define PG_INT128_TYPE __int128",
    "      |                        ^~~~~~~~",
    "configure: WARNING:",
    "*** Without Bison you will not be able to build PostgreSQL from Git nor",
    "*** change any of the parser definition files.  You can obtain Bison from",
    "*** a GNU mirror site.  (If you are using the official distribution of",
    "*** PostgreSQL then you do not need to worry about this, because the Bison",
    "*** output is pre-generated.)",
    "end",
    "CMake Warning at cmake/ldap.cmake:158 (MESSAGE):",
    "  Could not find LDAP",
    "Call Stack (most recent call first):",
    "  CMakeListsOriginal.txt:1351 (MYSQL_CHECK_LDAP)",
    "  CMakeLists.txt:7 (include)",
    "",
    "",
    "CMake Warning at libmysql/authentication_ldap/CMakeLists.txt:30 (MESSAGE):",
    "  Skipping the LDAP client authentication plugin",
    "",
    "",
    "In file included from /package/include/glib-2.0/gobject/gobject.h:24,",
    "                 from /package/include/glib-2.0/gobject/gbinding.h:29,",
    "                 from /package/include/glib-2.0/glib-object.h:22,",
    "                 from ../source_subfolder/atk/atkobject.h:27,",
    "                 from ../source_subfolder/atk/atk.h:25,",
    "                 from ../source_subfolder/atk/atktext.c:22:",
    "../source_subfolder/atk/atktext.c: In function \u2018atk_text_range_get_type_once\u2019:",
    "../source_subfolder/atk/atktext.c:1640:52: warning: ISO C prohibits argument conversion to "
    "union type [-Wpedantic]",
    " 1640 | G_DEFINE_BOXED_TYPE (AtkTextRange, atk_text_range, atk_text_range_copy,",
    "      |                                                    ^~~~~~~~~~~~~~~~~~~",
]


dataset = [
    pytest.param(
        [
            {
                "context": "src/main/src/Em_FilteringQmFu.c: In function ‘Em_FilteringQmFu_processSensorSignals’:\n",
                "file": "src/main/src/Em_FilteringQmFu.c",
                "category": "-Wimplicit-function-declaration",
                "line": "266",
                "column": "5",
                "severity": "warning",
                "info": "implicit declaration of function ‘memset’",
                "hint": ""
                "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));\n"
                "     ^~~~~~",
            },
            {
                "context": "",
                "file": "C:\\source_subfolder\\source\\common\\x86\\seaintegral.asm",
                "line": "92",
                "column": None,
                "severity": "warning",
                "info": ""
                "improperly calling multi-line macro `SETUP_STACK_POINTER' with 0 parameters",
                "category": "-w+macro-params-legacy",
                "hint": None,
            },
            {
                "context": "In file included from C:\\conan\\data\\source_subfolder\\zutil.c:10:\n",
                "file": "C:\\conan\\data\\source_subfolder/gzguts.h",
                "line": "146",
                "column": "52",
                "severity": "warning",
                "info": "extension used",
                "category": "-Wlanguage-extension-token",
                "hint": ""
                "ZEXTERN z_off64_t ZEXPORT gzseek64 OF((gzFile, z_off64_t, int));\n"
                "                                               ^",
            },
            {
                "context": "/build/source_subfolder/bzip2.c: In function "
                "‘applySavedFileAttrToOutputFile’:\n",
                "file": "/build/source_subfolder/bzip2.c",
                "line": "1073",
                "column": "11",
                "severity": "warning",
                "info": "ignoring return value of ‘fchown’, declared with attribute warn_unused_result",
                "category": "-Wunused-result",
                "hint": ""
                " 1073 |    (void) fchown ( fd, fileMetaInfo.st_uid, fileMetaInfo.st_gid );\n"
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
                "hint": ""
                '   35 | %name-prefix "constexpYY"\n'
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
            {
                "context": ""
                "In file included from ../../src/include/c.h:54,\n"
                "                 from ../../src/include/postgres_fe.h:25,\n"
                "                 from archive.c:19:\n",
                "file": "../../src/include/pg_config.h",
                "line": "772",
                "column": "24",
                "severity": "warning",
                "category": "-Wpedantic",
                "info": "ISO C does not support ‘__int128’ types",
                "hint": ""
                "  772 | #define PG_INT128_TYPE __int128\n"
                "      |                        ^~~~~~~~",
            },
            {
                "context": ""
                "In file included from /package/include/glib-2.0/gobject/gobject.h:24,\n"
                "                 from /package/include/glib-2.0/gobject/gbinding.h:29,\n"
                "                 from /package/include/glib-2.0/glib-object.h:22,\n"
                "                 from ../source_subfolder/atk/atkobject.h:27,\n"
                "                 from ../source_subfolder/atk/atk.h:25,\n"
                "                 from ../source_subfolder/atk/atktext.c:22:\n"
                "../source_subfolder/atk/atktext.c: In function \u2018atk_text_range_get_type_once\u2019:\n",
                "file": "../source_subfolder/atk/atktext.c",
                "line": "1640",
                "column": "52",
                "severity": "warning",
                "info": "ISO C prohibits argument conversion to union type",
                "category": "-Wpedantic",
                "hint": ""
                " 1640 | G_DEFINE_BOXED_TYPE (AtkTextRange, atk_text_range, atk_text_range_copy,\n"
                "      |                                                    ^~~~~~~~~~~~~~~~~~~",
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
                "hint": '   strcat(mode2,"b");   /* binary mode */\n         ^',
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
                "info": ""
                "  Manually-specified variables were not used by the project:\n\n"
                "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY\n\n",
            },
            {
                "file": "cmake/ldap.cmake",
                "line": "158",
                "severity": "Warning",
                "function": "MESSAGE",
                "info": "  Could not find LDAP\n",
                "context": ""
                "Call Stack (most recent call first):\n"
                "  CMakeListsOriginal.txt:1351 (MYSQL_CHECK_LDAP)\n"
                "  CMakeLists.txt:7 (include)",
            },
            {
                "file": "libmysql/authentication_ldap/CMakeLists.txt",
                "line": "30",
                "severity": "Warning",
                "function": "MESSAGE",
                "context": None,
                "info": "  Skipping the LDAP client authentication plugin\n\n",
            },
        ],
        id="cmake",
    ),
    pytest.param(
        [
            {
                "from": "Makefile.config",
                "info": "No sys/sdt.h found, no SDT events are defined, please install "
                "systemtap-sdt-devel or systemtap-sdt-dev",
                "line": "565",
                "severity": None,
            },
            {
                "from": "configure",
                "line": None,
                "severity": "WARNING",
                "info": ""
                "\n*** Without Bison you will not be able to build PostgreSQL from Git nor"
                "\n*** change any of the parser definition files.  You can obtain Bison from"
                "\n*** a GNU mirror site.  (If you are using the official distribution of"
                "\n*** PostgreSQL then you do not need to worry about this, because the Bison"
                "\n*** output is pre-generated.)",
            },
        ],
        id="autotools",
    ),
    pytest.param(
        [
            {
                "ref": "libjpeg/1.2.3",
                "name": "libjpeg",
                "version": "1.2.3",
                "user": None,
                "channel": None,
                "info": "package is corrupted",
                "severity": "WARN",
                "severity_l": None,
            },
            {
                "ref": "libmysqlclient/8.0.25",
                "name": "libmysqlclient",
                "version": "8.0.25",
                "user": None,
                "channel": None,
                "severity_l": "WARN",
                "severity": None,
                "info": "requirement openssl/1.1.1m overridden by poco/1.11.1 to openssl/1.1.1l",
            },
        ],
        id="conan",
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
