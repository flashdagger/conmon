#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import re

import pytest

from conmon.warnings import Regex

output = [
    "src/main/src/Em_FilteringQmFu.c: In function "
    "\u2018Em_FilteringQmFu_processSensorSignals\u2019:",
    "src/main/src/Em_FilteringQmFu.c:266:5: warning: implicit declaration of function "
    "\u2018memset\u2019 [-Wimplicit-function-declaration]",
    "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));",
    "     ^~~~~~",
    "C:\\source_subfolder\\source\\common\\x86\\seaintegral.asm:92: warning: improperly calling "
    "multi-line macro `SETUP_STACK_POINTER' with 0 parameters [-w+macro-params-legacy]",
    "some text",
    "In file included from C:\\conan\\data\\source_subfolder\\zutil.c:10:",
    "C:\\conan\\data\\source_subfolder/gzguts.h(146,52): warning: extension used "
    "[-Wlanguage-extension-token]",
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
    "C:\\source_subfolder\\bzlib.c(1418,10): warning C4996: 'strcat': This function or variable "
    "may be unsafe. Consider using strcat_s instead. To disable deprecation, use "
    "_CRT_SECURE_NO_WARNINGS. See online help for details.",
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
    "CMake Warning (dev) at libmysql/authentication_ldap/CMakeLists.txt:30 (MESSAGE):",
    "  Skipping the LDAP client authentication plugin",
    "This warning is for project developers.  Use -Wno-dev to suppress it.",
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
    "CMake Warning:",
    "  Manually-specified variables were not used by the project:",
    "",
    "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY",
    "    CMAKE_INSTALL_BINDIR",
    "    CMAKE_INSTALL_DATAROOTDIR",
    "    CMAKE_INSTALL_INCLUDEDIR",
    "    CMAKE_INSTALL_LIBDIR",
    "    CMAKE_INSTALL_LIBEXECDIR",
    "    CMAKE_INSTALL_OLDINCLUDEDIR",
    "    MAKE_INSTALL_SBINDIR",
    "",
    "",
    "source_subfolder/src/tramp.c:215:52: warning: format \u2018%ld\u2019 expects argument of type "
    "\u2018long int *\u2019, but argument 8 has type \u2018long unsigned int *\u2019 [-Wformat=]",
    '  215 |     nfields = sscanf (line, "%lx-%lx %9s %lx %9s %ld %s",',
    "      |                                                  ~~^",
    "      |                                                    |",
    "      |                                                    long int *",
    "      |                                                  %ld",
    "  216 |       &start, &end, perm, &offset, dev, &inode, file);",
    "      |                                         ~~~~~~",
    "      |                                         |",
    "      |                                         long unsigned int *",
    "In file included from ../../src/include/postgres.h:47,",
    "                 from rmtree.c:15:",
    "rmtree.c: In function \u2018rmtree\u2019:",
    "In file included from ../../src/include/c.h:54,",
    "                 from ../../src/include/postgres.h:46,",
    "                 from stringinfo.c:20:",
    "../../src/include/pg_config.h:772:24: warning: ISO C does not support \u2018__int128\u2019 "
    "types [-Wpedantic]",
    "C:\\src\\bzlib.c(161) : note: index 'blockSize100k' range checked by comparison on this line",
    "ebcdic.c:284: warning: ISO C forbids an empty translation unit [-Wpedantic]",
    "  284 | #endif",
    "      | ",
    "WARNING: this is important",
    "warning: Boost.Build engine (b2) is 4.8.0",
    "./src/graph.cc: In member function \u2018void Edge::Dump(const char*) const\u2019:",
    "./src/graph.cc:409:16: warning: format \u2018%p\u2019 expects argument of type "
    "\u2018void*\u2019, but argument 2 has type \u2018const Edge*\u2019 [-Wformat=]",
    '  409 |   printf("] 0x%p\\n", this);',
    "      |               ~^",
    "      |                |",
    "      |                void*",
    "ninja/1.9.0 (test package): WARN: This conanfile has no build step",
    "src/port/pg_crc32c_sse42_choose.c(41,10): warning : passing 'unsigned int [4]' to "
    "parameter of type 'int *' converts between pointers to integer types with different sign "
    "[-Wpointer-sign] [C:\\conan\\source_subfolder\\libpgport.vcxproj]",
    "NMAKE : fatal error U1077: 'C:\\Users\\marcel\\applications\\LLVM\\bin\\clang-cl.EXE' : "
    "return code '0x1'",
    "clang-cl: warning: /: 'linker' input unused [-Wunused-command-line-argument]",
    "In file included from crypto\\asn1\\a_sign.c:22:",
    "In file included from include\\crypto/evp.h:11:",
    "In file included from include\\internal/refcount.h:21:",
    "In file included from C:\\Users\\LLVM\\lib\\clang\\13.0.1\\include\\stdatomic.h:17:",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\include\\stdatomic.h(15,2): "
    "error: <stdatomic.h> is not yet supported when compiling as C",
    "#error <stdatomic.h> is not yet supported when compiling as C",
    " ^",
    "C:\\conan\\source_subfolder\\Crypto\\src\\OpenSSLInitializer.cpp(35,10): "
    "warning: OpenSSL 1.1.1l  24 Aug 2021 [-W#pragma-messages]",
    "        #pragma message (OPENSSL_VERSION_TEXT POCO_INTERNAL_OPENSSL_BUILD)",
    "                ^",
    "source_subfolder/meson.build:1559:2: ERROR: Problem encountered: "
    "Could not determine size of size_t.",
    'CMake Error: CMake was unable to find a build program corresponding to "MinGW Makefiles".  '
    "CMAKE_MAKE_PROGRAM is not set.  You probably need to select a different build tool.",
    "CMake Deprecation Warning at CMakeLists.txt:78 (CMAKE_MINIMUM_REQUIRED):",
    "  Compatibility with CMake < 2.8.12 will be removed from a future version of",
    "  CMake.",
    "",
    "  Update the VERSION argument <min> value or use a ...<max> suffix to tell",
    "  CMake that the project does not need compatibility with older versions.",
    "",
    "",
    "source_subfolder/locks/unix/proc_mutex.c: At top level:",
    'source_subfolder/locks/unix/proc_mutex.c:932:5: warning: this use of "defined" may not be portable [-Wexpansion-to-defined]',
    "  932 | #if APR_USE_PROC_PTHREAD_MUTEX_COND",
    "      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
    "In file included from /usr/include/string.h:495,",
    "                 from /src/share/grabbag/picture.c:29:",
    "In function \u2018strncpy\u2019,",
    "    inlined from \u2018grabbag__picture_from_specification\u2019 at /src/include/share/safe_str.h:63:8:",
    "/usr/include/x86_64-linux-gnu/bits/string_fortified.h:106:10: warning: \u2018__builtin_strncpy\u2019 specified bound 64 equals destination size [-Wstringop-truncation]",
    "  106 |   return __builtin___strncpy_chk (__dest, __src, __len, __bos (__dest));",
    "      |          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
    "In file included from source_subfolder/vp9/ratectrl_rtc.cc:10:",
    "In file included from source_subfolder/vp9/ratectrl_rtc.h:19:",
    "source_subfolder/vp9/common/vp9_onyxc_int.h:316:51: warning: zero as null pointer constant [-Wzero-as-null-pointer-constant]",
    "  if (index < 0 || index >= FRAME_BUFFERS) return NULL;",
    "                                                  ^~~~",
    "                                                  nullptr",
    "cl : Command line warning D9002 : ignoring unknown option '/diagnostics:caret/Wall'",
    "",
]
dataset = [
    pytest.param(
        [
            {
                "context": "src/main/src/Em_FilteringQmFu.c: In function "
                "‘Em_FilteringQmFu_processSensorSignals’:\n",
                "file": "src/main/src/Em_FilteringQmFu.c",
                "line": "266",
                "column": "5",
                "severity": "warning",
                "info": "implicit declaration of function ‘memset’",
                "category": "-Wimplicit-function-declaration",
                "project": None,
                "hint": ""
                "     memset(&reicevedSignals, 0, sizeof(reicevedSignals));\n"
                "     ^~~~~~\n",
            },
            {
                "context": None,
                "file": "C:\\source_subfolder\\source\\common\\x86\\seaintegral.asm",
                "line": "92",
                "column": None,
                "severity": "warning",
                "info": ""
                "improperly calling multi-line macro `SETUP_STACK_POINTER' with 0 parameters",
                "category": "-w+macro-params-legacy",
                "project": None,
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
                "project": None,
                "hint": ""
                "ZEXTERN z_off64_t ZEXPORT gzseek64 OF((gzFile, z_off64_t, int));\n"
                "                                               ^\n",
            },
            {
                "context": "/build/source_subfolder/bzip2.c: In function "
                "‘applySavedFileAttrToOutputFile’:\n",
                "file": "/build/source_subfolder/bzip2.c",
                "line": "1073",
                "column": "11",
                "severity": "warning",
                "info": ""
                "ignoring return value of ‘fchown’, declared with attribute warn_unused_result",
                "category": "-Wunused-result",
                "project": None,
                "hint": ""
                " 1073 |    (void) fchown ( fd, fileMetaInfo.st_uid, fileMetaInfo.st_gid );\n"
                "      |           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
            },
            {
                "context": None,
                "file": "/source_subfolder/src/constexp.y",
                "line": "35",
                "column": "1-25",
                "severity": "warning",
                "info": 'deprecated directive: ‘%name-prefix "constexpYY"’, use ‘%define '
                "api.prefix {constexpYY}’",
                "category": "-Wdeprecated",
                "project": None,
                "hint": ""
                '   35 | %name-prefix "constexpYY"\n'
                "      | ^~~~~~~~~~~~~~~~~~~~~~~~~      | %define api.prefix {constexpYY}\n",
            },
            {
                "context": None,
                "file": "/source_subfolder/src/constexp.y",
                "line": None,
                "column": None,
                "severity": "warning",
                "info": "fix-its can be applied.  Rerun with option '--update'.",
                "category": "-Wother",
                "project": None,
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
                "info": "ISO C does not support ‘__int128’ types",
                "category": "-Wpedantic",
                "project": None,
                "hint": ""
                "  772 | #define PG_INT128_TYPE __int128\n"
                "      |                        ^~~~~~~~\n",
            },
            {
                "context": ""
                "In file included from /package/include/glib-2.0/gobject/gobject.h:24,\n"
                "                 from /package/include/glib-2.0/gobject/gbinding.h:29,\n"
                "                 from /package/include/glib-2.0/glib-object.h:22,\n"
                "                 from ../source_subfolder/atk/atkobject.h:27,\n"
                "                 from ../source_subfolder/atk/atk.h:25,\n"
                "                 from ../source_subfolder/atk/atktext.c:22:\n"
                "../source_subfolder/atk/atktext.c: In function "
                "\u2018atk_text_range_get_type_once\u2019:\n",
                "file": "../source_subfolder/atk/atktext.c",
                "line": "1640",
                "column": "52",
                "severity": "warning",
                "info": "ISO C prohibits argument conversion to union type",
                "category": "-Wpedantic",
                "project": None,
                "hint": ""
                " 1640 | G_DEFINE_BOXED_TYPE (AtkTextRange, atk_text_range, atk_text_range_copy,\n"
                "      |                                                    ^~~~~~~~~~~~~~~~~~~\n",
            },
            {
                "context": None,
                "file": "source_subfolder/src/tramp.c",
                "line": "215",
                "column": "52",
                "severity": "warning",
                "info": "format ‘%ld’ expects argument of type ‘long int *’, but argument 8 "
                "has type ‘long unsigned int *’",
                "category": "-Wformat=",
                "project": None,
                "hint": ""
                '  215 |     nfields = sscanf (line, "%lx-%lx %9s %lx %9s %ld %s",\n'
                "      |                                                  ~~^\n"
                "      |                                                    |\n"
                "      |                                                    long int *\n"
                "      |                                                  %ld\n"
                "  216 |       &start, &end, perm, &offset, dev, &inode, file);\n"
                "      |                                         ~~~~~~\n"
                "      |                                         |\n"
                "      |                                         long unsigned int *\n",
            },
            {
                "context": ""
                "In file included from ../../src/include/postgres.h:47,\n"
                "                 from rmtree.c:15:\n"
                "rmtree.c: In function ‘rmtree’:\n"
                "In file included from ../../src/include/c.h:54,\n"
                "                 from ../../src/include/postgres.h:46,\n"
                "                 from stringinfo.c:20:\n",
                "file": "../../src/include/pg_config.h",
                "line": "772",
                "column": "24",
                "severity": "warning",
                "info": "ISO C does not support ‘__int128’ types",
                "category": "-Wpedantic",
                "project": None,
                "hint": None,
            },
            {
                "context": None,
                "file": "C:\\src\\bzlib.c",
                "line": "161",
                "column": None,
                "severity": "note",
                "category": None,
                "project": None,
                "info": "index 'blockSize100k' range checked by comparison on this line",
                "hint": None,
            },
            {
                "context": None,
                "file": "ebcdic.c",
                "line": "284",
                "column": None,
                "severity": "warning",
                "info": "ISO C forbids an empty translation unit",
                "category": "-Wpedantic",
                "project": None,
                "hint": "  284 | #endif\n      | \n",
            },
            {
                "context": "./src/graph.cc: In member function "
                "\u2018void Edge::Dump(const char*) const\u2019:\n",
                "file": "./src/graph.cc",
                "line": "409",
                "column": "16",
                "severity": "warning",
                "info": ""
                "format ‘%p’ expects argument of type ‘void*’, "
                "but argument 2 has type ‘const Edge*’",
                "category": "-Wformat=",
                "project": None,
                "hint": ""
                '  409 |   printf("] 0x%p\\n", this);\n'
                "      |               ~^\n"
                "      |                |\n"
                "      |                void*\n",
            },
            {
                "context": None,
                "file": "src/port/pg_crc32c_sse42_choose.c",
                "line": "41",
                "column": "10",
                "severity": "warning",
                "info": "passing 'unsigned int [4]' to parameter of type 'int *' converts "
                "between pointers to integer types with different sign",
                "category": "-Wpointer-sign",
                "project": "C:\\conan\\source_subfolder\\libpgport.vcxproj",
                "hint": None,
            },
            {
                "context": None,
                "file": "clang-cl",
                "severity": "warning",
                "info": "/: 'linker' input unused",
                "category": "-Wunused-command-line-argument",
                "line": None,
                "column": None,
                "project": None,
                "hint": None,
            },
            {
                "context": "In file included from crypto\\asn1\\a_sign.c:22:\n"
                "In file included from include\\crypto/evp.h:11:\n"
                "In file included from include\\internal/refcount.h:21:\n"
                "In file included from "
                "C:\\Users\\LLVM\\lib\\clang\\13.0.1\\include\\stdatomic.h:17:\n",
                "file": "C:\\Program Files (x86)\\Microsoft Visual Studio\\include\\stdatomic.h",
                "line": "15",
                "column": "2",
                "severity": "error",
                "category": None,
                "info": "<stdatomic.h> is not yet supported when compiling as C",
                "hint": "#error <stdatomic.h> is not yet supported when compiling as C\n ^\n",
                "project": None,
            },
            {
                "context": None,
                "file": "C:\\conan\\source_subfolder\\Crypto\\src\\OpenSSLInitializer.cpp",
                "line": "35",
                "column": "10",
                "severity": "warning",
                "info": "OpenSSL 1.1.1l  24 Aug 2021",
                "category": "-W#pragma-messages",
                "project": None,
                "hint": "        #pragma message (OPENSSL_VERSION_TEXT "
                "POCO_INTERNAL_OPENSSL_BUILD)\n"
                "                ^\n",
            },
            {
                "context": None,
                "file": "source_subfolder/meson.build",
                "line": "1559",
                "column": "2",
                "severity": "ERROR",
                "category": None,
                "info": "Problem encountered: Could not determine size of size_t.",
                "project": None,
                "hint": None,
            },
            {
                "category": "-Wexpansion-to-defined",
                "column": "5",
                "context": "source_subfolder/locks/unix/proc_mutex.c: At top level:\n",
                "file": "source_subfolder/locks/unix/proc_mutex.c",
                "hint": "  932 | #if APR_USE_PROC_PTHREAD_MUTEX_COND\n"
                "      |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
                "info": 'this use of "defined" may not be portable',
                "line": "932",
                "project": None,
                "severity": "warning",
            },
            {
                "category": "-Wstringop-truncation",
                "column": "10",
                "context": ""
                "In file included from /usr/include/string.h:495,\n"
                "                 from /src/share/grabbag/picture.c:29:\n"
                "In function \u2018strncpy\u2019,\n"
                "    inlined from \u2018grabbag__picture_from_specification\u2019 at "
                "/src/include/share/safe_str.h:63:8:\n",
                "file": "/usr/include/x86_64-linux-gnu/bits/string_fortified.h",
                "hint": "  106 |   return __builtin___strncpy_chk (__dest, __src, __len, "
                "__bos (__dest));\n"
                "      |          "
                "^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
                "info": "‘__builtin_strncpy’ specified bound 64 equals destination size",
                "line": "106",
                "project": None,
                "severity": "warning",
            },
            {
                "category": "-Wzero-as-null-pointer-constant",
                "column": "51",
                "context": "In file included from source_subfolder/vp9/ratectrl_rtc.cc:10:\n"
                "In file included from source_subfolder/vp9/ratectrl_rtc.h:19:\n",
                "file": "source_subfolder/vp9/common/vp9_onyxc_int.h",
                "hint": "  if (index < 0 || index >= FRAME_BUFFERS) return NULL;\n"
                "                                                  ^~~~\n"
                "                                                  nullptr\n",
                "info": "zero as null pointer constant",
                "line": "316",
                "project": None,
                "severity": "warning",
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
                "hint": '   strcat(mode2,"b");   /* binary mode */\n         ^\n',
            },
            {
                "file": "NMAKE",
                "line": None,
                "column": None,
                "severity": "fatal error",
                "category": "U1077",
                "info": "'C:\\Users\\marcel\\applications\\LLVM\\bin\\clang-cl.EXE' : "
                "return code '0x1'",
                "project": None,
                "hint": None,
            },
            {
                "file": "cl",
                "line": None,
                "column": None,
                "severity": "Command line warning",
                "category": "D9002",
                "info": "ignoring unknown option '/diagnostics:caret/Wall'",
                "project": None,
                "hint": None,
            },
        ],
        id="msvc",
    ),
    pytest.param(
        [
            {
                "severity": "Warning",
                "file": None,
                "line": None,
                "function": None,
                "info": ""
                "Manually-specified variables were not used by the project:\n\n"
                "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY\n",
                "context": None,
            },
            {
                "severity": "Warning",
                "file": "cmake/ldap.cmake",
                "line": "158",
                "function": "MESSAGE",
                "info": "Could not find LDAP\n",
                "context": ""
                "Call Stack (most recent call first):\n"
                "  CMakeListsOriginal.txt:1351 (MYSQL_CHECK_LDAP)\n"
                "  CMakeLists.txt:7 (include)\n",
            },
            {
                "severity": "Warning",
                "file": "libmysql/authentication_ldap/CMakeLists.txt",
                "line": "30",
                "function": "MESSAGE",
                "info": "Skipping the LDAP client authentication plugin\n",
                "context": None,
            },
            {
                "severity": "Warning",
                "file": None,
                "line": None,
                "function": None,
                "info": ""
                "Manually-specified variables were not used by the project:\n\n"
                "    CMAKE_EXPORT_NO_PACKAGE_REGISTRY\n"
                "    CMAKE_INSTALL_BINDIR\n"
                "    CMAKE_INSTALL_DATAROOTDIR\n"
                "    CMAKE_INSTALL_INCLUDEDIR\n"
                "    CMAKE_INSTALL_LIBDIR\n"
                "    CMAKE_INSTALL_LIBEXECDIR\n"
                "    CMAKE_INSTALL_OLDINCLUDEDIR\n"
                "    MAKE_INSTALL_SBINDIR\n",
                "context": None,
            },
            {
                "severity": "Error",
                "file": None,
                "line": None,
                "function": None,
                "info": ""
                'CMake was unable to find a build program corresponding to "MinGW Makefiles".  '
                "CMAKE_MAKE_PROGRAM is not set.  You probably need to select"
                " a different build tool.\n",
                "context": None,
            },
            {
                "severity": "Deprecation Warning",
                "file": "CMakeLists.txt",
                "line": "78",
                "function": "CMAKE_MINIMUM_REQUIRED",
                "info": ""
                "Compatibility with CMake < 2.8.12 will be removed from a future version of\n"
                "  CMake.\n\n"
                "  Update the VERSION argument <min> value or use a ...<max> suffix to tell\n"
                "  CMake that the project does not need compatibility with older versions.\n",
                "context": None,
            },
        ],
        id="cmake",
    ),
    pytest.param(
        [
            {
                "from": "Makefile.config",
                "info": "No sys/sdt.h found, no SDT events are defined, please install "
                "systemtap-sdt-devel or systemtap-sdt-dev\n",
                "line": "565",
                "severity": None,
            },
            {
                "from": "configure",
                "line": None,
                "severity": "WARNING",
                "info": "\n"
                "*** Without Bison you will not be able to build PostgreSQL from Git nor\n"
                "*** change any of the parser definition files.  You can obtain Bison from\n"
                "*** a GNU mirror site.  (If you are using the official distribution of\n"
                "*** PostgreSQL then you do not need to worry about this, because the Bison\n"
                "*** output is pre-generated.)\n",
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
            {
                "channel": None,
                "info": "this is important",
                "name": None,
                "ref": None,
                "severity": None,
                "severity_l": "WARNING",
                "user": None,
                "version": None,
            },
            {
                "severity_l": None,
                "ref": "ninja/1.9.0",
                "name": "ninja",
                "version": "1.9.0",
                "channel": None,
                "user": None,
                "info": "This conanfile has no build step",
                "severity": "WARN",
            },
        ],
        id="conan",
    ),
    pytest.param(
        [
            {
                "severity": "warning",
                "info": "Boost.Build engine (b2) is 4.8.0\n",
            },
        ],
        id="build",
    ),
]


@pytest.mark.parametrize("expected", dataset)
def test_warnings_regex(expected, request):
    compiler = request.node.callspec.id
    matches = list(
        match.groupdict()
        for match in re.finditer(Regex.get(compiler), "\n".join(output))
    )
    assert matches == expected
