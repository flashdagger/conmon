import re
from pathlib import Path

import pytest
import conmon.regex

from conmon.regex import (
    CMAKE_BUILD_PATH_REGEX,
    REF_REGEX,
    shorten_conan_path,
)

valid_refs = [
    dict(name="my-package", version="version", user="user", channel="channel"),
    dict(name="My_Package", version="1.2.3+", user=None, channel=None),
]

invalid_refs = [
    dict(name="-mypackage", version="version", user="user", channel="channel"),
    dict(name="mypackage", version="1", user="user", channel="channel"),
]


output = [
    "Microsoft (R) Build Engine version 17.1.0+ae57d105c for .NET Framework",
    "Copyright (C) Microsoft Corporation. All rights reserved.",
    "  Checking Build System",
    "  Building Custom Rule C:/conan/data/zlib/1.2.12/_/_/build/"
    "5a61a86bb3e07ce4262c80e1510f9c05e9b6d48b/src/CMakeLists.txt",
    "  adler32.c",
    "[3/16] Building C object CMakeFiles\\zlib.dir\\gzclose.c.obj",
    "[ 93%] Building C object CMakeFiles/zlib.dir/zutil.c.obj",
    "[100%] Linking C static library libz.a",
    "[100%] Built target zlib",
    "make[1]: Entering directory '/c/conan/data/openssl/1.1.1m/_/_/build/"
    "66a17af0d813c047a4915019b905badff163123c/source_subfolder'",
    "/c/conan/data/mingw-builds/11.2.0/_/_/package/6903a9d1b48b06f7fbe0929db654512c77e6cc32/"
    "bin/gcc.exe  -I. -Iinclude -m64 -m64 -O3 -s -Wall -O3 -DL_ENDIAN -DOPENSSL_PIC "
    "-DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 "
    "-DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM "
    "-DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM "
    '-DOPENSSLDIR="\\"/c/conan/data/openssl/1.1.1m/_/_/package/'
    '66a17af0d813c047a4915019b905badff163123c/res\\"" -DENGINESDIR="\\"/c/conan/data/openssl/'
    '1.1.1m/_/_/package/66a17af0d813c047a4915019b905badff163123c/lib/engines-1_1\\"" '
    "-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_MT -DNDEBUG -DNDEBUG "
    "-IC:/conan/data/mingw-builds/11.2.0/_/_/package/6903a9d1b48b06f7fbe0929db654512c77e6cc32/"
    "include  -MMD -MF apps/app_rand.d.tmp -MT apps/app_rand.o -c "
    "-o apps/app_rand.o apps/app_rand.c",
    "  CC       libmisc/walk_tree.lo",
    "  CCLD     libacl.la",
    "  CCLD     chacl",
]
dataset = [
    pytest.param(
        [
            ("", "adler32.c"),
            ("[3/16]", "CMakeFiles\\zlib.dir\\gzclose.c.obj"),
            ("[ 93%]", "CMakeFiles/zlib.dir/zutil.c.obj"),
            ("[100%]", "libz.a"),
            ("", "apps/app_rand.c"),
            ("  CC", "libmisc/walk_tree.lo"),
            ("  CCLD", "libacl.la"),
        ],
        id="BUILD_STATUS_REGEX",
    ),
]


@pytest.mark.parametrize("expected", dataset)
def test_build_status_regex(expected, request):
    regex_name = request.node.callspec.id
    regex = getattr(conmon.regex, regex_name, None)
    assert isinstance(regex, type(re.compile(""))), f"invalid regex {regex_name!r}"
    pattern, flags = conmon.regex.compact_pattern(regex)
    matches = list(
        match_tuple
        for match_tuple in re.findall(
            pattern, "\n".join(output), flags=flags | re.MULTILINE
        )
    )
    # matches are tuples of (status, file)
    assert matches == expected


@pytest.mark.parametrize("expected", valid_refs)
def test_ref_regex_ok(expected):
    ref = f"{expected['name']}/{expected['version']}@"
    if expected["user"]:
        ref = ref + expected["user"]
    if expected["channel"]:
        ref = ref + "/" + expected["channel"]
    expected["ref"] = ref
    match = REF_REGEX.fullmatch(expected["ref"])
    assert match is not None
    assert match.groupdict() == expected


@pytest.mark.parametrize("expected", invalid_refs)
def test_ref_regex_nok(expected):
    expected[
        "ref"
    ] = f"{expected['name']}/{expected['version']}@{expected['user']}/{expected['channel']}"
    match = REF_REGEX.fullmatch(expected["ref"])
    assert match is None


paths = [
    ("", ""),
    (
        "/home/user/.conan/data/libmysqlclient/8.0.25/_/_/build/"
        "3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12/libmysql/api_test.c",
        ".../libmysql/api_test.c",
    ),
    (
        "C:/home/user/.conan/data/libmysqlclient/8.0.25/_/_/package/"
        "3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12/libmysql/api_test.c",
        ".../libmysql/api_test.c",
    ),
    (
        r"c:\home\user\.conan\data\libmysqlclient\8.0.25\_\_\package"
        r"\3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12\libmysql\api_test.c",
        r"...\libmysql\api_test.c",
    ),
    (
        "path is too short /libmysqlclient/8.0.25/_/_/build/"
        "3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12/libmysql/api_test.c",
        "path is too short /libmysqlclient/8.0.25/_/_/build/"
        "3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12/libmysql/api_test.c",
    ),
    (
        "[ 99%] Linking CXX static library /home/user/.conan/data/libmysqlclient/8.0.25/_/_/"
        "build/3b926ebe4e4bf1b03a5d7d9151eabdcd92583a12/libmysql/api_test.c",
        "[ 99%] Linking CXX static library .../libmysql/api_test.c",
    ),
]


@pytest.mark.parametrize("path_pair", paths)
def test_shorten_conan_data_path(path_pair):
    path, expected = path_pair
    assert shorten_conan_path(path) == expected


cmake_build_path = [
    Path("site-packages/cmake/data/share/cmake-3.25/Modules/CMakeCCompilerABI.c"),
    Path("CMakeFiles\\ShowIncludes\\main.c"),
    Path("Release/CMakeFiles/3.25.0/CompilerIdC"),
    Path("Release/CMakeFiles/CMakeScratch/TryCompile-MSORCG/CheckIncludeFile.c"),
    Path("CMakeFiles/CMakeTmp/check_crypto_md.c"),
    Path("Release/CMakeFiles/_CMakeLTOTest-CXX/src/foo.cpp"),
]


@pytest.mark.parametrize("path", cmake_build_path)
def test_cmake_build_path_regex(path):
    match = CMAKE_BUILD_PATH_REGEX.search(path.as_posix())
    assert match, f"{path!r} did not match"
