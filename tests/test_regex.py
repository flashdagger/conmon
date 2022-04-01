import pytest

from conmon.regex import shorten_conan_path, REF_REGEX

valid_refs = [
    dict(name="my-package", version="version", user="user", channel="channel"),
    dict(name="My_Package", version="1.2.3+", user=None, channel=None),
]

invalid_refs = [
    dict(name="-mypackage", version="version", user="user", channel="channel"),
    dict(name="mypackage", version="1", user="user", channel="channel"),
]


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
