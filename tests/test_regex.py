import pytest

from conmon.__main__ import ConanParser
from conmon.compilers import COMPILER_REGEX_MAP
from textwrap import dedent

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
    match = ConanParser.REF_REGEX.fullmatch(expected["ref"])
    assert match is not None
    assert match.groupdict() == expected


@pytest.mark.parametrize("expected", invalid_refs)
def test_ref_regex_nok(expected):
    expected[
        "ref"
    ] = f"{expected['name']}/{expected['version']}@{expected['user']}/{expected['channel']}"
    match = ConanParser.REF_REGEX.fullmatch(expected["ref"])
    assert match is None


def test_cmake_warning_regex():
    log = """
    -- Configuring done
    CMake Warning:
      Manually-specified variables were not used by the project:
        CMAKE_EXPORT_NO_PACKAGE_REGISTRY
    -- 
    CMake Warning at CMakeLists.txt:
      some warning text
    -- 
    CMake Warning at CMakeLists.txt:9 (message):
      some warning text
    -- continue
    """
    match = list(COMPILER_REGEX_MAP["cmake"].finditer(dedent(log)))
    assert len(match) == 3

    assert match[0].group("severity") == "Warning"
    assert match[0].group("file") is None
    assert match[0].group("function") is None
    assert match[0].group("line") is None
    assert match[0].group("info").startswith("  Manually-specified variables")

    assert match[1].group("severity") == "Warning"
    assert match[1].group("file") == "CMakeLists.txt"
    assert match[1].group("function") is None
    assert match[1].group("line") is None
    assert match[1].group("info") == "  some warning text\n"

    assert match[2].group("severity") == "Warning"
    assert match[2].group("file") == "CMakeLists.txt"
    assert match[2].group("function") == "message"
    assert match[2].group("line") == "9"
    assert match[2].group("info") == "  some warning text\n"


def test_cmake_warning_regex_multiline():
    log = """
    CMake Warning:
      Manually-specified variables were not used by the project:
    
        CMAKE_EXPORT_NO_PACKAGE_REGISTRY
        CMAKE_INSTALL_BINDIR
        CMAKE_INSTALL_DATAROOTDIR
        CMAKE_INSTALL_INCLUDEDIR
        CMAKE_INSTALL_LIBDIR
        CMAKE_INSTALL_LIBEXECDIR
        CMAKE_INSTALL_OLDINCLUDEDIR
        MAKE_INSTALL_SBINDIR
        
        
    """
    regex = COMPILER_REGEX_MAP["cmake"]
    error_string = dedent(log)
    match = list(regex.finditer(error_string))
    assert len(match) == 1
    info = "\n".join(error_string.splitlines()[2:-1])
    expected = dict(severity="Warning", file=None, line=None, info=info)
    err_match = {
        key: match[0].group(key) for key in set(expected) & set(regex.groupindex)
    }
    assert expected == err_match
