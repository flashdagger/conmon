import pytest

from conmon.__main__ import ConanParser

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
