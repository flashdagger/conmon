from conmon.__main__ import Requirements


def test_regex():
    line = (
        "     openssl/3.2.1#c7b554068caae5eda12b735ea6f23d70"
        ":3593751651824fb813502c69c971267624ced41a"
        "#60e6fc0f973babfbed66a66af22a4f02 - Downloaded (conancenter)"
    )
    match = Requirements.REGEX.match(line)
    assert match is not None
    print(match.groupdict())
