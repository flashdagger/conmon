import json
import sys
from collections import defaultdict
from difflib import ndiff
from pathlib import Path
from pprint import pformat


def show_diff(key, a, b):
    print(f"* {key}:")
    text_a = pformat(a, width=80, indent=1, compact=False)
    text_b = pformat(b, width=80, indent=1, compact=False)
    for line in ndiff(text_a.splitlines(), text_b.splitlines()):
        if not line or line.startswith(" "):
            continue
        print(line.rstrip())


def show_changes(*tu):
    assert len(tu) > 1

    for key in tu[0]:
        a = tu[0][key]

        for idx in range(1, len(tu)):
            b = tu[idx].get(key, type(a)())
            if a != b:
                show_diff(f"{key} 0<>{idx}", a, b)
    print()


def assert_uninque(lib, check_data):
    for source, tus in check_data.items():
        assert tus
        if len(tus) == 1:
            continue
        if tus[0] == tus[1]:
            continue

        msg = f"{lib}: {Path(*source.parts[-3:])} x{len(tus)}"
        if __name__ == "__main__":
            print(msg)
            show_changes(*tus)
        else:
            assert tus[0] == tus[1], msg


def test_main(path="./report.json"):
    with open(path) as fd:
        info = json.load(fd)

    for lib, data in info["requirements"].items():
        tus = data.get("translation_units")
        if not tus:
            continue

        check_data = {}
        for tu in tus:
            for source in tu.pop("sources", ()):
                check_data.setdefault(Path(source), []).append(tu)

        assert_uninque(lib, check_data)
        count_map = defaultdict(int)
        for value in check_data.values():
            count_map[len(value)] += 1

        print(
            ", ".join(
                f"{value} unique files in {key} unit(s)"
                for key, value in sorted(count_map.items())
            ),
        )


if __name__ == "__main__":
    test_main(*sys.argv[1:2])
