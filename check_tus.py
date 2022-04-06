import json
import sys
from collections import defaultdict
from difflib import ndiff
from pathlib import Path
from pprint import pformat
from typing import List

from conmon.utils import shorten


def show_diff(key, obj_a, obj_b) -> List[str]:
    lines = [f">>> {key}:"]
    width = 1 if any(len(str(obj)) for obj in (obj_a, obj_b)) else 120
    indent = 2
    text_a = pformat(obj_a, width=width, indent=indent, compact=False)
    text_b = pformat(obj_b, width=width, indent=indent, compact=False)
    if len(text_a) > 1:
        for find, replace in (("[", "[\n "), ("]", ",\n ]")):
            text_a = text_a.replace(find, replace)
            text_b = text_b.replace(find, replace)
    for line in ndiff(text_a.splitlines(), text_b.splitlines()):
        # if not line or line.startswith(" "):
        #    continue
        lines.append(line.rstrip())

    return lines


def show_changes(*tu) -> str:
    assert len(tu) > 1

    lines = []
    for key in tu[0]:
        obj_a = tu[0][key]

        for idx in range(1, len(tu)):
            obj_b = tu[idx].get(key, type(obj_a)())
            if obj_a != obj_b:
                lines.extend(show_diff(f"{key} 0<>{idx}", obj_a, obj_b))

    return "\n".join(lines)


def assert_unique(lib, check_data):
    diffs = {}

    for source, tus in check_data.items():
        assert tus
        if len(tus) == 1:
            continue
        if tus[0] == tus[1]:
            continue

        diffs.setdefault(show_changes(*tus), []).append(
            Path(*source.parts[-3:]).as_posix()
        )

    print("lib:", lib)
    for key, value in diffs.items():
        files = ", ".join(sorted(value))
        print(
            shorten(files, width=250, template=f"{{}} (x{len(value)})", strip="middle")
        )
        print(key)
        print()


def test_main(path="./report.json"):
    with open(path, encoding="utf8") as fp:
        info = json.load(fp)

    json_map = {}
    for lib, data in info["requirements"].items():
        tus = data.get("build", {}).get("translation_units")
        if not tus:
            continue

        check_data = {}
        for unit in tus:
            for source in unit.pop("sources", ()):
                check_data.setdefault(Path(source), []).append(unit)

        assert_unique(lib, check_data)
        count_map = defaultdict(int)
        for value in check_data.values():
            count_map[len(value)] += 1

        print(
            ", ".join(
                f"{value} unique files in {key} unit(s)"
                for key, value in sorted(count_map.items())
            ),
        )
        json_map[lib] = list(str(p) for p in sorted(check_data.keys()))

    with Path(path).with_suffix(".src.json").open("w", encoding="utf8") as fp:
        json.dump(json_map, fp, indent=4)


if __name__ == "__main__":
    test_main(*sys.argv[1:2])
