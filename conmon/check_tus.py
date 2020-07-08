import json
import re
import sys
from collections import Counter
from pathlib import Path
from pprint import pprint

from .__main__ import REPORT_JSON
from .compilers import parse_warnings


def parse_build(key, lines):
    files = set()
    if not lines:
        return files
    print("-->", key)
    for line in lines:
        match = re.match(r".*?([.\w/\\-]+(\.[a-z]{1,3})+)([^\w(]|$)", line)
        if not match:
            continue
        file = Path(match.group(1))
        suffix = file.suffixes[0]
        name, *_ = file.name.split(".", maxsplit=1)
        if suffix == ".obj":
            suffix = ".c"
        if suffix in {".c", ".cpp", ".cxx"}:
            files.add(name + suffix)
    return files


def check(report):
    files = set()
    files.update(parse_build(report["ref"], report["build"]))

    t_units = set()
    for t_unit in report["translation_units"]:
        t_units.update(set(t_unit["sources"]))

    found = 0
    missing = 0

    for file in files:
        path = Path(file)
        for t_unit in set(t_units):
            tu_path = Path(t_unit)
            if path.name == tu_path.name:
                found += 1
                t_units.remove(t_unit)
                break
        else:
            print("missing", file)
            missing += 1

    print("total", len(files), "found", found, "missing", missing)
    print("residue", len(t_units))


def check_warnings(report):
    result = parse_warnings("\n".join(report["build"]), "gnu")
    stats = Counter((mapping.get("category") for mapping in result))
    pprint(stats)


def main():
    if sys.argv[1:]:
        json_file = Path(sys.argv[1])
    else:
        json_file = REPORT_JSON

    with json_file.open() as fh:
        report = json.load(fh)

    for key, value in report.get("requirements", {}).items():
        if "build" not in value:
            continue
        print(key.upper())
        print("=" * len(key))
        check(value)
        # check_warnings(value)
        print()


if __name__ == "__main__":
    main()
