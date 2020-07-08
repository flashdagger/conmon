import json
import re
import sys
from pathlib import Path


def parse_build(key, lines):
    files = set()
    if not lines:
        return files
    print("-->", key)
    for line in lines:
        match = re.match(r".*?([\w/\\-]+\.c[cxp]*)([^\w(]|$)", line)
        if not match:
            continue
        file = Path(match.group(1))
        if file.parent.name.endswith(".dir"):
            file = file.parent.parent / file.name
        files.add(file.name)
    return files


def check(report):
    files = set()
    files.update(parse_build(report["ref"], report["build"]))

    tus = set()
    for tu in report["translation_units"]:
        tus.update(set(tu["sources"]))

    found = 0
    missing = 0

    for file in files:
        path = Path(file)
        for tu in set(tus):
            tu_path = Path(tu)
            if path.name == tu_path.name:
                found += 1
                tus.remove(tu)
                break
        else:
            print("missing", file)
            missing += 1

    print("total", len(files), "found", found, "missing", missing)
    print("residue", len(tus))


def check_warnings(report):
    from .compilers import parse_warnings
    from pprint import pprint
    from collections import Counter

    result = parse_warnings("\n".join(report["build"]), "gnu")
    stats = Counter((mapping.get("category") for mapping in result))
    pprint(stats)


def main():
    json_file = sys.argv[1]
    with open(json_file) as fp:
        report = json.load(fp)

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
