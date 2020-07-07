import argparse
import json
import sys
from typing import List


def main(args) -> int:
    with open(args.input) as fh:
        data = json.load(fh)

    packages = [
        key
        for key, value in data["requirements"].items()
        if "translation_units" in value
    ]
    if not packages:
        print(f"{args.input} has no built packages.", file=sys.stderr)
        return 1

    if args.package is None:
        args.package = packages[-1]
    elif args.package not in packages:
        print(
            f"Package {args.package!r} not found. Choose from {packages}.",
            file=sys.stderr,
        )
        return 1

    with open(args.output, "w") as fh:
        json.dump(
            data["requirements"][args.package]["translation_units"][0], fh, indent=4
        )

    return 0


def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "extract translation units from conanreport"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-i", "--input", default="conan_report.json", help="conan report input file",
    )
    parser.add_argument(
        "-o", "--output", default="tu.json", help="translation units output file",
    )
    parser.add_argument(
        "--package", help="name of the requirement inside the report file",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    ARGS = parse_args(sys.argv[1:])
    sys.exit(main(ARGS))
