import argparse
import logging
import os
import re
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path
from subprocess import CalledProcessError, check_output
from typing import List

import colorama  # type: ignore
import colorlog  # type: ignore

LOG = logging.getLogger("CLEANUP")


def conan(cmd: str) -> str:
    output = check_output(["conan", *shlex.split(cmd)], universal_newlines=True)
    return output.rstrip()


def ref_from_path(path: Path) -> str:
    name, version, user, channel = path.parts[-4:]
    ref = f"{name}/{version}@"
    if user != "_":
        ref += f"{user}/{channel}"
    return ref


def remove_path(path: Path):
    shutil.rmtree(path, ignore_errors=True)


def cleanup_conan(args) -> int:
    cache = Path(conan("config get storage.path"))
    now = datetime.now()
    regex = re.compile(args.filter)
    any_match = False
    return_status = 0

    for path in cache.glob("*/*/*/*"):
        if not path.is_dir():
            continue
        conan_file = path / "export" / "conanfile.py"
        if not conan_file.is_file():
            LOG.warning("%s does not contain conanfile")
            continue

        stat = conan_file.stat()
        ref = ref_from_path(path)
        age = now - datetime.fromtimestamp(stat.st_atime)
        if args.debug:
            LOG.debug("%s age: %s days", ref, age.days)

        if age.days <= args.days or not regex.match(ref):
            continue

        any_match = True
        if args.dry_run:
            LOG.info("Would delete %s (%s days)", ref, age.days)
        else:
            LOG.info("Deleting %s (%s days)", ref, age.days)
            try:
                conan(f"remove --force {ref}")
            except CalledProcessError as exc:
                if args.debug:
                    LOG.debug(exc)
                return_status = 1

    if not any_match:
        LOG.info("Nothing to delete.")

    return return_status


def main() -> int:
    args = parse_args(sys.argv[1:])

    colorama_args = dict(autoreset=True, convert=None, strip=None, wrap=True)
    # prevent messing up colorama settings
    if os.getenv("CI"):
        colorama.deinit()
        colorama_args.update(dict(strip=False, convert=False))
    colorama.init(**colorama_args)

    handler = logging.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter("%(log_color)s[%(name)s:%(levelname)s] %(message)s")
    )

    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG)

    if os.getenv("CI"):
        LOG.info("Running in Gitlab CI")

    if args.what == "conan":
        return cleanup_conan(args)

    return 0


def parse_args(args: List[str]):
    """
    parsing commandline parameters
    """
    description = "Remove folders from conan cache or virtualenvwrapper workspaces"
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--what", help="conan or env", choices=("conan", "env"), default="conan"
    )
    parser.add_argument(
        "--dry-run", help="don't delete anything", action="store_true",
    )
    parser.add_argument(
        "--debug", help="output additional info", action="store_true",
    )
    parser.add_argument(
        "--days",
        type=int,
        help="minimum age of items to be deleted (determined by access time)",
        default=0,
    )
    parser.add_argument(
        "--filter",
        help="regular expression that item names need to match",
        default=".*",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
