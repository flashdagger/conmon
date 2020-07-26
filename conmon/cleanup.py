import argparse
import logging
import os
import re
import shlex
import shutil
import sys
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from subprocess import CalledProcessError, PIPE, check_output
from typing import List, Optional

import colorama  # type: ignore
import colorlog  # type: ignore

LOG = logging.getLogger("CLEANUP")


# pylint: disable=too-few-public-methods
class GLOBALS:
    now = datetime.now()
    debug = False


def human_readable_size(size: int, precision: int = 1) -> str:
    ssize = float(size)
    for dim in ("Bytes", "kB", "MB", "GB"):
        if ssize > 1024:
            ssize = ssize / 1024
        else:
            break

    fsize = f"{ssize:.{precision}f}"
    return f"{fsize.rstrip('.0')} {dim}"


def conan(cmd: str) -> Optional[str]:
    try:
        output = check_output(
            ["conan", *shlex.split(cmd)], stderr=PIPE, universal_newlines=True
        )
    except CalledProcessError as exc:
        LOG.warning(exc.stderr.rstrip())
        return None
    return output.rstrip()


def ref_from_path(path: Path) -> str:
    name, version, user, channel = path.parts[-4:]
    ref = f"{name}/{version}@"
    if user != "_":
        ref += f"{user}/{channel}"
    return ref


def folder_size(path: Path) -> int:
    total = 0
    for file in path.glob("**/*"):
        if not file.is_file():
            continue
        total += file.stat().st_size
    return total


def remove_path(path: Path):
    shutil.rmtree(path, ignore_errors=True)


def cleanup_conan_cache(args) -> int:
    config_cache = conan("config get storage.path")
    if config_cache is None:
        return 1
    elif config_cache == "None":
        config_cache = conan("config home") + "/data"

    cache = Path(config_cache)
    regex = re.compile(args.filter)
    total_size = 0
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
        age = GLOBALS.now - datetime.fromtimestamp(stat.st_atime)
        if GLOBALS.debug:
            LOG.debug("%s age: %s days", ref, age.days)

        if age.days < args.days or not regex.match(ref):
            continue

        fsize = folder_size(path)
        hr_size = human_readable_size(fsize)
        info = f"{hr_size}, {age.days} days"
        if args.dry_run:
            LOG.info("Would delete %s (%s)", ref, info)
            total_size += fsize
        else:
            LOG.info("Deleting %s (%s days)", ref, info)
            if conan(f"remove --force {ref}") is None:
                return_status = 1
            else:
                total_size += fsize

    if total_size == 0:
        LOG.info("Nothing to delete.")
    else:
        LOG.info("Freed %s in conan cache.", human_readable_size(total_size))

    return return_status


def cleanup_conan_dlcache(args):
    output = conan("config get storage.download_cache")
    if output is None:
        return

    cache = Path(output)
    total_size = 0
    for path in cache.iterdir():
        if not path.is_file():
            continue
        stat = path.stat()
        age = GLOBALS.now - datetime.fromtimestamp(stat.st_atime)
        if age.days < args.days:
            continue
        size = stat.st_size
        hr_size = human_readable_size(size)
        info = f"{hr_size}, {age.days} days"
        if args.dry_run:
            LOG.info("Would delete %s (%s)", path.name, info)
            total_size += size
        else:
            LOG.info("Deleting %s (%s)", path.name, info)
            with suppress(OSError):
                path.unlink()
                total_size += size
                (path.with_name("locks") / path.name).unlink(missing_ok=True)

    if total_size > 0:
        LOG.info("Freed %s in download cache.", human_readable_size(total_size))

    if args.dry_run:
        return

    for path in (cache / "locks").iterdir():
        if not path.is_file():
            continue
        if not (cache / path.name).exists():
            with suppress(OSError):
                path.unlink(missing_ok=True)


def cleanup_conan(args) -> int:
    cleanup_conan_dlcache(args)
    return cleanup_conan_cache(args)


def main() -> int:
    args = parse_args(sys.argv[1:])
    GLOBALS.debug = args.debug

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
        default=100,
    )
    parser.add_argument(
        "--filter",
        help="regular expression that item names need to match",
        default=".*",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
