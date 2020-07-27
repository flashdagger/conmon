import argparse
import logging
import os
import re
import shlex
import shutil
import sys
from contextlib import suppress
from datetime import datetime
import fnmatch
from pathlib import Path
from subprocess import CalledProcessError, PIPE, check_output
from typing import Callable, List, Optional

import colorama  # type: ignore
import colorlog  # type: ignore

LOG = logging.getLogger("CLEANUP")


# pylint: disable=too-few-public-methods
class GLOBAL:
    now = datetime.now()
    debug = False
    globmatch: Callable[[str, str], bool] = (
        fnmatch.fnmatch if sys.platform.startswith("win") else fnmatch.fnmatchcase
    )
    min_size = 0


def human_readable_size(size: int, precision: int = 1) -> str:
    ssize = float(size)

    for dim in ("Bytes", "kB", "MB", "GB"):
        if ssize > 1024:
            ssize = ssize / 1024
        else:
            break

    fsize = f"{ssize:.{precision}f}".rstrip("0").rstrip(".")
    return f"{fsize} {dim}"


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


def cleanup_env(args) -> int:
    workon_env = os.getenv("WORKON_HOME")
    if workon_env:
        workon_home = Path(workon_env)
    else:
        for subdir in ("Envs", ".virtualenvs"):
            workon_home = Path.home() / subdir
            if workon_home.exists():
                break

    if not workon_home.exists():
        return 0

    total_size = 0
    for file in tuple(workon_home.glob("**/pyvenv.cfg")):
        age = GLOBAL.now - datetime.fromtimestamp(file.stat().st_atime)
        path = file.parent
        name = path.relative_to(workon_home).as_posix()

        # noinspection PyCallByClass
        if age.days < args.days or not GLOBAL.globmatch(name, args.filter):
            continue

        fsize = folder_size(path)
        if fsize < GLOBAL.min_size:
            continue

        hr_size = human_readable_size(fsize)
        info = f"{hr_size}, {age.days} days"
        if args.dry_run:
            LOG.info("Would delete %r (%s)", name, info)
            total_size += fsize
        else:
            LOG.info("Deleting %r (%s)", name, info)
            remove_path(path)
            total_size += fsize

    if total_size == 0:
        LOG.info("Nothing to delete.")
    else:
        action = "Could free" if args.dry_run else "Freed"
        LOG.info(
            "%s %s in virtual environments.", action, human_readable_size(total_size)
        )

    return 0


def cleanup_conan_cache(args) -> int:
    config_cache = conan("config get storage.path")
    if config_cache is None:
        return 1

    if config_cache == "None":
        config_cache = str(conan("config home")) + "/data"

    cache = Path(config_cache)
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
        age = GLOBAL.now - datetime.fromtimestamp(stat.st_atime)

        # noinspection PyCallByClass
        if age.days < args.days or not GLOBAL.globmatch(ref, args.filter):
            continue

        fsize = folder_size(path)
        if fsize < GLOBAL.min_size:
            continue

        hr_size = human_readable_size(fsize)
        info = f"{hr_size}, {age.days} days"
        if args.dry_run:
            LOG.info("Would delete %r (%s)", ref, info)
            total_size += fsize
        else:
            LOG.info("Deleting %r (%s)", ref, info)
            if conan(f"remove --force {ref}") is None:
                return_status = 1
            else:
                total_size += fsize

    if total_size == 0:
        LOG.info("Nothing to delete.")
    else:
        action = "Could free" if args.dry_run else "Freed"
        LOG.info("%s %s in conan cache.", action, human_readable_size(total_size))

    return return_status


def cleanup_conan_dlcache(args) -> int:
    output = conan("config get storage.download_cache")
    if output is None:
        return 1

    cache = Path(output)
    if not cache.exists():
        return 0

    total_size = 0
    for path in cache.iterdir():
        if not path.is_file():
            continue
        stat = path.stat()
        age = GLOBAL.now - datetime.fromtimestamp(stat.st_atime)
        size = stat.st_size
        if age.days < args.days or size < GLOBAL.min_size:
            continue
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
                lockfile = path.with_name("locks") / path.name
                lockfile.unlink(missing_ok=True)  # type: ignore

    if total_size == 0:
        LOG.info("Nothing to delete.")
    else:
        action = "Could free" if args.dry_run else "Freed"
        LOG.info("%s %s in download cache.", action, human_readable_size(total_size))

    if args.dry_run:
        return 0

    for path in (cache / "locks").iterdir():
        if not path.is_file():
            continue
        if not (cache / path.name).exists():
            with suppress(OSError):
                path.unlink(missing_ok=True)  # type: ignore

    return 0


def main() -> int:
    args = parse_args(sys.argv[1:])
    GLOBAL.debug = args.debug
    if args.size:
        match = re.match(
            r"^([\d.]+)\s*([kmg]?)(?:b|bytes)?\s*$", (args.size or "").lower()
        )
        if match is None:
            LOG.error("Invalid size %r", args.size)
            return 1
        num = float(match.group(1))
        factor = {"k": 1, "m": 2, "g": 3}.get(match.group(2), 0)
        GLOBAL.min_size = int(num * 1024 ** factor)

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
        LOG.info(
            "Cleaning conan package cache. (min_age='%s days' min_size=%r filter=%r)",
            args.days,
            human_readable_size(GLOBAL.min_size),
            args.filter,
        )
        return cleanup_conan_cache(args)
    if args.what == "dlcache":
        LOG.info(
            "Cleaning conan download cache. (min_age='%s days' min_size=%r)",
            args.days,
            human_readable_size(GLOBAL.min_size),
        )
        return cleanup_conan_dlcache(args)
    if args.what == "envs":
        LOG.info(
            "Cleaning Python venvs. (min_age='%s days' min_size=%r filter=%r)",
            args.days,
            human_readable_size(GLOBAL.min_size),
            args.filter,
        )
        return cleanup_env(args)

    raise Exception(f"Invalid selection {args.what}")


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
        "--what",
        help="choose workspace to perform cleanup",
        choices=("conan", "dlcache", "envs"),
        default="conan",
    )
    parser.add_argument(
        "-n", "--dry-run", help="don't delete anything, only show", action="store_true",
    )
    parser.add_argument(
        "--debug", help="output additional info", action="store_true",
    )
    parser.add_argument(
        "--days",
        type=int,
        help="minimum age of items to be deleted (determined by access time)",
        default=90,
    )
    parser.add_argument(
        "--size", help="minimum size of items to be deleted (accepts kB MB GB)",
    )
    parser.add_argument(
        "--filter", help="glob expression that item names need to match", default="*",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    sys.exit(main())
