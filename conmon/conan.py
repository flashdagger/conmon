#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import os
import re
import shlex
import sys
from ast import literal_eval
from configparser import ConfigParser
from contextlib import suppress
from functools import lru_cache
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from subprocess import check_output, CalledProcessError, PIPE
from typing import Dict, Any, Optional, Tuple, List

LOG = logging.getLogger("CONAN")
USER_HOME = Path(os.getenv("CONAN_USER_HOME", "~")).expanduser().absolute()
CONFIG_FOLDER = USER_HOME / ".conan"


class ClientConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

    def items_as_dict(self, section: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        for key, value in self.items(section):
            value = re.sub(r" *#.*", "", value)
            try:
                info[key] = literal_eval(value)
            except (ValueError, SyntaxError):
                info[key] = value
        return info


@lru_cache(maxsize=32)
def config(section: Optional[str] = None) -> Dict[str, Any]:
    if section:
        return config().get(section, {})

    parser = ClientConfigParser(allow_no_value=True)
    with (CONFIG_FOLDER / "conan.conf").open(encoding="utf8") as fp:
        parser.read_file(fp)

    return {
        section: dict(parser.items_as_dict(section)) for section in parser.sections()
    }


def conmon_setting(name: str, default: Any = None) -> Any:
    env_key = f"CONMON_{name.upper().replace('.', '_')}"
    value = os.getenv(env_key)
    if isinstance(value, str):
        with suppress(ValueError, SyntaxError):
            return literal_eval(value)
        return value
    return config("conmon").get(name, default)


def storage_path() -> Path:
    spath = config("storage").get("path", ".data")
    path = Path(spath).expanduser()
    if not path.is_absolute():
        path = CONFIG_FOLDER / path
    return path


def download_cache() -> Optional[Path]:
    dlpath = config("storage").get("download_cache")
    return dlpath and Path(dlpath).absolute()


def loglevel(name: str, default=logging.WARNING) -> int:
    level = conmon_setting(name)
    if isinstance(level, str):
        level = getattr(logging, level.upper(), None)
    if not isinstance(level, int):
        level = default
    assert isinstance(level, int)
    return level


@lru_cache(maxsize=1)
def call_cmd_and_version() -> Tuple[List[str], str]:
    """determines the fastest method to get the version of conan"""

    regex = re.compile(r"[12](?:\.\d+){2}")
    conan_command = [sys.executable, "-m", "conans.conan"]

    try:
        # parse the sourcefile without importing it
        if not sys.modules.get("conans"):
            spec: Any = find_spec("conans")
            out = Path(spec.origin).read_text(encoding="utf-8") if spec else ""
            return conan_command, regex.findall(out)[0]
    except (ImportError, FileNotFoundError, IndexError):
        pass

    try:
        # import the conan module and get the version string
        module = import_module("conans")
        version = getattr(module, "__version__")
        return conan_command, version
    except (ModuleNotFoundError, AttributeError):
        pass

    # use the conan executable or python calling the module
    conmon_conan_cmd = conmon_setting("conan_cmd") or "conan"
    try:
        LOG.debug("calling via %r", conmon_conan_cmd)
        conan_command = shlex.split(conmon_conan_cmd, posix=os.name == "posix")
        out = check_output(
            [*conan_command, "--version"],
            universal_newlines=True,
        )
        return conan_command, regex.findall(out)[0]
    except CalledProcessError as exc:
        if exc.output:
            LOG.error("%s", exc.output)
    except (FileNotFoundError, IndexError):
        pass

    LOG.error("The command %r cannot be executed.", conmon_conan_cmd)
    sys.exit(1)


def command(cmd: str) -> Optional[str]:
    try:
        conan_cmd, _ = call_cmd_and_version()
        output = check_output(
            [*conan_cmd, *shlex.split(cmd)], stderr=PIPE, universal_newlines=True
        )
    except CalledProcessError as exc:
        severity = logging.ERROR if "ERROR:" in exc.stderr else logging.WARNING
        LOG.log(severity, exc.stderr.replace("ERROR: ", "").rstrip())
        return None
    return output.rstrip()
