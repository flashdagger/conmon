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
from io import StringIO
from itertools import chain
from pathlib import Path
from subprocess import PIPE, CalledProcessError, check_output
from typing import Any, Dict, List, Optional, Tuple

CONAN2 = True
LOG = logging.getLogger("CONAN")

if CONAN2:
    CONFIG_FOLDER = Path(os.getenv("CONAN_HOME", "~/.conan2")).expanduser().absolute()
else:
    _USER_HOME = Path(os.getenv("CONAN_USER_HOME", "~")).expanduser().absolute()
    CONFIG_FOLDER = _USER_HOME / ".conan"


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
def parsed_config(file: str) -> Dict[str, Dict[str, Any]]:
    config_file = CONFIG_FOLDER / file
    if config_file.suffix == "":
        config_file = config_file.with_suffix(".conf")

    if not config_file.is_file():
        LOG.warning("missing %s config file '%s'", file, config_file)
        return {}

    with config_file.open(encoding="utf8") as fh:
        parser = ClientConfigParser(allow_no_value=True, delimiters=("=",))
        fh_pre = StringIO("[_]\n")
        fh_pre.name = fh.name
        parser.read_file(chain(fh_pre, fh))

    return {
        section: dict(parser.items_as_dict(section)) for section in parser.sections()
    }


@lru_cache(maxsize=32)
def config(file: str, section: Optional[str] = None) -> Dict[str, Any]:
    mapping = parsed_config(file).get(section or "_", {})

    if file == "conmon" and section is None:
        unknown_keys = mapping.keys() - DEFAULTS.keys()
        if unknown_keys:
            LOG.warning("Unknown settings in conan.cfg: %s", ", ".join(unknown_keys))

    return mapping


DEFAULTS = {
    "conan:cmd": "",
    "log.level:default": "debug",
    "log.level:proc": None,
    "log.level:msysps": None,
    "log.level:conan": None,
    "log.level:conmon": None,
    "log.level:build": None,
    "log:warning_count": False,
    "log:stdout": True,
    "log:stderr": True,
    "build:monitor": True,
    "report:conan.log": False,
    "report:proc.json": False,
    "report:report.json": False,
    "report:log_states": False,
    "report:build_stderr": True,
    "report:build_stdout": True,
}


def conmon_setting(name: str) -> Any:
    env_key = f"CONMON_{name.upper().replace(':', '_')}"
    value = os.getenv(env_key)
    if isinstance(value, str):
        with suppress(ValueError, SyntaxError):
            return literal_eval(value)
        return value
    mapping = config("conmon")
    if name in mapping:
        return mapping[name]

    return DEFAULTS[name]


def report_path(file: str) -> Optional[Path]:
    setting = conmon_setting(f"report:{file}")
    if not setting:
        return None
    path = Path(setting)
    if not path.suffix:
        path = path / file

    return path


def storage_path() -> Path:
    spath = config("global").get("core.cache:storage_path", "p")
    path = Path(spath).expanduser()
    if not path.is_absolute():
        path = CONFIG_FOLDER / path
    return path


def download_cache() -> Optional[Path]:
    dlpath = config("global").get("core.download:download_cache")
    return dlpath and Path(dlpath).expanduser()


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
    executable = sys.executable
    if os.name == "nt" and "scalene" in executable:
        executable = "venv\\Scripts\\python.exe"
    conan_command = [executable, "-m", "conans.conan"]

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
