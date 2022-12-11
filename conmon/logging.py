#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import os
from typing import Dict, Mapping, Optional, Set

import colorama
from colorlog import ColoredFormatter, default_log_colors
from colorlog.escape_codes import escape_codes

from . import conan


# pylint: disable=too-few-public-methods
class _GLOBALS:
    initialized = False
    log_level = logging.WARNING
    log_format = "%(log_color)s[%(name)s:%(levelname)s] %(message)s"
    log_colors = {
        **default_log_colors,
        "DEBUG": "light_black",
    }
    handler = logging.StreamHandler()
    logger_mapping: Dict[str, logging.Logger] = {}


class UniqueLogger(logging.Logger):
    def __init__(self, logger: logging.Logger):
        super().__init__(f"{logger.name}_unique")
        self._logger = logger
        self.seen: Set = set()

    # pylint: disable=arguments-differ
    def _log(self, level, msg, args, **kwargs):
        key = tuple((str(msg), *map(str, args)))
        if key in self.seen:
            return
        self.seen.add(key)
        getattr(self._logger, "_log")(level, msg, args, **kwargs)


def level_from_name(name: Optional[str], default=logging.NOTSET) -> int:
    name = name.upper() if name else ""
    name, *_ = name.split()
    return getattr(logging, name, default)


def setup_logger(logger: logging.Logger):
    level = conan.loglevel(f"log.level.{logger.name.lower()}", _GLOBALS.log_level)
    logger.setLevel(level)
    if not logger.hasHandlers():
        logger.addHandler(_GLOBALS.handler)


def get_logger(name="root"):
    logger = logging.getLogger(name)
    setup_logger(logger)
    _GLOBALS.logger_mapping[logger.name] = logger
    return logger


def logger_colors(logger: logging.Logger) -> Mapping[str, str]:
    for handler in logger.handlers:
        if isinstance(handler.formatter, ColoredFormatter):
            return handler.formatter.log_colors
    return {}


def logger_escape_code(logger: logging.Logger, level: str) -> str:
    colors = logger_colors(logger)
    color = colors.get(level, "")
    return color and escape_codes.get(color, "")


def init(force=False):
    if force:
        colorama.deinit()
    elif _GLOBALS.initialized:
        return

    colorama_args = dict(autoreset=True, convert=None, strip=None, wrap=True)
    # prevent messing up colorama settings on gitlab
    if os.getenv("CI"):
        colorama.deinit()
        colorama_args.update(dict(strip=False, convert=False))

    colorama.init(**colorama_args)

    _GLOBALS.handler.setFormatter(
        ColoredFormatter(
            _GLOBALS.log_format,
            log_colors=_GLOBALS.log_colors,
        )
    )

    _GLOBALS.log_level = conan.loglevel("log.level")

    # .conan module cannot import .logging due to circular dependency
    setup_logger(conan.LOG)
    for logger in _GLOBALS.logger_mapping.values():
        setup_logger(logger)

    _GLOBALS.initialized = True
