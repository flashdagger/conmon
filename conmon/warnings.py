#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import logging
import re
from collections import Counter
from contextlib import suppress
from itertools import groupby, islice
from typing import Any, Callable, Dict, Iterator, Iterable, Match, Optional, Tuple

from .logging import UniqueLogger, get_logger
from .regex import REF_REGEX, Regex, compact_pattern, shorten_conan_path
from .utils import get_terminal_width, shorten_per_line

LOG = get_logger("BUILD")
LOG_ONCE = UniqueLogger(LOG)


class BuildRegex(Regex):
    CMAKE = re.compile(
        r"""(?xm)
            ^CMake\ (?P<severity>[\w ]+)
            (?: \ \(\w+\) )?
            (?:
                \ (?:in|at)\ (?P<file>(?:[A-Za-z]:)?[^\n:]+)
                (?::(?P<line>\d+)\ \((?P<function>\w+)\))?
            )?
            :(?:\n\ )?\ #
            (?P<info>.+\n(?:\n?\ {2}.*\n)*(?:.+\n\n)?)
            \n?
            (?P<context>Call\ Stack.+ (?:\n\ +.+)+\n)?
        """
    )
    GNU = re.compile(
        r"""(?xm)
        ^(?P<context>(?: .+[:,]\n)+)?
        \ *
        (?!\d+:)
        (?P<file>(?:[A-Za-z]:)?[\w()</\\. +-]*[\w>])
        (?:
            [:(]
            (?P<line>\d+)
            (?:
                [:.,]
                (?P<column>[\d-]+)
            )?
            (?:\)\ ?)?
        )?
        :\ #
        (?P<severity>(?i:warning|error|note|message|fatal\ error))\ ?:\ #
        (?P<info>.*?)
        (\ \[(?P<category>[\w#=+\-]+)])?
        (\ \[ (?P<project>[^]\n]+) ])?
        \n
        (?P<hint>
            (?:
                \ +\d+\ \|\ .+\n(?:\ +\|\ .*\n)*
            )+
            | (?:.+\n){1,2}[ ~]*\^[ ~]*(?:\n\ .+)?\n
        )?
        """
    )
    MSVC = re.compile(
        r"""(?xm)
            ^(?P<file>(?:[A-Za-z]:)?[\w()/\\. -]*\w)
            (?:\(
              (?P<line>\d+)
              (?:, (?P<column>\d+))?
            \))?
            \ ?:\ #
            (?P<severity>[A-Za-z\s]+)  \ #
            (?P<category>[A-Z]+\d+)\ ?:\ #
            (?P<info>.+?)
            (\ \[(?P<project>[^]]+)])?
            \n
            (?P<hint>[^\n]+\n\s*\^\n)?
        """
    )
    AUTOTOOLS = re.compile(
        r"""(?xm)
        ^(?P<from>
            ar
            | libtool
            | [\w/.-]+\.(?: m4 | asm )
            | auto([a-z]+)
            | aclocal(?:.\w+)?
            | config(?:ure)?(?:\.[a-z]+)?
            | Makefile(?:\.[a-z]+)?
            | make\[\d+]
        )
        ( :(?P<line>\d+) )?
        (
            :\ (?P<severity>(?i:warning|error))
        )?
        :\ ?#
        (?P<info>.*\n(?:[ *]+.+\n)*)
        """
    )
    CONAN = re.compile(
        rf"""(?xm)
        ^(?P<severity_l>ERROR|WARN(?:ING)?)?
        (?(severity_l):\ )
        (?:
            {compact_pattern(REF_REGEX)[0]}
            (?: \ \([a-z ]+\) )?
            :\ +
         )?
        (?(severity_l) | (?P<severity>ERROR|WARN(?:ING)?):\ ?)
        (?P<info>.*)
        \n
        """
    )
    BUILD = re.compile(
        r"""(?xm)
        ^(?P<severity>error|warning):\ #
        (?P<info>.*\n)
        """
    )


class IgnoreRegex(Regex):
    STOP = re.compile(r"(?m)^Stop.\n")
    EMPTY_LINES = re.compile(r"(?m)^\s*\n")
    # EMPTY_LINES = re.compile(r"^\s*\n+|(?<=[^\n]\n{3})\n+")
    MAKE_WARNINGS = re.compile(r"(?m)^[\w.-]+(\[\d+])?: \*{3}.+\n")
    MSVC_TOOLS = re.compile(r"(?m)^(Microsoft|Copyright) \([RC]\) .+\n")
    WARNINGS_GENERATED = re.compile(r"(?m)^\d+ warnings?.* generated\.\n")
    MESON_STATUS = re.compile(
        r"(?m)^(Generating targets|(Writing )?build\.ninja): +\d+ *%.+\n"
    )


def levelname_from_severity(severity: Optional[str], default="NOTSET") -> str:
    severity = severity.lower() if severity else ""

    if severity.startswith("warn") or severity.endswith("warning"):
        return "WARNING"
    if severity == "fatal error":
        return "CRITICAL"
    if severity == "error":
        return "ERROR"
    if severity in {"note", "message"}:
        return "INFO"
    return default


def loglevel_from_severity(severity: Optional[str]) -> int:
    return getattr(logging, levelname_from_severity(severity))


def convert(mapping: Dict[str, Any], func: Callable, *keys: str) -> None:
    for key in keys:
        if key not in mapping:
            continue
        with suppress(ValueError, TypeError, AttributeError):
            mapping[key] = func(mapping[key])


def show_stats(stats):
    total_stats = ((key[0], key[1], stats[key]) for key in sorted(stats))
    for severity, stats_iter in groupby(total_stats, key=lambda item: item[0]):
        stat_list = tuple(stats_iter)
        total = sum(key[-1] for key in stat_list)
        if total < 2:
            continue
        LOG.info(
            "Compilation issued %s distinct %ss",
            total,
            severity,
        )
        if severity != "warning":
            continue
        sorted_stats = sorted(
            stat_list, key=lambda item: (item[1][0], item[2]), reverse=True
        )
        width = len(str(max(item[2] for item in stat_list)))
        template = f" %{width}sx %s"
        for key, grp in groupby(sorted_stats, key=lambda item: item[2]):
            values = (item[1] for item in grp)
            while True:
                value = ", ".join((islice(values, 5)))
                if not value:
                    break
                LOG.info(template, key, value)


def warnings_from_matches(**kwargs: Iterable[Match]) -> Iterator[Dict[str, Any]]:
    stats: Dict[Tuple[str, str], int] = Counter()

    for name, matches in kwargs.items():
        for match in matches:
            mapping = {
                key: value
                for key, value in match.groupdict().items()
                if not (
                    value is None and key in {"column", "hint", "context", "project"}
                )
            }
            if name == "autotools" and not (
                mapping.get("severity") or mapping.get("line")
            ):
                continue
            convert(mapping, int, "line", "column")
            convert(
                mapping,
                lambda v: v.rstrip("\n").splitlines(keepends=False)
                if isinstance(v, str)
                else [],
                "context",
                "hint",
                "info",
            )
            convert(mapping, str.lower, "severity")
            if name in {"gnu", "msvc"}:
                mapping["from"] = "compilation"
            elif "from" not in mapping:
                mapping["from"] = name
            yield mapping

            severity = mapping.get("severity")
            if not (
                severity
                and severity.split()[-1] in {"warning", "error", "note", "message"}
            ):
                continue

            key = (
                severity,
                repr(mapping["category"] or "<undefined>")
                if mapping["from"] == "compilation"
                else mapping["from"],
            )

            if (
                key not in stats
                and severity not in {"note", "message"}
                or severity == "error"
            ):
                LOG.log(
                    loglevel_from_severity(severity),
                    shorten_per_line(
                        shorten_conan_path(match.group().rstrip()),
                        width=get_terminal_width() or 120,
                        strip="middle",
                        keep_first=True,
                    ),
                )
            stats[key] += 1

    show_stats(stats)
