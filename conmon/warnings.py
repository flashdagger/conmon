import re
from collections import Counter
from contextlib import suppress
from itertools import groupby
from typing import (
    Any,
    Dict,
    List,
    Pattern,
    Tuple,
    Set,
    Iterable,
    Match,
    Callable,
)

from .logging import UniqueLogger, get_logger, level_from_name
from .regex import REF_REGEX, compact_pattern, shorten_conan_path
from .utils import shorten, added_first

LOG = get_logger("BUILD")
LOG_ONCE = UniqueLogger(LOG)


class Regex:
    CMAKE = re.compile(
        r"""(?xm)
            ^CMake\ (?P<severity>\w+)
            (?:
                \ (?:in|at)\ (?P<file>(?:[A-Za-z]:)?[^\n:]+)
                (?::(?P<line>\d+)\ \((?P<function>\w+)\))?
            )?:
            \n
            (?P<info> \ +[^\n]+(\n{1,2}\ +[^\n]+)* )
            \n
            (?P<context>Call\ Stack[^\n]+ (?:\n\ +[^\n]+)+)?
            (?(context)\n)
            \n{2}
        """
    )
    GNU = re.compile(
        r"""(?xm)
        ^(?P<context>
            (?:
                (?:
                    (?:In\ file\ included|\ +)\ from\ [^\n]+:\d+[:,]\n
                )*
                (?:
                    (?:[A-Za-z]: )? [^\n:]+:\ In\ function\ [^:\n]+:\n
                )?
            )+
        )?
        \ *
        (?P<file>(?:[A-Za-z]:)?[^\n:()]+\.\w{1,4})
        (?:
            [:(]
            (?P<line>\d+)
            (?:
                [:.,]
                (?P<column>\d+(?:-\d+)?)
            )?
        )?
        \)?:\ #
        (?P<severity>warning|error|note|fatal error):\ #
        (?P<info>.*?)
        (\ \[(?P<category>[\w=+\-]+)])?
        \n
        (
            (?P<hint>
                [^\n]+\n
                [^\^\n]*\^[^\^\n]*
                (?:\n\ +[^\n]+)*
            )
            \n
        )?
        """
    )
    MSVC = re.compile(
        r"""(?xm)
            (?P<file>^[^\n(]+)
            (
              \( (?P<line>\d+) (?:, (?P<column>\d+) )? \)
            )?
            \ ?:\ #
            (?P<severity>[a-z\s]+)  \ #
            (?P<category>[A-Z]+\d+):\ #
            (?P<info>.+?)
            (
                \ \[ (?P<project>[^]]+) ]
            )?
            \n
            (?P<hint>[^\n]+\n\s*\^)?
            (?(hint)\n)
        """
    )
    AUTOTOOLS = re.compile(
        r"""(?xm)
        ^(?P<from>
            configure(?:\.[a-z]+)? | Makefile(?:\.[a-z]+)? | [a-z]+
        )
        ( :(?P<line>\d+) )?
        (
            :\ (?P<severity>(?i:warning|error))
        )?
        :\ ?#
        (?P<info>.*(?:\n[ *]+[^\n]+)*)
        \n
        """
    )
    CONAN = re.compile(
        rf"""(?xm)
        (?:(?P<severity_l>ERROR|WARN):\ )?
        (?:{compact_pattern(REF_REGEX)[0]}:\ +)?
        (?(severity_l) | (?P<severity>ERROR|WARN):\ ?)
        (?P<info>.*)
        \n
        """
    )

    @classmethod
    def get(cls, key: str) -> Pattern:
        key = key.replace("-", "_").upper()
        return getattr(cls, key)

    @classmethod
    def dict(cls, *keys: str) -> Dict[str, Pattern]:
        if not keys:
            keys = tuple(
                key.lower().replace("_", "-") for key in dir(cls) if key.isupper()
            )
        return {key: cls.get(key) for key in keys}


_PROCESSED: Set[str] = set()


def convert(mapping: Dict[str, Any], func: Callable, *keys: str) -> None:
    for key in keys:
        if key not in mapping:
            continue
        with suppress(ValueError, TypeError, AttributeError):
            mapping[key] = func(mapping[key])


def show_stats(stats):
    total_stats = ((key[0], key[1], stats[key]) for key in sorted(stats))
    for severity, stats_iter in groupby(total_stats, key=lambda _item: _item[0]):
        stat_list: List[Any] = list(stat for stat in stats_iter)
        total = sum(key[-1] for key in stat_list)
        if total < 2:
            continue
        LOG.info(
            "Compilation issued %s distinct %s(s)",
            total,
            severity,
        )
        for _, key, value in sorted(
            stat_list, key=lambda item: (item[1][0], item[2]), reverse=True
        ):
            LOG.info("  %s: %s", key, value)


def warnings_from_matches(**kwargs: Iterable[Match]) -> List[Dict[str, Any]]:
    stats: Dict[Tuple[str, str], int] = Counter()
    warnings = []

    for name, matches in kwargs.items():
        for match in matches:
            if not added_first(_PROCESSED, match.group()):
                continue
            mapping = match.groupdict()
            convert(mapping, int, "line", "column")
            convert(
                mapping,
                lambda v: v.rstrip("\n").splitlines(keepends=False),
                "context",
                "hint",
            )
            convert(mapping, str.lower, "severity")
            if name in {"gnu", "msvc"}:
                mapping["from"] = "compilation"
            elif "from" not in mapping:
                mapping["from"] = name
            warnings.append(mapping)

            severity = mapping.get("severity")
            if severity not in {"warning", "error", "fatal error"}:
                continue
            if name == "cmake" and not mapping["file"]:
                continue

            key = (
                severity,
                repr(mapping["category"])
                if mapping["from"] == "compilation"
                else mapping["from"],
            )

            if key not in stats:
                output = shorten(
                    shorten_conan_path(match.group()), width=500, strip="middle"
                )
                LOG.log(level_from_name(str(severity)), output.rstrip())
            stats[key] += 1

    show_stats(stats)
    return warnings
