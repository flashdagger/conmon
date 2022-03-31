import logging
import re
from collections import Counter
from contextlib import suppress
from itertools import groupby
from typing import Any, Dict, List, Optional, Tuple, Pattern, Union

from .logging import get_logger, UniqueLogger
from .regex import shorten_conan_path, REF_REGEX, compact_pattern
from .utils import shorten

LOG = get_logger("BUILD")
LOG_ONCE = UniqueLogger(LOG)


class WarningRegex:
    CMAKE = re.compile(
        r"""(?xm)
            ^CMake\ (?P<severity>\w+)
            (?:
                \ (?:in|at)\ (?P<file>(?:[A-za-z]:)?[^\n:]+)
                (?::(?P<line>\d+)\ \((?P<function>\w+)\))?
             )?:
             \n
            (?P<info> (?:\ +[^\n]+\n{1,2})+ )
            (?P<context>Call\ Stack[^\n]+ (?:\n\ +[^\n]+)+)?
        """
    )
    GNU = re.compile(
        r"""(?xm)
        ^(?P<context>
            (?:In\ file\ included\ from\ [^\n]+:\d+:\n)*
            |
            (?:
                (?:[A-za-z]: )? [^\n:]+:\ In\ function\ [^:]+:\n
            )?
        )
        \ *
        (?P<file>(?:[A-za-z]:)?[^\n:()]+)
        (?:
            [:(]
            (?P<line>\d+)
            (?:
                [:.,]
                (?P<column>\d+(?:-\d+)?)
            )?
        )?
        \)?:\ #
        (?P<severity>[a-z\s]+):\ #
        (?P<info>.*?)
        (\ \[(?P<category>[\w=+\-]+)])?
        \n
        (
            (?P<hint>[^\n]+\n[\s|~]*\^[\s~]*(?:\n\ +|\ [^\n]+)?)
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
        """
    )
    AUTOTOOLS = re.compile(
        r"""(?x)
        (?P<from>
            ar | autoreconf | aclocal | configure(?:\.[a-z]+)? | Makefile(?:\.[a-z]+)?
        )
        ( :(?P<line>\d+) )?
        (
            :\ (?P<severity>warning|error)
        )?
        :\ #
        (?P<info>.*)
        """
    )
    CONAN = re.compile(
        rf"""(?xm)
        (?:(?P<severity_l>ERROR|WARN):\ )?
        (?:{compact_pattern(REF_REGEX)[0]}:\ +)?
        (?(severity_l) | (?P<severity>ERROR|WARN):\ ?)
        (?P<info>.*)
        """
    )

    @classmethod
    def get(cls, key: str, default=None) -> Optional[Pattern]:
        key = key.replace("-", "_").upper()
        return getattr(cls, key, default)


def log_level(hint: Optional[str]) -> int:
    hint_l = hint.lower() if hint else ""
    if "warn" in hint_l:
        return logging.WARNING
    if "error" in hint_l:
        return logging.ERROR
    return logging.INFO


def to_int(mapping: Dict[str, Any], *keys: str) -> None:
    for key in keys:
        if key not in mapping:
            continue
        with suppress(ValueError, TypeError):
            mapping[key] = int(mapping[key])


def parse_cmake_warnings(output: str) -> List[Dict[str, Any]]:
    groupdict: Dict[str, Any]
    warnings = []

    for match in WarningRegex.CMAKE.finditer(output):
        groupdict = match.groupdict()
        to_int(groupdict, "line")
        groupdict["from"] = "cmake"
        groupdict["info"] = groupdict["info"].strip()
        groupdict["severity"] = groupdict["severity"].lower()
        warnings.append(groupdict)
        if groupdict["severity"] == "error":
            LOG.error(match.group().rstrip())
        elif groupdict["severity"] == "warning" and groupdict["file"]:
            LOG.warning(match.group().rstrip())

    return warnings


def parse_autotools_warnings(output: str) -> List[Dict[str, Any]]:
    groupdict: Dict[str, Any]
    warnings = []

    for match in WarningRegex.AUTOTOOLS.finditer(output):
        groupdict = match.groupdict()
        to_int(groupdict, "line")
        severity = match.group("severity")
        groupdict["severity"] = severity or "note"
        if severity:
            LOG_ONCE.warning(match.group())
        warnings.append(groupdict)

    return warnings


def filter_compiler_warnings(
    output: List[List[str]], compiler: str
) -> Tuple[str, List[List[str]]]:
    residue = []
    parsed_output = []
    compiler_regex = WarningRegex.get(compiler)

    if not compiler_regex:
        LOG.warning("filter_compiler_warnings: unknown type %r", compiler)
        return "", output

    for lines in output:
        text = "\n".join((*lines, "\n"))
        if all(re.fullmatch(r"\d+ warnings? generated\.", line) for line in lines):
            continue
        if compiler_regex.search(text):
            parsed_output.append(text)
        else:
            residue.append(lines)

    return "\n".join(parsed_output), residue


def parse_compiler_warnings(output: str, compiler: str) -> List[Dict[str, Any]]:
    stats: Dict[Tuple[str, str], int] = Counter()
    groupdict: Dict[str, Any]
    warnings: List[Dict[str, Any]] = []
    keyset = set()
    ident_set = set()
    compiler_regex = WarningRegex.get(compiler)
    if not compiler_regex:
        LOG.warning("parse_warnings: unknown type %r", compiler)
        return warnings

    for match in compiler_regex.finditer(output):
        groupdict = match.groupdict()
        ident = hash(frozenset(groupdict.items()))
        if ident in ident_set:
            continue
        ident_set.add(ident)
        to_int(groupdict, "line", "column")

        file = groupdict.get("file", "")
        if file.endswith(".y"):
            from_tool = "bison"
        else:
            from_tool = "compiler"

        groupdict["from"] = from_tool
        for _item in ("context", "hint"):
            if _item in groupdict:
                value = groupdict[_item]
                groupdict[_item] = value.splitlines(keepends=False) if value else []
        warnings.append(groupdict)

        severity = groupdict["severity"]
        if severity not in {"warning", "error", "fatal error"}:
            continue

        key = (
            severity,
            repr(groupdict["category"]) if from_tool == "compiler" else from_tool,
        )
        stats[key] += 1

        if key not in keyset:
            output = shorten(shorten_conan_path(match.group()), width=500)
            LOG.log(log_level(severity), output.rstrip())
            keyset.add(key)

    total_stats = ((key[0], key[1], stats[key]) for key in sorted(stats))
    for severity, stats_iter in groupby(total_stats, key=lambda _item: _item[0]):
        stat_list: List[Any] = list(stat for stat in stats_iter)
        LOG.info(
            "Compilation issued %s distinct %s(s)",
            sum(key[-1] for key in stat_list),
            severity,
        )
        if severity != "warning":
            continue
        for _, key, value in sorted(
            stat_list, key=lambda item: (item[1][0], item[2]), reverse=True
        ):
            LOG.info("  %s: %s", key, value)

    return warnings


def filter_lines(
    output: List[List[str]], *regex: Union[str, Pattern]
) -> List[List[str]]:
    residue = []

    for lines in output:
        text = "\n".join((*lines, "\n"))
        if any(re.search(rgx, text) for rgx in regex):
            continue
        residue.append(lines)

    return residue
