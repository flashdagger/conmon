import logging
import re
from collections import Counter
from itertools import groupby
from typing import Any, Dict, List, Optional, Tuple, Pattern

from conmon.utils import shorten

LOG = logging.getLogger("BUILD")


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
    CLANG_CL = re.compile(
        r"^(?P<context>(In\ file\ included\ from\ [^\n]+:\d+:\n)*)"
        r"(?P<file>[^\n(]+)\((?P<line>\d+),(?P<column>\d+)\):\s"
        r"(?P<severity>[a-z\s]+):\s"
        r"(?P<info>.*?)"
        r"(\s\[(?P<category>[^]]+)])?"
        r"\n"
        r"((?P<hint>[^\n]+\n[\s~]*\^[\s~]*)\n)?",
        re.VERBOSE | re.MULTILINE,
    )
    GNU = re.compile(
        r"""(?xm)
             ^(?P<context>
                (In\ file\ included\ from\ [^\n]+:\d+:\n)*
              | (
                  (?:[A-za-z]:)? [^\n:]+:\ In\ function\ [^:]+:\n
                )?
              )
              \ *
             (?P<file>(?:[A-za-z]:)?[^\n:]+):
             (?P<line>\d+):
             (?:(?P<column>\d+):)?\ #
             (?P<severity>[a-z\s]+):\ #
             (?P<info>.*?)
             (\ \[(?P<category>[\w+-=]+)])?
             \n
             (
                (?P<hint>[^\n]+\n[\s|~]*\^[\s~]*)
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
            (\ \[ (?P<project>[^]]+) ])?
            \n
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
        value = mapping.get(key)
        if not isinstance(value, str):
            continue
        mapping[key] = int(value)


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
        text = "\n".join(lines)
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
        groupdict["from"] = (
            "autotools" if groupdict.get("file") in {"configure.ac"} else "compiler"
        )
        severity = groupdict["severity"]
        warnings.append(groupdict)

        if severity not in {"warning", "error", "fatal error"}:
            continue

        key = (severity, groupdict["category"] or "<no-category>")
        stats[key] += 1

        if key not in keyset:
            output = shorten(match.group().rstrip(), width=500)
            LOG.log(log_level(severity), output)
            keyset.add(key)

    total_stats = ((key[0], key[1], stats[key]) for key in sorted(stats))
    for severity, stats_iter in groupby(total_stats, key=lambda item: item[0]):
        stat_list: List[Any] = list(stat for stat in stats_iter)
        LOG.info(
            "Compilation issued %s distinct %s(s)",
            sum(key[-1] for key in stat_list),
            severity,
        )
        for _, key, value in stat_list:
            if key is None:
                continue
            LOG.info("  %s: %s", key, value)

    return warnings
