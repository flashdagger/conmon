import re
import sys
import time
from configparser import ConfigParser

import colorama


class StopWatch:
    def __init__(self):
        self._last_ts = time.time()

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self._last_ts

    def timespan_elapsed(self, timespan_s: float) -> bool:
        if self.elapsed_seconds >= timespan_s:
            self._last_ts = time.time() - self.elapsed_seconds % timespan_s
            return True

        return False

    def reset(self):
        self._last_ts = time.time()


class StrictConfigParser(ConfigParser):
    OPTCRE = re.compile(
        # allow only = or : for option separator
        r"(?P<option>[^=\n\s]+)\s*"
        r"(?P<vi>[=:]\s*)"
        r"(?P<value>.*)"
    )

    def optionxform(self, optionstr):
        return optionstr


class ScreenWriter:
    def __init__(self):
        self._last_line = ""

    def reset(self):
        self._last_line = ""

    def print(self, line: str, overwrite=False, indent=-1):
        append = indent >= 0
        spaces = " " * max(0, indent - len(self._last_line)) if append else ""

        if self._last_line and not append:
            printed_line = "\r" + colorama.ansi.clear_line(2) + line
        else:
            printed_line = spaces + line

        if overwrite:
            self._last_line = line
            print(printed_line, end="")
            sys.stdout.flush()
        else:
            self._last_line = ""
            print(printed_line)
