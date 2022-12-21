import re
import sys
from pathlib import Path

import pytest
from psutil import Process

from conmon import conan
from conmon.shell import Shell, parse_ps


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestShell:
    @pytest.fixture(scope="class")
    def shell(self, request):
        bin_dir = request.config.cache.get("shell/msys_bindir", None)
        if not bin_dir:
            output = (
                conan.command("install msys2/cci.latest@ -s os=Windows -s arch=x86_64")
                or ""
            )
            match = re.search(r"MSYS_BIN[^:]*: *(?P<path>.+)\n", output)
            bin_dir = match and match["path"]
            request.config.cache.set("shell/msys_bindir", bin_dir)

        if not bin_dir:
            return

        shell = Shell(Path(bin_dir, "sh.exe"))
        yield shell
        shell.exit()

    def test_shell_ps(self, shell: Shell):
        shell.send("/usr/bin/ps")
        ps_output = shell.receive(timeout=0.1)
        assert ps_output

        proc_map = {proc["COMMAND"]: proc for proc in parse_ps(ps_output)}
        assert "/usr/bin/ps" in proc_map

        shell_children = {int(proc["WINPID"]) for proc in proc_map.values()}
        current_children = {proc.pid for proc in Process().children()}
        assert not shell_children.isdisjoint(current_children)
