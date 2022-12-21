import os
import re
import sys
from contextlib import suppress
from pathlib import Path

import psutil
import pytest
from psutil import Process

from conmon import conan
from conmon.shell import Command, Shell, parse_ps


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestShell:
    @pytest.fixture(scope="class")
    def msys_bindir(self, request):
        bin_dir = request.config.cache.get("shell/msys_bindir", None)
        if not bin_dir:
            output = (
                conan.command("install msys2/cci.latest@ -s os=Windows -s arch=x86_64")
                or ""
            )
            match = re.search(r"MSYS_BIN[^:]*: *(?P<path>.+)\n", output)
            bin_dir = match and match["path"]
            if bin_dir:
                request.config.cache.set("shell/msys_bindir", bin_dir)

        assert bin_dir, "MSYS bin directory not founf"
        path = Path(bin_dir)
        assert path.is_dir(), f"{path} is not a directory"
        yield path
        children = Process().children()
        assert not children, f"found running processes {children}"

    def test_empty(self, msys_bindir: Path):
        command = Command()
        assert command.returncode is None
        assert command.is_running() is False
        assert command.wait() is None

    def test_running(self, msys_bindir: Path):
        command = Command()
        command.run([msys_bindir / "sleep", "1"])
        assert command.returncode is None
        assert command.is_running() is True
        returncode = command.wait(terminate=True)
        assert returncode == command.returncode == 1
        assert command.is_running() is False

    def test_failing(self, msys_bindir: Path):
        command = Command()
        command.run([msys_bindir / "false"])
        returncode = command.wait()
        assert returncode == command.returncode == 1

    def test_success(self, msys_bindir: Path):
        command = Command()
        command.run([msys_bindir / "true"])
        returncode = command.wait()
        assert returncode == command.returncode == 0

    def test_proc_del(self, msys_bindir: Path):
        command = Command()
        command.run([msys_bindir / "sleep", "10"])
        proc = Process(command.proc.pid)
        assert proc in Process().children()
        command.run([msys_bindir / "sleep", "10"])
        assert proc not in Process().children(), "old process is still running"
        proc = Process(command.proc.pid)
        del command
        assert proc not in Process().children(), "deleted process is still running"

    def test_streams(self, msys_bindir: Path):
        command = Command()
        command.run([msys_bindir / "echo", "Hello World!"])
        stdout, stderr = command.streams.readboth(timeout=0.1)
        assert stdout == ("Hello World!\n",)
        assert stderr == ()

        command.run([msys_bindir / "sh", "-c", "echo Hello World! 1>&2"])
        stdout, stderr = command.streams.readboth(timeout=0.05)
        assert stdout == ()
        assert stderr == ("Hello World!\n",)

        command.run([msys_bindir / "echo", "Hello World!"])
        stdout, stderr = command.streams.readboth()
        assert stdout == stderr == ()
        command.wait()
        stdout, stderr = command.streams.readboth()
        assert stdout == ("Hello World!\n",)
        assert stderr == ()

    @pytest.fixture
    def shell(self, msys_bindir: Path):
        sh_path = msys_bindir / "sh.exe"
        assert sh_path.is_file() and os.access(
            sh_path, os.X_OK
        ), f"{sh_path} is not an executable"
        shell = Shell()
        shell.run(sh_path)
        assert shell.is_running() is True
        yield shell
        shell.exit()
        assert shell.is_running() is False

    def test_shell_ps(self, shell: Shell):
        shell.send("/usr/bin/ps")
        ps_output = shell.receive(timeout=0.1)
        assert ps_output

        proc_map = {proc["COMMAND"]: proc for proc in parse_ps(ps_output)}
        assert "/usr/bin/ps" in proc_map

        for proc in proc_map.values():
            with suppress(psutil.NoSuchProcess):
                assert Process(int(proc["WINPID"])).is_running() is True

    def test_shell_fail(self, shell: Shell):
        shell.send("missing_cmd")
        with pytest.raises(Shell.Error) as exc_info:
            shell.receive(timeout=0.1)

        assert exc_info.value.args[0].endswith("missing_cmd: command not found\n")
        assert shell.is_running() is False
        with pytest.raises(Shell.Error) as exc_info:
            shell.send("whoami")

        assert exc_info.value.args[0] == "Process is not running"
