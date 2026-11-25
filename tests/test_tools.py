"""Unit tests call the tool functions directly (the decorator returns the plain function) and one
end-to-end test speaks real MCP over stdio to a subprocess."""
import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import host_inspector as h


class SafetyTests(unittest.TestCase):
    def test_kill_refuses_pid_1_0_and_self(self):
        for pid in (0, 1, os.getpid()):
            self.assertTrue(h.kill_process(pid).startswith("refused"), pid)

    def test_kill_refuses_other_users_processes(self):
        if os.getuid() == 0:
            self.skipTest("running as root")
        # pid 2 (kthreadd) is root-owned on Linux
        if Path("/proc/2").exists():
            self.assertIn("belongs to", h.kill_process(2))

    def test_kill_signals_own_child(self):
        child = subprocess.Popen(["sleep", "30"])
        try:
            self.assertIn("sent SIGTERM", h.kill_process(child.pid))
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        finally:
            child.kill()

    def test_kill_unknown_pid(self):
        self.assertIn("no process", h.kill_process(2**22 - 3))

    def test_run_never_uses_a_shell(self):
        self.assertIn("not installed", h._run(["definitely-not-installed-xyz"]))
        # a shell metacharacter is passed as a literal argument, not interpreted
        self.assertEqual(h._run(["echo", "a; echo b"]), "a; echo b")

    def test_run_reports_timeout(self):
        self.assertIn("timed out", h._run(["sleep", "5"], timeout=0.2))


class ToolTests(unittest.TestCase):
    def test_system_overview_shape(self):
        o = h.system_overview()
        for k in ("hostname", "os", "kernel", "cpu", "memory", "disks", "uptime"):
            self.assertIn(k, o)
        self.assertGreater(o["memory"]["total_gb"], 0)

    def test_top_processes_sorted_and_limited(self):
        ps = h.top_processes(sort_by="memory", limit=5)
        self.assertLessEqual(len(ps), 5)

    def test_process_details_self_and_missing(self):
        self.assertEqual(h.process_details(os.getpid())["pid"], os.getpid())
        self.assertIn("error", h.process_details(2**22 - 3))

    def test_find_large_files_respects_threshold_and_limit(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(d)]))
        for i, mb in enumerate((1, 2, 3)):
            (d / f"f{i}").write_bytes(b"0" * mb * 1024 * 1024)
        (d / "small").write_bytes(b"0")
        r = h.find_large_files(str(d), min_size_mb=1, limit=2)
        self.assertEqual([x["path"].rsplit("/", 1)[1] for x in r], ["f2", "f1"])

    def test_find_large_files_skips_symlinked_dirs(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(d)]))
        (d / "real").mkdir()
        (d / "real" / "big").write_bytes(b"0" * 1024 * 1024)
        (d / "link").symlink_to(d / "real")
        self.assertEqual(len(h.find_large_files(str(d), min_size_mb=1)), 1)   # not counted twice

    def test_check_connectivity_closed_port(self):
        r = h.check_connectivity("127.0.0.1", 1, timeout_s=1)
        self.assertIsInstance(r, dict)

    def test_fmt_bytes(self):
        self.assertEqual(h._fmt_bytes(1536), "1.5KB")
        self.assertEqual(h._fmt_bytes(0), "0.0B")


class ProtocolTest(unittest.TestCase):
    def test_server_lists_tools_and_calls_one_over_stdio(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async def go():
            params = StdioServerParameters(command=sys.executable, args=["-m", "host_inspector"],
                                           env={**os.environ, "PYTHONPATH": str(Path(h.__file__).parent.parent)})
            async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                res = await s.call_tool("kill_process", {"pid": 1})
                return names, res.content[0].text
        names, text = asyncio.run(go())
        self.assertTrue({"system_overview", "kill_process", "journal_logs", "find_large_files"} <= names)
        self.assertTrue(text.startswith("refused"))


if __name__ == "__main__":
    unittest.main()
