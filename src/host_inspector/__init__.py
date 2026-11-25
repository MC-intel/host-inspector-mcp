"""host-inspector-mcp: read-mostly system inspection tools for a Linux host, exposed over MCP (stdio).

All tools run as the invoking (unprivileged) user and never use a shell.
Read-only except `kill_process`, which can only signal processes the user owns.
"""

from __future__ import annotations

import datetime as dt
import heapq
import os
import platform
import shutil
import signal as _signal
import subprocess
import time
from pathlib import Path
from typing import Literal

import psutil
from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations

# HOST_INSPECTOR_NAME / HOST_INSPECTOR_INSTRUCTIONS let one server definition describe itself correctly
# on different hosts (for example when the same package is launched over ssh on another machine).
mcp = MCPServer(
    name=os.environ.get("HOST_INSPECTOR_NAME", "host"),
    instructions=os.environ.get("HOST_INSPECTOR_INSTRUCTIONS") or (
        "Tools for inspecting this Linux host: hardware, processes, disks, network, systemd services, "
        "logs and packages. Prefer these over ad-hoc shell commands for routine health checks."
    ),
)

RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


def _run(cmd: list[str], timeout: float = 20) -> str:
    """Run a command without a shell; return stdout (or a readable error)."""
    if shutil.which(cmd[0]) is None:
        return f"error: `{cmd[0]}` is not installed"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"error: `{' '.join(cmd)}` timed out after {timeout}s"
    out = p.stdout.strip()
    if p.returncode != 0 and not out:
        return f"error (exit {p.returncode}): {p.stderr.strip()}"
    return out


def _gb(n: float) -> float:
    return round(n / 1024**3, 2)


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


# --------------------------------------------------------------------------- overview


@mcp.tool(annotations=RO)
def system_overview() -> dict:
    """Snapshot of the machine: OS, kernel, CPU, memory, swap, load, uptime and mounted disks."""
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            k, _, v = line.partition("=")
            os_release[k] = v.strip('"')
    except OSError:
        pass
    freq = psutil.cpu_freq()
    disks = []
    for part in psutil.disk_partitions():
        if part.fstype in ("squashfs", "tmpfs", "efivarfs") or part.mountpoint.startswith("/snap"):
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        disks.append({"mount": part.mountpoint, "device": part.device, "fs": part.fstype,
                      "total_gb": _gb(u.total), "free_gb": _gb(u.free), "used_pct": u.percent})
    boot = dt.datetime.fromtimestamp(psutil.boot_time())
    return {
        "hostname": platform.node(),
        "os": os_release.get("PRETTY_NAME", platform.platform()),
        "kernel": platform.release(),
        "cpu": {
            "model": next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines()
                           if l.startswith("model name")), platform.processor()),
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(),
            "freq_mhz": round(freq.current) if freq else None,
            "usage_pct": psutil.cpu_percent(interval=0.5),
        },
        "load_avg_1_5_15": [round(x, 2) for x in os.getloadavg()],
        "memory": {"total_gb": _gb(vm.total), "available_gb": _gb(vm.available), "used_pct": vm.percent},
        "swap": {"total_gb": _gb(sw.total), "used_pct": sw.percent},
        "boot_time": boot.isoformat(timespec="seconds"),
        "uptime": str(dt.datetime.now() - boot).split(".")[0],
        "disks": disks,
        "users_logged_in": sorted({u.name for u in psutil.users()}),
    }


@mcp.tool(annotations=RO)
def hardware_sensors() -> dict:
    """Temperatures (CPU/NVMe/etc.), fan speeds and battery, where the kernel exposes them."""
    temps = {}
    for chip, entries in (psutil.sensors_temperatures() or {}).items():
        temps[chip] = [{"label": e.label or chip, "current_c": e.current, "high_c": e.high,
                        "critical_c": e.critical} for e in entries]
    fans = {chip: [{"label": e.label, "rpm": e.current} for e in entries]
            for chip, entries in (psutil.sensors_fans() or {}).items()}
    bat = psutil.sensors_battery()
    return {"temperatures": temps, "fans": fans,
            "battery": None if bat is None else {"percent": bat.percent, "plugged_in": bat.power_plugged}}



# --------------------------------------------------------------------------- processes


@mcp.tool(annotations=RO)
def top_processes(sort_by: Literal["cpu", "memory"] = "cpu", limit: int = 15) -> list[dict]:
    """List the heaviest processes by CPU% (sampled over ~0.5s) or resident memory."""
    procs = list(psutil.process_iter(["pid", "name", "username", "memory_info", "cmdline"]))
    for p in procs:
        try:
            p.cpu_percent(None)
        except psutil.Error:
            pass
    time.sleep(0.5)
    rows = []
    for p in procs:
        try:
            rss = p.info["memory_info"].rss if p.info["memory_info"] else 0
            rows.append({"pid": p.info["pid"], "name": p.info["name"], "user": p.info["username"],
                         "cpu_pct": round(p.cpu_percent(None), 1), "rss_mb": round(rss / 1024**2, 1),
                         "cmd": " ".join(p.info["cmdline"] or [])[:200]})
        except psutil.Error:
            continue
    key = "cpu_pct" if sort_by == "cpu" else "rss_mb"
    return heapq.nlargest(max(1, min(limit, 100)), rows, key=lambda r: r[key])


@mcp.tool(annotations=RO)
def process_details(pid: int) -> dict:
    """Detailed info on one process: command, parent, status, threads, open files and connections."""
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {"pid": pid, "name": p.name(), "status": p.status(), "user": p.username(),
                    "cmdline": p.cmdline(), "cwd": None, "exe": None, "ppid": p.ppid(),
                    "parent": p.parent().name() if p.parent() else None,
                    "started": dt.datetime.fromtimestamp(p.create_time()).isoformat(timespec="seconds"),
                    "threads": p.num_threads(), "rss_mb": round(p.memory_info().rss / 1024**2, 1),
                    "children": [{"pid": c.pid, "name": c.name()} for c in p.children()][:50]}
            try:
                info["cwd"], info["exe"] = p.cwd(), p.exe()
                info["open_files"] = [f.path for f in p.open_files()][:50]
                info["connections"] = [
                    {"laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                     "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None, "status": c.status}
                    for c in p.net_connections()][:50]
            except psutil.AccessDenied:
                info["note"] = "cwd/exe/files/connections hidden: process owned by another user"
            return info
    except psutil.NoSuchProcess:
        return {"error": f"no process with pid {pid}"}


@mcp.tool(annotations=ToolAnnotations(destructiveHint=True, readOnlyHint=False, openWorldHint=False))
def kill_process(pid: int, signal: Literal["TERM", "KILL", "INT", "HUP"] = "TERM") -> str:
    """Send a signal to a process owned by the current user (default SIGTERM). Refuses PID 1 and this server."""
    if pid in (0, 1, os.getpid()):
        return f"refused: will not signal pid {pid}"
    try:
        p = psutil.Process(pid)
        if p.uids().real != os.getuid():
            return f"refused: pid {pid} ({p.name()}) belongs to {p.username()}"
        name = p.name()
        p.send_signal(getattr(_signal, f"SIG{signal}"))
        return f"sent SIG{signal} to {pid} ({name})"
    except psutil.NoSuchProcess:
        return f"no process with pid {pid}"
    except psutil.AccessDenied:
        return f"permission denied signalling {pid}"


# --------------------------------------------------------------------------- disks / files


@mcp.tool(annotations=RO)
def disk_usage(path: str = "~", top_n: int = 20) -> dict:
    """Size of each immediate child of a directory (like `du -d1`), largest first."""
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        return {"error": f"{root} is not a directory"}
    out = _run(["du", "-x", "-d1", "-b", str(root)], timeout=120)
    entries = []
    for line in out.splitlines():
        size, _, name = line.partition("\t")
        if size.isdigit() and name != str(root):
            entries.append((int(size), name))
    total = next((int(l.split("\t")[0]) for l in out.splitlines() if l.endswith("\t" + str(root))), None)
    entries.sort(reverse=True)
    return {"path": str(root), "total": _fmt_bytes(total) if total else None,
            "children": [{"path": n, "size": _fmt_bytes(s)} for s, n in entries[:top_n]]}


@mcp.tool(annotations=RO)
def find_large_files(path: str = "~", min_size_mb: int = 100, limit: int = 25) -> list[dict]:
    """Find the largest files under a path (stays on one filesystem, skips unreadable dirs)."""
    root = Path(path).expanduser().resolve()
    dev = root.stat().st_dev
    threshold = min_size_mb * 1024**2
    heap: list[tuple[int, str, float]] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        try:
            if os.stat(dirpath).st_dev != dev:
                dirnames[:] = []
                continue
        except OSError:
            continue
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            if st.st_size >= threshold:
                item = (st.st_size, fp, st.st_mtime)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                else:
                    heapq.heappushpop(heap, item)
    return [{"path": p, "size": _fmt_bytes(s),
             "modified": dt.datetime.fromtimestamp(m).isoformat(timespec="seconds")}
            for s, p, m in sorted(heap, reverse=True)]


# --------------------------------------------------------------------------- network


@mcp.tool(annotations=RO)
def network_status() -> dict:
    """Network interfaces with addresses/link state, default route, DNS servers and listening ports."""
    stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
    ifaces = []
    for name, st in stats.items():
        ifaces.append({"name": name, "up": st.isup, "speed_mbps": st.speed, "mtu": st.mtu,
                       "addresses": [a.address for a in addrs.get(name, [])
                                     if a.family.name in ("AF_INET", "AF_INET6")]})
    listening = []
    for c in psutil.net_connections(kind="inet"):
        if c.status == psutil.CONN_LISTEN or (c.type.name == "SOCK_DGRAM" and not c.raddr):
            name = None
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except psutil.Error:
                    pass
            listening.append({"proto": "tcp" if c.type.name == "SOCK_STREAM" else "udp",
                              "address": f"{c.laddr.ip}:{c.laddr.port}", "pid": c.pid, "process": name})
    listening.sort(key=lambda r: (r["proto"], int(r["address"].rsplit(":", 1)[1])))
    dns = _run(["resolvectl", "dns"]) if shutil.which("resolvectl") else ""
    return {"interfaces": ifaces, "default_route": _run(["ip", "route", "show", "default"]),
            "dns": dns, "listening": listening,
            "note": "process names for sockets owned by other users are hidden without root"}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_connectivity(host: str = "1.1.1.1", port: int = 443, timeout_s: float = 3.0) -> dict:
    """Test DNS resolution and a TCP connect to host:port, reporting latency."""
    import socket
    result: dict = {"host": host, "port": port}
    t0 = time.perf_counter()
    try:
        ip = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0]
        result["resolved_ip"], result["dns_ms"] = ip, round((time.perf_counter() - t0) * 1000, 1)
    except OSError as e:
        return result | {"ok": False, "error": f"DNS failed: {e}"}
    t1 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            result["connect_ms"] = round((time.perf_counter() - t1) * 1000, 1)
            result["ok"] = True
    except OSError as e:
        result |= {"ok": False, "error": f"connect failed: {e}"}
    return result


# --------------------------------------------------------------------------- systemd / logs


@mcp.tool(annotations=RO)
def service_status(unit: str | None = None, user: bool = False) -> str:
    """Status of one systemd unit (e.g. 'ssh', 'docker'), or with no unit, list failed units
    plus running services. Set user=True for the user's own systemd instance."""
    base = ["systemctl", "--no-pager"] + (["--user"] if user else [])
    if unit:
        return _run(base + ["status", "--lines=15", unit])
    failed = _run(base + ["list-units", "--failed", "--plain", "--no-legend"]) or "(none)"
    running = _run(base + ["list-units", "--type=service", "--state=running", "--plain", "--no-legend"])
    return f"FAILED UNITS:\n{failed}\n\nRUNNING SERVICES:\n{running}"


@mcp.tool(annotations=RO)
def journal_logs(unit: str | None = None, since: str = "1 hour ago",
                 priority: Literal["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] = "info",
                 grep: str | None = None, lines: int = 100, boot: Literal["current", "previous"] | None = None) -> str:
    """Read systemd journal entries, filtered by unit, time window, priority, boot and regex.
    Note: system-wide logs need the user to be in the `adm` group (they are)."""
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "-p", priority, "-n", str(min(lines, 1000))]
    if boot:
        cmd += ["-b", "0" if boot == "current" else "-1"]
    else:
        cmd += ["--since", since]
    if unit:
        cmd += ["-u", unit]
    if grep:
        cmd += ["--grep", grep]
    return _run(cmd, timeout=30) or "(no matching entries)"


# --------------------------------------------------------------------------- packages


@mcp.tool(annotations=RO)
def package_updates() -> dict:
    """Pending apt and snap updates, and whether a reboot is required. (Does not refresh indexes.)"""
    apt = [l for l in _run(["apt", "list", "--upgradable"]).splitlines() if "/" in l]
    security = [l for l in apt if "-security" in l]
    snaps = _run(["snap", "refresh", "--list"])
    reboot = Path("/var/run/reboot-required")
    return {"apt_upgradable": apt, "apt_security_count": len(security),
            "snap_refreshable": snaps, "reboot_required": reboot.exists(),
            "reboot_reason": Path("/var/run/reboot-required.pkgs").read_text().split()
            if Path("/var/run/reboot-required.pkgs").exists() else []}


@mcp.tool(annotations=RO)
def package_info(name: str) -> str:
    """Whether an apt package is installed, its version, candidate version and description;
    falls back to searching package names if it isn't an exact match."""
    policy = _run(["apt-cache", "policy", name])
    if policy and not policy.startswith("error") and "Candidate" in policy:
        desc = _run(["apt-cache", "show", "--no-all-versions", name])
        summary = "\n".join(l for l in desc.splitlines()
                            if l.split(":")[0] in ("Package", "Version", "Section", "Installed-Size", "Description"))
        return f"{policy}\n\n{summary}"
    found = _run(["apt-cache", "search", "--names-only", name]).splitlines()[:30]
    return "no exact match; similar packages:\n" + ("\n".join(found) or "(none)")


@mcp.tool(annotations=RO)
def tool_inventory() -> dict:
    """Which common developer/admin CLI tools are on PATH, with versions."""
    tools = {
        "python3": ["--version"], "uv": ["--version"], "git": ["--version"], "gh": ["--version"],
        "node": ["--version"], "npm": ["--version"], "docker": ["--version"], "gcc": ["--version"],
        "make": ["--version"], "ssh": ["-V"], "sshd": ["-V"], "rg": ["--version"], "jq": ["--version"],
        "curl": ["--version"], "tmux": ["-V"], "htop": ["--version"], "nvidia-smi": ["--version"],
        "nvcc": ["--version"],
    }
    env = os.environ | {"PATH": os.environ.get("PATH", "") + f":{Path.home()}/.local/bin"}
    out = {}
    for t, args in tools.items():
        path = shutil.which(t, path=env["PATH"])
        if not path:
            out[t] = None
            continue
        try:
            p = subprocess.run([path, *args], capture_output=True, text=True, timeout=5)
            txt = (p.stdout or p.stderr).strip().splitlines()
            out[t] = txt[0] if txt else path
        except (subprocess.TimeoutExpired, OSError):
            out[t] = path
    return out



def main() -> None:
    mcp.run("stdio")


if __name__ == "__main__":
    main()
