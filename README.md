# host-inspector-mcp

An [MCP](https://modelcontextprotocol.io) server (stdio) that lets an AI assistant **inspect a Linux host
safely**: what is using the CPU, which disk is filling up, why a service failed, what the journal says.
It replaces "run this shell command for me" with a small set of typed, bounded, mostly read-only tools.

Built on the `mcp` 2.x Python SDK and `psutil`. Python >= 3.12.

## Tools

| Tool | What it does | Access |
|---|---|---|
| `system_overview` | OS, kernel, CPU, memory, swap, load, uptime, mounted disks | read-only |
| `hardware_sensors` | temperatures, fans, battery where the kernel exposes them | read-only |
| `top_processes` | heaviest processes by CPU or memory | read-only |
| `process_details` | one PID: command, parent, children, open files, sockets | read-only |
| `disk_usage` | `du -d1`-style breakdown of a directory | read-only |
| `find_large_files` | biggest files under a path (one filesystem, symlinks not followed) | read-only |
| `network_status` | interfaces, default route, DNS, listening ports | read-only |
| `check_connectivity` | DNS + TCP connect latency to host:port | read-only (network) |
| `service_status` | one systemd unit, or all failed and running units | read-only |
| `journal_logs` | `journalctl` filtered by unit, time, priority, regex, boot | read-only |
| `package_updates` | pending apt/snap updates and reboot-required | read-only |
| `package_info` | apt policy and description, or a name search | read-only |
| `tool_inventory` | which developer CLIs are installed, with versions | read-only |
| `kill_process` | signal a process **you own** | the only mutating tool; annotated destructive |

## Safety design

The server is the permission boundary between a language model and a machine, so the boundaries are explicit
and tested ([`tests/test_tools.py`](tests/test_tools.py)):

* **No shell, ever.** Every external command goes through one helper, `_run(argv)`, which uses
  `subprocess.run` with a list. A test passes `"a; echo b"` and checks it arrives as a literal argument.
* **Bounded.** Every command has a timeout (a test proves a hung command is reported, not waited on). Output
  lists are capped (`limit`, `top_n`, first 50 files or sockets, and so on) so a call cannot flood the model's context.
* **Unprivileged.** It runs as the invoking user. When a process belongs to someone else, `process_details`
  returns a note instead of an error, and `kill_process` refuses.
* **One mutating tool, with guard rails.** `kill_process` refuses PID 0, PID 1 and the server itself, refuses
  processes owned by other users, and only accepts `TERM`, `KILL`, `INT` or `HUP` (a typed `Literal`).
* **Honest MCP annotations.** Read-only tools carry `readOnlyHint`; only `kill_process` carries
  `destructiveHint`; `check_connectivity` is marked open-world because it touches the network. A client can
  therefore auto-approve the first group and prompt for the last.
* **Robust walkers.** `find_large_files` stays on one filesystem, skips symlinked directories (a test proves
  nothing is counted twice) and ignores unreadable directories rather than failing.
* **Portable.** Missing tools (for example no `journalctl` in a container) produce a readable
  `error: ... is not installed` string instead of a stack trace.

## Run it

```sh
pip install .
claude mcp add host -- host-inspector-mcp           # or any MCP client: command = host-inspector-mcp, transport = stdio
HOST_INSPECTOR_NAME=build-box HOST_INSPECTOR_INSTRUCTIONS="CI runner, Debian 12" host-inspector-mcp
```

The two environment variables let the same package describe itself correctly when it is launched on
different hosts (for example over `ssh host host-inspector-mcp`).

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests     # 14 tests, including a real MCP handshake over stdio
```

The last test launches the server as a subprocess, lists its tools through the official MCP client and calls
`kill_process` on PID 1 to prove the refusal travels over the protocol.
