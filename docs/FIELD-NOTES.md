# Field notes: giving an assistant a safe view of a machine

I run AI coding assistants against my own machines, and "let it run shell commands" is a poor trade for routine
health checks: it is powerful, it is unbounded, and the approval prompt trains you to click yes. This server is
what I built instead.

## Origin

The first version covered one Linux workstation: load, memory, disks, a failing service, what changed in the
journal. I then wanted the same view of a **headless server on the same network**. Instead of forking the code,
the server describes itself through two environment variables (`HOST_INSPECTOR_NAME`,
`HOST_INSPECTOR_INSTRUCTIONS`) and is launched on the other machine over ssh, so the assistant sees two clearly
named servers with identical tools. Name and instructions are the only per-host difference.

## Design decisions

* **Outputs are bounded.** A tool result lands in the assistant's context window, so every list has a cap
  (`limit`, `top_n`, the first 50 files or sockets of a process) and the large-file search keeps only the top N
  in a heap instead of collecting everything it walks.
* **Typed arguments over strings.** `signal` is a `Literal["TERM", "KILL", "INT", "HUP"]` and `sort_by` a
  `Literal["cpu", "memory"]`. The schema the model sees *is* the validation.
* **One mutating tool, annotated honestly.** MCP lets a server mark tools read-only or destructive. Clients can
  then auto-approve the former and always ask about the latter, which only works if the server doesn't lie.
  Only `kill_process` carries the destructive hint, and it refuses PID 0, PID 1, itself and other users' processes.
* **Symlinked directories are not followed** when hunting large files: following a link double-counts or walks
  off the tree you meant to inspect. A test pins this. The walk also stays on one filesystem.
* **Missing tools are an answer, not a crash.** Minimal hosts have no `journalctl` or `apt`; the tool says so.
* **No shell, anywhere.** Every external command is an argv list with a timeout, and a test checks that a
  metacharacter arrives as a literal argument.

## What I left out of this public version

The original also had GPU tools (utilisation sampling, hardware video transcoding and a benchmark, written for
one specific graphics card). They were useful on that machine and meaningless on most others, so they are not
here. What remains is the portable core.
