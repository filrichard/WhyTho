# whytho

**whytho** is a UNIX process investigation tool that explains **why a process is running** by combining OS-level process metadata with evidence-based analysis.

It is designed for **macOS** (with Linux planned), written in **modern C++**, and focuses on **explanation and transparency** rather than surveillance or automated decision-making.

---

## Motivation

When inspecting a system, it’s common to encounter unfamiliar processes. Tools like `ps`, `top`, and `lsof` expose raw data, but they don’t answer the higher-level question:

> *Why is this process running?*

**whytho** bridges that gap by:
- Collecting process metadata directly from the OS
- Building a process ancestry chain
- Applying deterministic analysis rules
- Presenting human-readable explanations backed by evidence

whytho does **not** claim to infer intent or detect malware. It surfaces facts and patterns so users can make informed decisions.

---

## Features

### Core inspection
- Inspect a process by PID
- Display executable path, UID, PPID
- Build a depth-limited process ancestry chain
- Graceful handling of permission and race conditions

### Evidence-based analysis
- Detects system-managed vs user-session processes
- Identifies helper/child processes
- Assigns informational severity levels to findings
- Avoids speculative or destructive behavior

### Output modes
- **Human-readable CLI output**
- **Machine-readable JSON output** (`--json`)
  - Stable schema
  - Missing strings represented as `null`
  - Suitable for scripting and automation

### CLI ergonomics
- `--help`, `--version`
- Clear error messages
- Strict PID validation

---

## Building
```sh
make
```

---

## Example usage

### Human-readable output
```sh
./bin/whytho 866

whytho  •  explain why a process is running

Process: Brave Browser Helper (GPU)

PID: 866    User: 501
Executable: /Applications/Brave Browser.app/Contents/Frameworks/...

Why it's running:
  • Likely started under a user login session (launchd ancestry).
  • Application child process: Brave Browser → Brave Browser Helper (GPU)
  • Lineage: launchd → Brave Browser → Brave Browser Helper (GPU)

Ancestry:
  [866] /Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Versions/143.1.85.118/Helpers/Brave Browser Helper (GPU).app/Contents/MacOS/Brave Browser Helper (GPU)
  [654] /Applications/Brave Browser.app/Contents/MacOS/Brave Browser
  [1] /sbin/launchd
```
---

## Requirements
- C++
- macOS
- make
