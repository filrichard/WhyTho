
# whytho

**whytho** is a cross-platform UNIX process investigation tool that explains **why a process is running** by analyzing OS-level evidence such as its executable, parent process, launch context, privileges, and runtime behavior.

It is designed for **macOS and Linux**, built in **C/C++**, and focuses on *explanation and transparency* rather than surveillance or automation.

---

## Motivation

When inspecting a system, it’s common to encounter unfamiliar or suspicious-looking processes. Tools like `ps`, `top`, and `lsof` expose raw data, but they don’t answer the higher-level question:

> *Why is this process running?*

**whytho** bridges that gap by:
- Collecting process metadata from the operating system
- Inferring likely launch reasons (service, user action, shell, etc.)
- Highlighting notable or unusual traits with evidence
- Optionally generating a human-readable explanation

whytho does **not** claim to determine intent or label processes as malicious. Instead, it presents facts, inferences, and caveats so the user can make informed decisions.

---

## Features

### Core
- Inspect a process by PID
- Display executable path, user, parent process, and start time
- Show command line (when permitted by the OS)
- Rule-based findings that highlight noteworthy traits
- Clear, structured CLI output

### Platform-aware analysis
- macOS: launchd ancestry, executable location, permission constraints
- Linux: `/proc`-based inspection, service/daemon inference (where possible)

### Optional AI-assisted explanation
- `--help-ai` flag generates a natural-language explanation
- AI is used **only as an explainer**, never as the source of truth
- All AI input is structured, minimized, and privacy-aware

### Output modes
- Human-readable CLI output
- (Planned) JSON output for scripting and automation

---

## Example usage

```sh
# Inspect a process by PID
whytho 1234

# Include additional context and explanations
whytho 1234 --verbose

# Request an AI-generated explanation (optional)
whytho 1234 --help-ai
