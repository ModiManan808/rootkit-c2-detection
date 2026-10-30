# eBPF-Based Detection Validation Against Kernel Rootkit and C2 Beaconing Techniques

**Domain:** Malware Analysis / Purple Teaming & Detection Engineering

> ⚠️ **Status: Early development.** This repo currently contains rootkit-side building blocks (kernel modules) and a basic detection question being tested. It is not yet a complete detection-validation pipeline. See [Progress](#progress) below for exactly what works today.

---

## Problem Statement

Organizations invest heavily in detection tools (EDR, SIEM, host-based monitoring) and generally assume these tools will catch real attacker behavior once deployed, an assumption that's rarely tested. This project asks a narrower, testable question:

> *Does our specific detection setup catch this specific, real attacker technique, and if not, why not?*

## Objectives

- Implement a real Linux kernel-level rootkit that hides a process and a kernel module via syscall hooking.
- Implement a C2 beaconing simulator that mimics real covert, periodic outbound communication.
- Build an eBPF-based instrumentation layer that observes both techniques at the kernel/network level, independent of any tool the rootkit itself could deceive.
- Build a baseline detection layer (auditd, custom eBPF alerting, basic traffic analysis) representing "what a typical monitoring setup would catch."
- Compare ground-truth behavior against what the detection layer actually flags.
- Auto-generate a structured gap-analysis report per technique.

## Background

This project sits within an established practice known as purple teaming / detection engineering, validating detection controls against real, reproducible attacker techniques rather than trusting vendor claims. Two reference tools informed its design:

- **Atomic Red Team** (Red Canary), an open-source library of single-technique attack simulations mapped to MITRE ATT&CK.
- **MITRE CALDERA**, an automated adversary emulation platform for observing detection coverage in real time.

Both are largely userland- and Windows-oriented. This project's contribution is a Linux kernel-level rootkit technique combined with a purpose-built eBPF detection/instrumentation layer, plus a network-layer C2 beaconing technique, covering two distinct stages of the attack lifecycle (defense evasion and command-and-control, per MITRE ATT&CK).

## Scope

| Module | Contents |
|---|---|
| **Module 1: Kernel Rootkit** (primary focus) | LKM with syscall hooking, process hiding (`getdents64`), module self-hiding (`lsmod`), eBPF ground-truth probes, baseline detection check |
| **Module 2: C2 Beaconing** | Periodic check-in agent with randomized intervals, network-level periodicity detection |
| **Module 3: Gap Analysis & Reporting** | Ground-truth vs. detection comparison, auto-generated per-technique report |

**Explicitly out of scope:** no interaction with real/third-party/production systems, no live malware samples, no persistence beyond the lab VM, no external exfiltration. Everything runs in an isolated VM.

## Technology Stack

| Component | Technology |
|---|---|
| Rootkit development | C, Linux Kernel Modules (LKM) |
| Kernel/network instrumentation | eBPF (bcc / libbpf) |
| Beaconing simulator | Python |
| Baseline detection | auditd, custom eBPF alerting, scapy / tshark |
| Reporting engine | Python, python-docx |
| Lab environment | Isolated Linux VM |

---

## Progress

### ✅ Done

- Lab environment set up (Ubuntu, kernel `7.0.0-31-generic`, `build-essential`, matching kernel headers), verified via successful module compilation.
- Basic "hello world" LKM (`module1-rootkit/hello_mod/`), confirms the build/load/unload toolchain works end-to-end.
- Syscall hook on `getdents64` via kprobes (`module1-rootkit/syscall_hook/`), logs the calling PID on every call. Used kprobes instead of direct `sys_call_table` patching since modern kernels don't export a writable table.
- Project folder structure mirroring the module breakdown above, with a dated progress log at `docs/progress-log.md`.

### 🔄 In progress

- **Process hiding** (`module1-rootkit/process_hiding/`): a post-handler on the `getdents64` kprobe intended to strip a target PID's directory entry so it disappears from `ps`/`top`. Builds and loads with no errors, but the target process is **not yet actually hidden**. Currently debugging whether the kprobe is intercepting correctly on this kernel version, and whether `ps` even goes through `getdents64` the way assumed.
- **Module self-hiding from `lsmod`** (`module1-rootkit/module_hiding/`): skeleton only, logic to unlink the module from the kernel's module list is stubbed with TODOs pending a locking check (`module_mutex`) before wiring it in.

### ⏭️ Not started

- C2 beaconing agent and network-level detection (Module 2)
- eBPF ground-truth instrumentation layer (Module 3 in timeline, Weeks 6–7), deliberately deferred until rootkit behaviors are functional, so there's something real to instrument
- Baseline detection layer (auditd rules / integrity checks)
- Gap-analysis and auto-report generation engine
