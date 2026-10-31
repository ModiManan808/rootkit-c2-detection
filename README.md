# eBPF-Based Detection Validation Against Kernel Rootkit and C2 Beaconing Techniques

**Domain:** Malware Analysis / Purple Teaming & Detection Engineering

> **Status: ~50% complete.** Module 1 (kernel rootkit + eBPF ground truth + baseline detection) is fully implemented and evidenced. The shared three-tier detection architecture is built. Module 2 (C2 beaconing) and Module 3 (gap-analysis reporting) are not yet started. See [Progress](#progress) below.

---

## Problem Statement

Organizations invest heavily in detection tools (EDR, SIEM, host-based monitoring) and generally assume these tools will catch real attacker behavior once deployed — an assumption that's rarely tested. This project asks a narrower, testable question:

> *Does our specific detection setup catch this specific, real attacker technique, and if not, why not?*

## Objectives

- Implement a real Linux kernel-level rootkit that hides a process and a kernel module via syscall hooking.
- Implement a C2 beaconing simulator that mimics real covert, periodic outbound communication.
- Build an eBPF-based instrumentation layer that observes both techniques at the kernel/network level, independent of any tool the rootkit itself could deceive.
- Build a baseline detection layer (auditd, chkrootkit/rkhunter, custom eBPF alerting, basic traffic analysis) representing "what a typical monitoring setup would catch."
- Compare ground-truth behavior against what the detection layer actually flags.
- Auto-generate a structured gap-analysis report per technique.

## Background

This project sits within an established practice known as purple teaming / detection engineering — validating detection controls against real, reproducible attacker techniques rather than trusting vendor claims. Two reference tools informed its design:

- **Atomic Red Team** (Red Canary) — an open-source library of single-technique attack simulations mapped to MITRE ATT&CK.
- **MITRE CALDERA** — an automated adversary emulation platform for observing detection coverage in real time.

Both are largely userland- and Windows-oriented. This project's contribution is a Linux kernel-level rootkit technique combined with a purpose-built eBPF detection/instrumentation layer, plus a network-layer C2 beaconing technique, covering two distinct stages of the attack lifecycle (defense evasion and command-and-control, per MITRE ATT&CK).

## Scope

| Module | Contents |
|---|---|
| **Module 1: Kernel Rootkit** ✅ | LKM with syscall hooking, process hiding (`getdents64`), module self-hiding (`lsmod`), eBPF ground-truth probes, baseline detection check |
| **Module 2: C2 Beaconing** ⏭️ | Periodic check-in agent with randomized intervals, network-level periodicity detection |
| **Module 3: Gap Analysis & Reporting** ⏭️ | Ground-truth vs. detection comparison, auto-generated per-technique report |

**Explicitly out of scope:** no interaction with real/third-party/production systems, no live malware samples, no persistence beyond the lab VM, no external exfiltration. Everything runs in an isolated VM.

## Technology Stack

| Component | Technology |
|---|---|
| Rootkit development | C, Linux Kernel Modules (LKM) |
| Kernel/network instrumentation | eBPF (bcc / libbpf) |
| Beaconing simulator | Python |
| Baseline detection | auditd, chkrootkit, rkhunter, custom eBPF alerting, scapy / tshark |
| Reporting engine | Python, python-docx |
| Lab environment | Isolated Linux VM |

## Repository Structure

```
rootkit-c2-detection/
├── detection/                   # Shared three-tier detection architecture
│   ├── detection_result.py      # DetectionResult / GapAnalysisEntry schema
│   ├── adapters/                # Per-tool adapters (auditd, chkrootkit, rkhunter, ...)
│   ├── correlation/              # Ground-truth vs. adapter correlation logic
│   └── manual/                   # Human-reviewed findings
├── ebpf/
│   └── ground_truth_logs/        # eBPF probe output (module load, fork/exit events)
├── module1-rootkit/               # LKM: syscall hooking, process/module hiding
├── module2-c2-beacon/             # Not started
├── module3-reporting/             # Not started
├── docs/
│   └── evidence/                  # Saved run logs used as detection evidence
├── .gitignore
└── README.md
```

---

## Progress

### ✅ Module 1 — Kernel Rootkit (complete, evidenced)

- **Process hiding**: `getdents64` kretprobe hook, hides a target process from `ps`/`top`-style enumeration.
- **Module self-hiding**: unlinks from the kernel's module list via `list_del`/`list_add`, hides from `lsmod`.
- Both tested live against `ps`, `lsmod`, and `/proc`.
- **eBPF ground-truth monitor**: module load + fork/exit tracepoints, confirmed catching both hidden events independent of the rootkit's manipulation.
- **Baseline detection**:
  - `auditd` — catches the `finit_module` syscall by name, but has no visibility into the `list_del`/`list_add` hiding itself.
  - `chkrootkit` / `rkhunter` adapters — userland scanner baseline, integration complete.
- Evidence logs saved under `docs/evidence/` (`ground_truth_run.log`, `auditd_module_load.log`).

### ✅ Shared Detection Architecture (built)

Three-tier design in `detection/`, independent of any single module so Module 2 can reuse it directly:

- **Adapter tier** — normalizes raw tool output (auditd, chkrootkit, rkhunter) into a common `DetectionResult` shape.
- **Correlation tier** — compares adapter results against eBPF ground truth to produce a per-technique `DetectionStatus` (detected / missed / partial).
- **Manual tier** — human-reviewed findings merged in alongside automated results.

### ⏭️ Not started

- **Module 2 — C2 Beaconing**: periodic check-in agent, network-level periodicity detection.
- **Module 3 — Gap Analysis & Reporting**: correlation output → auto-generated per-technique report (technique ID, evidence, impact, remediation). Report authored manually rather than auto-generated, per current plan.

---

## Evaluation Plan

- **Correctness**: each technique reliably reproduces its intended real-world behavior (e.g., process is genuinely hidden from `ps` but present in the true kernel task list).
- **Detection coverage**: number of techniques (out of 2, across component behaviors) flagged by baseline detection vs. missed.
- **Report quality**: each generated report reviewed for completeness — evidence, impact, remediation — against professional VAPT reporting standards.

## Expected Outcome

A working lab demonstration in which a real kernel rootkit and a real C2 beacon are executed against a baseline detection setup, with eBPF-based instrumentation proving exactly what happened at the system level regardless of what the detection layer reported — giving a concrete, evidence-based answer to "does this detection setup actually work," rather than an assumption.
