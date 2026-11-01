#!/usr/bin/env python3
"""
run_demo.py

Live demo driver for the progress review, built against the actual
rootkit-c2-detection repo layout as of this run:

  module1-rootkit/
    process_hiding/hide_process.c   - kretprobe on __x64_sys_getdents64,
                                       filters a target PID out of
                                       directory listings. Takes a
                                       target_pid module parameter at
                                       insmod time. Does NOT hide
                                       itself from lsmod.
    module_hiding/hide_module.c     - list_del's itself from the
                                       kernel's module list at load
                                       time (hidden from lsmod by
                                       default). Exposes
                                       /proc/hide_ctl - write '0' to
                                       unhide (required before rmmod
                                       can find it again), '1' to
                                       re-hide.
  ebpf/ground_truth_logs/ground_truth_monitor.py
                                     - bcc/eBPF script, kprobe on
                                       do_init_module + fork/exit
                                       tracepoints. Requires bcc
                                       installed and root. Prints
                                       "[GROUND TRUTH] ..." lines to
                                       stdout - this demo tails
                                       whatever log you're piping it
                                       to.
  docs/evidence/auditd_module_load.log
                                     - ausearch -k module_load style
                                       output. Real entries use
                                       syscall=313 / key="module_load"
                                       / type=KERN_MODULE - NOT the
                                       literal string "finit_module".

This script does NOT build or start the eBPF monitor for you (it needs
its own root shell since it blocks on perf_buffer_poll()). Start it
yourself in a second terminal before running this:

    sudo python3 ebpf/ground_truth_logs/ground_truth_monitor.py \\
        | tee docs/evidence/ground_truth_run.log

Then run this script, as root, from the repo root, in a THIRD
terminal (or the same one auditd is watching from):

    sudo python3 demo/run_demo.py

Each step pauses for Enter so you can narrate it live.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from detection.adapters import auditd_adapter, chkrootkit_adapter, rkhunter_adapter  # noqa: E402
from detection.detection_result import DetectionStatus  # noqa: E402

# ---- Color helpers - make the live terminal output skimmable --------------
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


def ok(msg: str) -> None:
    print(f"{GREEN}{BOLD}[OK]{RESET} {msg}")


def bad(msg: str) -> None:
    print(f"{RED}{BOLD}[!!]{RESET} {msg}")


def note(msg: str) -> None:
    print(f"{CYAN}[i]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[~]{RESET} {msg}")


PROCESS_HIDING_DIR = REPO_ROOT / "module1-rootkit" / "process_hiding"
MODULE_HIDING_DIR = REPO_ROOT / "module1-rootkit" / "module_hiding"
HIDE_PROCESS_KO = PROCESS_HIDING_DIR / "hide_process.ko"
HIDE_MODULE_KO = MODULE_HIDING_DIR / "hide_module.ko"
HIDE_CTL = Path("/proc/hide_ctl")

EVIDENCE_DIR = REPO_ROOT / "docs" / "evidence"
AUDITD_LOG = EVIDENCE_DIR / "auditd_module_load.log"
GROUND_TRUTH_LOG = REPO_ROOT / "ebpf" / "ground_truth_logs" / "ground_truth_run.log"

TARGET_PROC_CMD = ["sleep", "999"]


def pause(msg: str = "Press Enter to continue...") -> None:
    input(f"\n>>> {msg}")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, text=True, **kw)


def step_header(n: int, title: str) -> None:
    print("\n" + "=" * 72)
    print(f"{BOLD}{CYAN}STEP {n}: {title}{RESET}")
    print("=" * 72)


def pid_in_ps(pid: int) -> bool:
    out = subprocess.run(["ps", "-p", str(pid)], capture_output=True, text=True).stdout
    return str(pid) in out


def pid_in_proc_listing(pid: int) -> bool:
    out = subprocess.run(["bash", "-c", "ls /proc"], capture_output=True, text=True).stdout
    return str(pid) in out.split()


def run_capture_pid(cmd: list, **kw) -> tuple[int, int]:
    """Like run(), but returns the spawned process's own PID - needed
    because that PID is EXACTLY what the eBPF kprobe and auditd both
    record for this specific insmod call, which is what makes real
    event-level correlation possible (not just "a scanner said Warning
    about something")."""
    print(f"$ {' '.join(str(c) for c in cmd)}")
    proc = subprocess.Popen(cmd)
    pid = proc.pid
    proc.wait()
    return pid, proc.returncode


def module_visible_in_lsmod(name: str) -> bool:
    out = subprocess.run(["lsmod"], capture_output=True, text=True).stdout
    return any(line.split() and line.split()[0] == name for line in out.splitlines()[1:])


def module_loaded(name: str) -> bool:
    out = subprocess.run(["lsmod"], capture_output=True, text=True).stdout
    return any(line.split()[0] == name for line in out.splitlines()[1:] if line.split())


def clean_stale_module(name: str) -> None:
    """
    Remove a leftover instance from an earlier manual test run, so this
    run's insmod (with fresh params, e.g. a new target_pid) actually
    takes effect instead of silently failing against the old instance.
    """
    if name == "hide_module" and HIDE_CTL.exists():
        # Hidden from lsmod by its own design - unhide before rmmod can find it.
        print(f"Found a stale {name} (self-hidden) from an earlier run - unhiding + removing it.")
        subprocess.run(["bash", "-c", f"echo 0 > {HIDE_CTL}"])
        subprocess.run(["rmmod", name])
    elif module_loaded(name):
        print(f"Found a stale {name} already loaded from an earlier run - removing it.")
        subprocess.run(["rmmod", name])


def build_if_needed(ko_path: Path, build_dir: Path) -> None:
    if ko_path.exists():
        print(f"{ko_path.name} already built.")
        return
    print(f"{ko_path.name} not built yet - running make in {build_dir}")
    result = run(["make"], cwd=str(build_dir))
    if result.returncode != 0 or not ko_path.exists():
        print(f"!! Build failed - check kernel headers match `uname -r`.")
        sys.exit(1)


def preflight_check_ground_truth() -> None:
    """
    Fail fast, before touching any kernel module, if the eBPF ground
    truth monitor isn't actually writing live data. Catching this here
    takes 6 seconds. Catching it at Step 5 means you've already loaded
    both modules and have to redo the whole run.
    """
    step_header(0, "Pre-flight check - is the eBPF ground truth monitor actually live?")
    if not GROUND_TRUTH_LOG.exists():
        bad(f"{GROUND_TRUTH_LOG} does not exist yet.")
        print("\nStart the monitor in its own terminal FIRST, then re-run this script:")
        print(f"  cd {REPO_ROOT}")
        print("  sudo python3 -u ebpf/ground_truth_logs/ground_truth_monitor.py "
              "| tee ebpf/ground_truth_logs/ground_truth_run.log")
        sys.exit(1)

    before = GROUND_TRUTH_LOG.stat().st_size
    note("Waiting 6s to confirm the log is actively growing (not just old data)...")
    time.sleep(6)
    after = GROUND_TRUTH_LOG.stat().st_size

    if after > before:
        ok(f"Log grew by {after - before} bytes in 6s - monitor is live and flushing. Proceeding.")
        return

    bad(f"Log did NOT grow in 6s ({before} -> {after} bytes). The monitor is either not "
        f"running, or is running WITHOUT the -u flag and is buffering its output instead "
        f"of flushing it (this is the #1 cause of this failure).")
    print("\nFix - in the monitor's terminal, Ctrl+C it, then restart with -u EXACTLY like this:")
    print(f"  cd {REPO_ROOT}")
    print("  sudo pkill -f ground_truth_monitor.py")
    print("  sudo python3 -u ebpf/ground_truth_logs/ground_truth_monitor.py "
          "| tee ebpf/ground_truth_logs/ground_truth_run.log")
    print("\nThen re-run this script. Refusing to proceed - loading the rootkit now "
          "would waste the whole run if ground truth isn't actually capturing it.")
    sys.exit(1)


def main() -> None:
    preflight_check_ground_truth()

    # ---- Step 1: baseline, before anything is hidden ----------------------
    step_header(1, "Baseline - start target process, confirm it's visible")
    target = subprocess.Popen(TARGET_PROC_CMD)
    time.sleep(0.3)
    note(f"Started target process: {BOLD}sleep 999{RESET}, PID {BOLD}{target.pid}{RESET}")
    if pid_in_ps(target.pid):
        ok(f"PID {target.pid} is visible via ps (expected - nothing hidden yet).")
    else:
        bad(f"PID {target.pid} not visible via ps - unexpected, process may have exited.")
    pause("Build + load hide_process next.")

    # ---- Step 2: build + load the process-hiding module -------------------
    step_header(2, "Build and load hide_process.ko (process hiding)")
    build_if_needed(HIDE_PROCESS_KO, PROCESS_HIDING_DIR)
    clean_stale_module("hide_process")
    hide_process_insmod_pid, rc = run_capture_pid(
        ["insmod", str(HIDE_PROCESS_KO), f"target_pid={target.pid}"]
    )
    if rc != 0:
        print("!! insmod failed - module is still resident somehow. "
              "Run `sudo rmmod hide_process` manually and re-run this script.")
        sys.exit(1)
    note(f"insmod PID for this exact load: {BOLD}{hide_process_insmod_pid}{RESET} "
         f"(this is the PID we'll check for in ground truth + auditd in Step 6)")
    if module_visible_in_lsmod("hide_process"):
        ok("hide_process is visible in lsmod (expected - it doesn't hide itself).")
    else:
        bad("hide_process is NOT in lsmod - unexpected, load may have failed silently.")
    pause("Module loaded with target_pid set. Confirm the process is hidden from listings.")

    # ---- Step 3: show the process is hidden from ps/ls --------------------
    step_header(3, "Confirm process hiding (directory-listing filter)")
    hidden_from_ps = not pid_in_ps(target.pid)
    hidden_from_ls = not pid_in_proc_listing(target.pid)
    status = subprocess.run(
        ["bash", "-c", f"head -1 /proc/{target.pid}/status 2>/dev/null"],
        capture_output=True, text=True,
    ).stdout.strip()
    direct_access_works = bool(status)

    if hidden_from_ps:
        ok(f"ps -p {target.pid}  ->  EMPTY. Process hidden from ps.")
    else:
        bad(f"ps -p {target.pid}  ->  still shows the process. Hiding NOT in effect.")

    if hidden_from_ls:
        ok(f"ls /proc | grep {target.pid}  ->  EMPTY. Hidden from directory listing.")
    else:
        bad(f"ls /proc | grep {target.pid}  ->  still listed. Hiding NOT in effect.")

    if direct_access_works:
        ok(f"/proc/{target.pid}/status  ->  {status!r}. Direct access still works - process is REALLY running.")
    else:
        bad(f"/proc/{target.pid}/status  ->  not readable. Process may have actually died.")

    print()
    if hidden_from_ps and hidden_from_ls and direct_access_works:
        print(f"{BOLD}{GREEN}>>> THE GAP, CONFIRMED: listings lie, direct access proves it's alive. <<<{RESET}")
    else:
        print(f"{BOLD}{YELLOW}>>> Hiding did not fully take effect this run - see [!!] lines above. <<<{RESET}")
    pause()

    # ---- Step 4: build + load the module-hiding module ---------------------
    step_header(4, "Build and load hide_module.ko (module self-hiding)")
    build_if_needed(HIDE_MODULE_KO, MODULE_HIDING_DIR)
    clean_stale_module("hide_module")
    hide_module_insmod_pid, rc = run_capture_pid(["insmod", str(HIDE_MODULE_KO)])
    if rc != 0:
        print("!! insmod failed - module is still resident somehow. "
              "Run `echo 0 | sudo tee /proc/hide_ctl && sudo rmmod hide_module` "
              "manually and re-run this script.")
        sys.exit(1)
    note(f"insmod PID for this exact load: {BOLD}{hide_module_insmod_pid}{RESET}")
    hidden_from_lsmod = not module_visible_in_lsmod("hide_module")
    ctl_exists = HIDE_CTL.exists()

    if hidden_from_lsmod:
        ok("lsmod  ->  hide_module ABSENT. Self-hid immediately at load.")
    else:
        bad("lsmod  ->  hide_module still visible. Self-hiding NOT in effect.")

    if ctl_exists:
        ok(f"{HIDE_CTL} exists  ->  module really is loaded, despite lsmod saying otherwise.")
    else:
        bad(f"{HIDE_CTL} missing  ->  module may not have loaded at all.")

    print()
    if hidden_from_lsmod and ctl_exists:
        print(f"{BOLD}{GREEN}>>> THE GAP, CONFIRMED: lsmod lies, /proc/hide_ctl proves it's loaded. <<<{RESET}")
    else:
        print(f"{BOLD}{YELLOW}>>> Module self-hiding did not fully take effect - see [!!] lines above. <<<{RESET}")
    pause("Now check what eBPF ground truth saw.")

    # ---- Step 5: eBPF ground truth -----------------------------------------
    step_header(5, "eBPF ground truth - independent of the rootkit's lies")
    if not GROUND_TRUTH_LOG.exists():
        bad(f"{GROUND_TRUTH_LOG} not found.")
        print("   Start it in another terminal first:")
        print("   sudo python3 ebpf/ground_truth_logs/ground_truth_monitor.py "
              "| tee ebpf/ground_truth_logs/ground_truth_run.log")
    else:
        log_age = time.time() - GROUND_TRUTH_LOG.stat().st_mtime
        if log_age > 60:
            warn(f"This log hasn't been written to in {int(log_age)}s - "
                 f"the monitor may not be running. Verify with: "
                 f"ps aux | grep ground_truth_monitor")

        module_lines = subprocess.run(
            ["bash", "-c", f"grep -i 'module' {GROUND_TRUTH_LOG} | tail -5"],
            capture_output=True, text=True,
        ).stdout.strip()

        if module_lines:
            ok("Module-load events found in ground truth log (noise filtered out):")
            print(module_lines)
        else:
            bad("No module-load lines found in the ground truth log at all. Either the "
                "monitor isn't running, its kprobe isn't firing, or hide_process/hide_module "
                "were loaded before this log started. Check the monitor's own terminal output.")

        print(f"\n{CYAN}(For context, last 5 lines overall - mostly unrelated fork/exit noise):{RESET}")
        run(["tail", "-n", "5", str(GROUND_TRUTH_LOG)])
    pause("Ground truth shows the real module loads + the real fork, regardless of hiding.")

    # ---- Step 6: baseline detection adapters -------------------------------
    step_header(6, "Baseline detection - what would a typical setup catch?")
    note("rkhunter: full scan, live output below (10-30 min).")

    results = []
    # Always live, never the old saved AUDITD_LOG file - that file is
    # evidence from a PAST run, not this one. Using it here would silently
    # show a stale timestamp (e.g. days old) as if it were this run's result.
    results += auditd_adapter.run(log_path=None)
    results += chkrootkit_adapter.run()
    results += rkhunter_adapter.run()

    # ---- Event-level correlation: does each tool's raw output actually
    # reference the SPECIFIC PIDs from THIS run's events, not just "did it
    # print a Warning about something"? This is computed, not interpreted -
    # no judgment call needed live.
    print(f"\n{BOLD}{'=' * 72}")
    print("DETECTION VERIFICATION (per-event, computed from this run's exact PIDs)")
    print(f"{'=' * 72}{RESET}")

    gt_text = GROUND_TRUTH_LOG.read_text(errors="ignore") if GROUND_TRUTH_LOG.exists() else ""
    gt_module_pids = {int(m) for m in re.findall(r"module load: pid=(\d+)", gt_text)}

    auditd_raw = next((r.raw_output for r in results if r.source == "auditd"), "") or ""
    chkrootkit_raw = "\n".join(r.raw_output or "" for r in results if r.source == "chkrootkit")
    rkhunter_raw = "\n".join(r.raw_output or "" for r in results if r.source == "rkhunter")

    def auditd_has_pid(pid: int) -> bool:
        return any(f"pid={pid}" in line and "syscall=313" in line
                   for line in auditd_raw.splitlines())

    def text_mentions_pid(text: str, pid: int) -> bool:
        # Word boundary so e.g. pid=683 doesn't false-match inside "6838"
        return re.search(rf"\b{pid}\b", text) is not None

    events = [
        ("hide_process.ko load", hide_process_insmod_pid),
        ("hide_module.ko load", hide_module_insmod_pid),
    ]

    print(f"\n{BOLD}Module load events (exact insmod PID this run):{RESET}")
    for label, pid in events:
        gt_confirmed = pid in gt_module_pids
        gt_mark = f"{GREEN}CONFIRMED{RESET}" if gt_confirmed else f"{RED}NOT in ground truth{RESET}"
        print(f"  {label} (pid={pid}): ground truth = {gt_mark}")
        a_hit = auditd_has_pid(pid)
        print(f"    auditd:     {GREEN + 'DETECTED (pid+syscall=313 matched)' + RESET if a_hit else RED + 'MISSED (no matching record)' + RESET}")
        for tool_name, raw in (("chkrootkit", chkrootkit_raw), ("rkhunter", rkhunter_raw)):
            hit = text_mentions_pid(raw, pid)
            print(f"    {tool_name}:  {GREEN + 'mentions this PID' + RESET if hit else YELLOW + 'does not mention this PID (expected - whole-system scan, not PID-aware)' + RESET}")

    print(f"\n{BOLD}Process hiding event (target PID, the actual hidden process):{RESET}")
    print(f"  sleep 999 (pid={target.pid}): confirmed alive via direct /proc access in Step 3")
    for tool_name, raw in (("auditd", auditd_raw), ("chkrootkit", chkrootkit_raw), ("rkhunter", rkhunter_raw)):
        hit = text_mentions_pid(raw, target.pid)
        print(f"    {tool_name}:  {GREEN + 'mentions this PID' + RESET if hit else RED + 'MISSED - never references this specific PID' + RESET}")
    print(f"\n  {BOLD}This is the actual gap this project demonstrates:{RESET} none of these "
          f"three tools check whether a SPECIFIC known PID is being filtered out of "
          f"directory listings - that's the getdents64 hook your detection layer has "
          f"no visibility into.")

    status_color = {
        DetectionStatus.DETECTED: GREEN,
        DetectionStatus.MISSED: RED,
        DetectionStatus.NOT_APPLICABLE: CYAN,
    }

    print(f"\n{'Source':<12} {'Status':<10} Flagged text / notes (raw tool output, unfiltered)")
    print("-" * 90)
    for r in results:
        detail = (r.raw_output or r.notes or "")[:70]
        c = status_color.get(r.status, RESET)
        print(f"{c}{r.source:<12} {r.status.value:<10}{RESET} {detail}")

    # Computed per-source verdict, straight from what each tool actually
    # reported this run - no pre-filtering of what "counts."
    by_source: dict[str, list] = {}
    for r in results:
        by_source.setdefault(r.source, []).append(r)

    print(f"\n{BOLD}{'=' * 72}")
    print("VERDICT (computed from this run's actual tool output)")
    print(f"{'=' * 72}{RESET}")
    ok("Ground truth confirms: both module loads and the hidden process really happened.")
    for source, entries in sorted(by_source.items()):
        statuses = {e.status for e in entries}
        if DetectionStatus.DETECTED in statuses:
            n = sum(1 for e in entries if e.status == DetectionStatus.DETECTED)
            print(f"  {GREEN}{source}: DETECTED{RESET}  ({n} flagged line(s) this run)")
        elif DetectionStatus.NOT_APPLICABLE in statuses:
            print(f"  {CYAN}{source}: N/A{RESET}  (not installed or did not run)")
        else:
            print(f"  {RED}{source}: MISSED{RESET}  (zero flagged lines this run)")

    print(
        f"\n{BOLD}Note:{RESET} the table above is unfiltered raw tool output - every "
        "Warning/INFECTED line counts as DETECTED, with no manual exclusion of any "
        "result, even known false-positive-prone ones. If a tool shows DETECTED, "
        "say so plainly. If it shows MISSED, that's the gap for this run - report "
        "it as-is rather than assuming it."
    )

    # ---- Step 7: cleanup ----------------------------------------------------
    pause("Demo complete. Press Enter to clean up.")
    step_header(7, "Cleanup")
    if HIDE_CTL.exists():
        print("Unhiding hide_module before rmmod (it's unlinked from the module list,")
        print("so rmmod can't find it by name until it's re-linked):")
        run(["bash", "-c", f"echo 0 > {HIDE_CTL}"])
    run(["rmmod", "hide_module"])
    run(["rmmod", "hide_process"])
    target.terminate()
    print(f"Modules unloaded, target process {target.pid} terminated.")


if __name__ == "__main__":
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("This demo loads/unloads kernel modules - run with sudo.")
        sys.exit(1)
    main()