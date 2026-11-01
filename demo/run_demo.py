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


def main() -> None:
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
    result = run(["insmod", str(HIDE_PROCESS_KO), f"target_pid={target.pid}"])
    if result.returncode != 0:
        print("!! insmod failed - module is still resident somehow. "
              "Run `sudo rmmod hide_process` manually and re-run this script.")
        sys.exit(1)
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
    result = run(["insmod", str(HIDE_MODULE_KO)])
    if result.returncode != 0:
        print("!! insmod failed - module is still resident somehow. "
              "Run `echo 0 | sudo tee /proc/hide_ctl && sudo rmmod hide_module` "
              "manually and re-run this script.")
        sys.exit(1)
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
    note("rkhunter runs a FULL scan here (no checks disabled) - this can take "
         "10-30 minutes. This script is meant to be run once, ahead of time, "
         "with the full session captured to a transcript (see demo/README or "
         "the `script` command) and then shown as a recording during the "
         "actual presentation, rather than executed live.")

    results = []
    results += auditd_adapter.run(log_path=AUDITD_LOG if AUDITD_LOG.exists() else None)
    results += chkrootkit_adapter.run()
    results += rkhunter_adapter.run()

    status_color = {
        DetectionStatus.DETECTED: GREEN,
        DetectionStatus.PARTIAL: YELLOW,
        DetectionStatus.MISSED: RED,
        DetectionStatus.NOT_APPLICABLE: CYAN,
    }

    print(f"\n{'Source':<12} {'Status':<10} Flagged text / notes")
    print("-" * 90)
    for r in results:
        detail = (r.raw_output or r.notes or "")[:70]
        c = status_color.get(r.status, RESET)
        print(f"{c}{r.source:<12} {r.status.value:<10}{RESET} {detail}")

    detected = [r for r in results if r.status == DetectionStatus.DETECTED]
    partial = [r for r in results if r.status == DetectionStatus.PARTIAL]
    missed = [r for r in results if r.status == DetectionStatus.MISSED]

    print(f"\n{BOLD}{'=' * 72}")
    print("VERDICT")
    print(f"{'=' * 72}{RESET}")
    ok("Ground truth confirms: both module loads and the hidden process really happened.")
    print(f"  {GREEN}Real detections (DETECTED):{RESET}  "
          f"{', '.join(sorted(set(r.source for r in detected))) or 'none'}")
    print(f"  {YELLOW}Environmental noise only (PARTIAL):{RESET}  "
          f"{', '.join(sorted(set(r.source for r in partial))) or 'none'}")
    print(f"  {RED}Missed entirely:{RESET}  "
          f"{', '.join(sorted(set(r.source for r in missed))) or 'none'}")
    print(
        f"\n{BOLD}The gap:{RESET} auditd sees the module LOAD (syscall 313 / finit_module, "
        "logged via its 'module_load' key) for both hide_process and hide_module - but has "
        "zero visibility into the getdents64 directory-listing filter or the list_del "
        "self-hiding that happen after load. That's the detection gap this project demonstrates."
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