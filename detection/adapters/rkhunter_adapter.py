"""
rkhunter_adapter.py

Runs (or parses a saved log from) rkhunter and normalizes its output
into DetectionResult objects, mirroring auditd_adapter.py's interface.

rkhunter checks file/module hashes, hidden ports, suspicious LKMs, and
known rootkit signatures - a second independent userland baseline
alongside chkrootkit, useful for showing whether *either* generic
scanner catches the hiding technique your rootkit performs.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from detection.detection_result import DetectionResult, DetectionStatus, Tier

TECHNIQUE_ID = "T1014"
TECHNIQUE_NAME = "Rootkit - Process/Module Hiding"

# rkhunter marks EVERY uncertain check as "Warning" - most are generic
# host hygiene (deleted files held open by a running process, hidden
# ports from legitimate services, SSH config advice) and fire on
# nearly any box, unrelated to this project's specific technique. Only
# a line that actually names rootkit/hidden-module/syscall-table
# concepts is a real signal for what we're testing; everything else
# that says "Warning" is PARTIAL - noise worth a manual look, not a
# genuine detection of hide_process/hide_module.
_WARNING_RE = re.compile(r"\bWarning\b", re.IGNORECASE)
_RELEVANT_RE = re.compile(
    r"rootkit|hidden process|hidden module|syscall|LKM|kernel module|/proc",
    re.IGNORECASE,
)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    """
    log_path: path to a saved rkhunter report (e.g.
              docs/evidence/rkhunter_run.log, or rkhunter's own
              /var/log/rkhunter.log copied into docs/evidence/). If
              omitted, runs the FULL rkhunter scan live (requires
              root) - no checks disabled, since this is meant to be
              run once ahead of time (as part of a captured full demo
              transcript), not live in front of an audience. A full
              scan including signature/hash checks can take 10-30
              minutes; the timeout below is generous (30 min) rather
              than tuned for speed.

    Returns one DetectionResult per "Warning" line, plus a single
    MISSED result if nothing was flagged at all, or NOT_APPLICABLE if
    the tool isn't installed or the run times out.
    """
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        try:
            proc = subprocess.run(
                ["rkhunter", "--check", "--sk", "--rwo", "--nocolors"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1800,
            )
        except FileNotFoundError:
            return [
                DetectionResult(
                    technique_id=TECHNIQUE_ID,
                    technique_name=TECHNIQUE_NAME,
                    source="rkhunter",
                    tier=Tier.ADAPTER,
                    status=DetectionStatus.NOT_APPLICABLE,
                    raw_output=None,
                    notes="rkhunter is not installed on this host "
                          "(sudo apt install rkhunter).",
                )
            ]
        except subprocess.TimeoutExpired:
            return [
                DetectionResult(
                    technique_id=TECHNIQUE_ID,
                    technique_name=TECHNIQUE_NAME,
                    source="rkhunter",
                    tier=Tier.ADAPTER,
                    status=DetectionStatus.NOT_APPLICABLE,
                    raw_output=None,
                    notes="rkhunter did not finish within 30 minutes - treat as "
                          "inconclusive for this run rather than a MISS.",
                )
            ]
        raw = proc.stdout + proc.stderr

    warning_lines = [line for line in raw.splitlines() if _WARNING_RE.search(line)]
    relevant_lines = [line for line in warning_lines if _RELEVANT_RE.search(line)]
    noise_lines = [line for line in warning_lines if line not in relevant_lines]

    results: list[DetectionResult] = []

    for line in relevant_lines:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="rkhunter",
                tier=Tier.ADAPTER,
                status=DetectionStatus.DETECTED,
                raw_output=line.strip(),
                evidence_path=str(log_path) if log_path else None,
                notes="Warning specifically names rootkit/module/syscall concepts.",
            )
        )
    for line in noise_lines:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="rkhunter",
                tier=Tier.ADAPTER,
                status=DetectionStatus.PARTIAL,
                raw_output=line.strip(),
                evidence_path=str(log_path) if log_path else None,
                notes="Generic host-hygiene warning, not specific to this "
                      "technique - review before counting as a detection.",
            )
        )

    if not warning_lines:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="rkhunter",
                tier=Tier.ADAPTER,
                status=DetectionStatus.MISSED,
                raw_output=raw,
                evidence_path=str(log_path) if log_path else None,
                notes="rkhunter reported no warnings.",
            )
        )

    return results