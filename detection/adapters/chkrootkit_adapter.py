"""
chkrootkit_adapter.py

Runs (or parses a saved log from) chkrootkit and normalizes its output
into DetectionResult objects, mirroring auditd_adapter.py's interface.

chkrootkit scans for known rootkit signatures, suspicious binaries,
and some LKM tampering indicators - this is your userland "does a
generic scanner catch this" baseline, separate from auditd's
syscall-level visibility.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from detection.detection_result import DetectionResult, DetectionStatus, Tier

TECHNIQUE_ID = "T1014"
TECHNIQUE_NAME = "Rootkit - Process/Module Hiding"

# chkrootkit prints "INFECTED" or "Warning" on lines with a positive hit;
# "not infected" / "not found" on clean lines.
_INFECTED_RE = re.compile(r"INFECTED|Warning", re.IGNORECASE)
_CLEAN_RE = re.compile(r"not infected|not found|nothing found", re.IGNORECASE)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    """
    log_path: path to a saved chkrootkit run output (e.g.
              docs/evidence/chkrootkit_run.log). If omitted, runs
              `chkrootkit` live (requires root).

    Returns one DetectionResult per flagged line, plus a single
    MISSED result if nothing was flagged at all.
    """
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        proc = subprocess.run(
            ["chkrootkit"],
            capture_output=True,
            text=True,
            check=False,
        )
        raw = proc.stdout + proc.stderr

    results: list[DetectionResult] = []
    flagged_lines = [
        line for line in raw.splitlines()
        if _INFECTED_RE.search(line) and not _CLEAN_RE.search(line)
    ]

    if flagged_lines:
        for line in flagged_lines:
            results.append(
                DetectionResult(
                    technique_id=TECHNIQUE_ID,
                    technique_name=TECHNIQUE_NAME,
                    source="chkrootkit",
                    tier=Tier.ADAPTER,
                    status=DetectionStatus.DETECTED,
                    raw_output=line.strip(),
                    evidence_path=str(log_path) if log_path else None,
                    notes="Flagged by chkrootkit scan.",
                )
            )
    else:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="chkrootkit",
                tier=Tier.ADAPTER,
                status=DetectionStatus.MISSED,
                raw_output=raw,
                evidence_path=str(log_path) if log_path else None,
                notes="chkrootkit reported no infection/warning lines.",
            )
        )

    return results