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

# chkrootkit prints "INFECTED" only when a known rootkit SIGNATURE
# actually matches - that's a real, specific hit. It also prints
# generic "Warning" lines (promiscuous interface, deleted-but-held
# files, lastlog/wtmp anomalies) that fire on almost any Linux box and
# have nothing to do with the specific hiding technique this project
# tests. Since hide_process/hide_module are custom, unsignatured LKMs,
# chkrootkit realistically can only ever produce the generic warnings,
# never a true signature match - counting those as "detected" would
# misrepresent the actual gap. Split them: INFECTED = real detection,
# Warning-only = PARTIAL (environmental noise, needs manual review).
_INFECTED_RE = re.compile(r"\bINFECTED\b", re.IGNORECASE)
_WARNING_RE = re.compile(r"\bWarning\b", re.IGNORECASE)
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
        try:
            proc = subprocess.run(
                ["chkrootkit"],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return [
                DetectionResult(
                    technique_id=TECHNIQUE_ID,
                    technique_name=TECHNIQUE_NAME,
                    source="chkrootkit",
                    tier=Tier.ADAPTER,
                    status=DetectionStatus.NOT_APPLICABLE,
                    raw_output=None,
                    notes="chkrootkit is not installed on this host "
                          "(sudo apt install chkrootkit).",
                )
            ]
        raw = proc.stdout + proc.stderr

    results: list[DetectionResult] = []
    infected_lines = [
        line for line in raw.splitlines()
        if _INFECTED_RE.search(line) and not _CLEAN_RE.search(line)
    ]
    warning_lines = [
        line for line in raw.splitlines()
        if _WARNING_RE.search(line) and not _INFECTED_RE.search(line) and not _CLEAN_RE.search(line)
    ]

    for line in infected_lines:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="chkrootkit",
                tier=Tier.ADAPTER,
                status=DetectionStatus.DETECTED,
                raw_output=line.strip(),
                evidence_path=str(log_path) if log_path else None,
                notes="Signature match - real positive hit.",
            )
        )
    for line in warning_lines:
        results.append(
            DetectionResult(
                technique_id=TECHNIQUE_ID,
                technique_name=TECHNIQUE_NAME,
                source="chkrootkit",
                tier=Tier.ADAPTER,
                status=DetectionStatus.PARTIAL,
                raw_output=line.strip(),
                evidence_path=str(log_path) if log_path else None,
                notes="Generic environmental warning, not a signature match on "
                      "this technique - review before counting as a detection.",
            )
        )

    if not infected_lines and not warning_lines:
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