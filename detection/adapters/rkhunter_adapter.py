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

# rkhunter marks positive hits as "Warning" in its report; clean checks
# print "OK" or "Not found".
_WARNING_RE = re.compile(r"\bWarning\b", re.IGNORECASE)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    """
    log_path: path to a saved rkhunter report (e.g.
              docs/evidence/rkhunter_run.log, or rkhunter's own
              /var/log/rkhunter.log copied into docs/evidence/). If
              omitted, runs `rkhunter --check --sk` live (requires
              root; --sk skips interactive prompts).

    Returns one DetectionResult per "Warning" line, plus a single
    MISSED result if nothing was flagged at all.
    """
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        proc = subprocess.run(
            ["rkhunter", "--check", "--sk", "--rwo"],
            capture_output=True,
            text=True,
            check=False,
        )
        raw = proc.stdout + proc.stderr

    warning_lines = [line for line in raw.splitlines() if _WARNING_RE.search(line)]

    results: list[DetectionResult] = []

    if warning_lines:
        for line in warning_lines:
            results.append(
                DetectionResult(
                    technique_id=TECHNIQUE_ID,
                    technique_name=TECHNIQUE_NAME,
                    source="rkhunter",
                    tier=Tier.ADAPTER,
                    status=DetectionStatus.DETECTED,
                    raw_output=line.strip(),
                    evidence_path=str(log_path) if log_path else None,
                    notes="Flagged by rkhunter as a Warning.",
                )
            )
    else:
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