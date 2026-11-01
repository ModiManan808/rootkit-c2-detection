"""
chkrootkit_adapter.py

Runs chkrootkit and reports EXACTLY what it says - no false-positive
filtering, no relevance judgment. If chkrootkit prints "INFECTED" or
"Warning" on a line, that's a real DETECTED result. If it doesn't,
that's MISSED. The report-level gap analysis is: ground truth says
this happened, tool says detected/missed - that comparison IS the
finding, not a pre-filtered version of it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from detection.detection_result import DetectionResult, DetectionStatus, Tier

TECHNIQUE_ID = "T1014"
TECHNIQUE_NAME = "Rootkit - Process/Module Hiding"

_INFECTED_RE = re.compile(r"\bINFECTED\b", re.IGNORECASE)
_WARNING_RE = re.compile(r"\bWarning\b", re.IGNORECASE)
_CLEAN_RE = re.compile(r"not infected|not found|nothing found", re.IGNORECASE)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        try:
            proc = subprocess.run(
                ["chkrootkit"], capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            return [DetectionResult(
                technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
                source="chkrootkit", tier=Tier.ADAPTER,
                status=DetectionStatus.NOT_APPLICABLE, raw_output=None,
                notes="chkrootkit is not installed on this host.",
            )]
        raw = proc.stdout + proc.stderr

    flagged = [
        line for line in raw.splitlines()
        if (_INFECTED_RE.search(line) or _WARNING_RE.search(line))
        and not _CLEAN_RE.search(line)
    ]

    results: list[DetectionResult] = []
    if flagged:
        for line in flagged:
            results.append(DetectionResult(
                technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
                source="chkrootkit", tier=Tier.ADAPTER,
                status=DetectionStatus.DETECTED,
                raw_output=line.strip(), evidence_path=str(log_path) if log_path else None,
                notes="Raw chkrootkit output - flagged as INFECTED or Warning.",
            ))
    else:
        results.append(DetectionResult(
            technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
            source="chkrootkit", tier=Tier.ADAPTER,
            status=DetectionStatus.MISSED, raw_output=raw,
            evidence_path=str(log_path) if log_path else None,
            notes="chkrootkit reported no infection/warning lines.",
        ))
    return results