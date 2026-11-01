"""
auditd_adapter.py

Reference adapter implementation. All other adapters (chkrootkit,
rkhunter, ...) should mirror this function signature and return shape
so correlation.py can treat every tool identically.

This adapter parses auditd logs for the finit_module syscall (module
load events) - the baseline detection your rootkit testing already
confirmed: auditd catches the module *load* by name, but has no
visibility into the list_del/list_add self-hiding that happens after.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from detection.detection_result import DetectionResult, DetectionStatus, Tier

TECHNIQUE_ID = "T1014"
TECHNIQUE_NAME = "Rootkit - Kernel Module Load (finit_module)"

# auditd never prints the literal string "finit_module" - it logs the raw
# syscall number (313 = finit_module on x86_64), the audit key assigned to
# the watch rule ("module_load"), and a KERN_MODULE record with the module
# name. Match on any of those instead.
_FINIT_MODULE_RE = re.compile(
    r'syscall=313|key="module_load"|type=KERN_MODULE',
    re.IGNORECASE,
)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    """
    log_path: path to a saved auditd log (e.g.
              docs/evidence/auditd_module_load.log). If omitted, pulls
              live results via `ausearch -k module_load` instead.

    Returns a list with a single DetectionResult describing whether
    auditd flagged the module load.
    """
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        proc = subprocess.run(
            ["ausearch", "-k", "module_load"],
            capture_output=True,
            text=True,
            check=False,
        )
        raw = proc.stdout + proc.stderr

    hit = bool(_FINIT_MODULE_RE.search(raw))

    result = DetectionResult(
        technique_id=TECHNIQUE_ID,
        technique_name=TECHNIQUE_NAME,
        source="auditd",
        tier=Tier.ADAPTER,
        status=DetectionStatus.DETECTED if hit else DetectionStatus.MISSED,
        raw_output=raw,
        evidence_path=str(log_path) if log_path else None,
        notes=(
            "auditd flagged the finit_module syscall by name, but has no "
            "visibility into the list_del/list_add self-hiding performed "
            "after load."
            if hit
            else "No finit_module event found in the provided auditd log."
        ),
    )
    return [result]