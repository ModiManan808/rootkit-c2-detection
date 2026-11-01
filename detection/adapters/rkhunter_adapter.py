"""
rkhunter_adapter.py

Runs the FULL rkhunter scan and reports EXACTLY what it says - no
false-positive filtering, no relevance judgment. Every line rkhunter
marks "Warning" is reported as DETECTED, raw. No checks disabled, no
timeout (runs as long as it needs to), heartbeat every 20s of silence
so it never looks frozen.
"""

from __future__ import annotations

import queue
import re
import subprocess
import threading
import time
from pathlib import Path

from detection.detection_result import DetectionResult, DetectionStatus, Tier

TECHNIQUE_ID = "T1014"
TECHNIQUE_NAME = "Rootkit - Process/Module Hiding"

_WARNING_RE = re.compile(r"\bWarning\b", re.IGNORECASE)


def run(log_path: str | Path | None = None) -> list[DetectionResult]:
    if log_path is not None:
        raw = Path(log_path).read_text(errors="ignore")
    else:
        try:
            proc = subprocess.Popen(
                ["rkhunter", "--check", "--sk", "--nocolors"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            return [DetectionResult(
                technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
                source="rkhunter", tier=Tier.ADAPTER,
                status=DetectionStatus.NOT_APPLICABLE, raw_output=None,
                notes="rkhunter is not installed on this host.",
            )]

        q: queue.Queue = queue.Queue()

        def _reader():
            for line in iter(proc.stdout.readline, ""):
                q.put(line)
            q.put(None)

        threading.Thread(target=_reader, daemon=True).start()

        lines: list[str] = []
        start = time.monotonic()
        stream_done = False
        while not stream_done:
            try:
                item = q.get(timeout=20)
            except queue.Empty:
                elapsed = int(time.monotonic() - start)
                print(f"    ... still running ({elapsed // 60}m {elapsed % 60}s elapsed)",
                      flush=True)
                continue
            if item is None:
                stream_done = True
                break
            print(f"    {item.rstrip()}", flush=True)
            lines.append(item)

        proc.wait()
        raw = "".join(lines)

    flagged = [line for line in raw.splitlines() if _WARNING_RE.search(line)]

    results: list[DetectionResult] = []
    if flagged:
        for line in flagged:
            results.append(DetectionResult(
                technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
                source="rkhunter", tier=Tier.ADAPTER,
                status=DetectionStatus.DETECTED,
                raw_output=line.strip(), evidence_path=str(log_path) if log_path else None,
                notes="Raw rkhunter output - flagged as Warning.",
            ))
    else:
        results.append(DetectionResult(
            technique_id=TECHNIQUE_ID, technique_name=TECHNIQUE_NAME,
            source="rkhunter", tier=Tier.ADAPTER,
            status=DetectionStatus.MISSED, raw_output=raw,
            evidence_path=str(log_path) if log_path else None,
            notes="rkhunter reported no warnings.",
        ))
    return results