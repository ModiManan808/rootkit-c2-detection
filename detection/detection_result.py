"""
detection_result.py

Shared schema for the three-tier detection architecture:

  1. ADAPTER tier   - raw output from a single detection tool (auditd,
                       chkrootkit, rkhunter, ...), normalized into a
                       common shape.
  2. CORRELATION tier - compares adapter results against eBPF ground
                       truth events to decide HIT / MISS / PARTIAL per
                       technique.
  3. MANUAL tier    - human-reviewed findings (e.g. "I confirmed this
                       by inspecting /proc manually") that get merged
                       in alongside automated results for the final
                       gap-analysis report.

Every adapter in detection/adapters/ should return a list[DetectionResult].
Correlation and reporting code should only ever depend on this file,
never on a specific tool's raw output format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Tier(str, Enum):
    ADAPTER = "adapter"
    CORRELATION = "correlation"
    MANUAL = "manual"


class DetectionStatus(str, Enum):
    DETECTED = "detected"       # tool flagged it
    MISSED = "missed"           # ground truth says it happened, tool stayed silent
    PARTIAL = "partial"         # tool flagged something related but not the real cause
    NOT_APPLICABLE = "n/a"      # tool doesn't cover this technique at all


@dataclass
class DetectionResult:
    """
    One normalized finding, from any tier.

    technique_id:     MITRE ATT&CK ID, e.g. "T1014" (Rootkit) or
                       "T1071" (Application Layer Protocol / C2).
    technique_name:    Human-readable name, e.g. "Kernel Module Hiding".
    source:            Which tool/tier produced this, e.g. "auditd",
                       "chkrootkit", "rkhunter", "ebpf_ground_truth",
                       "manual".
    tier:              Tier enum - adapter / correlation / manual.
    status:            DetectionStatus enum.
    raw_output:        Unmodified tool output (string or dict) for
                       evidence purposes. Never parsed downstream -
                       correlation/reporting only reads the typed
                       fields below.
    evidence_path:     Optional path to a saved log file under
                       docs/evidence/.
    timestamp:         UTC time the result was produced.
    notes:             Free-text context (e.g. "flagged finit_module
                       syscall by name but had no visibility into the
                       list_del hiding itself").
    confidence:        0.0-1.0, mainly used by MANUAL tier entries;
                       automated adapters default to 1.0 for anything
                       they positively flag.
    """

    technique_id: str
    technique_name: str
    source: str
    tier: Tier
    status: DetectionStatus
    raw_output: Any = None
    evidence_path: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        d = {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "source": self.source,
            "tier": self.tier.value,
            "status": self.status.value,
            "raw_output": self.raw_output,
            "evidence_path": self.evidence_path,
            "timestamp": self.timestamp.isoformat(),
            "notes": self.notes,
            "confidence": self.confidence,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DetectionResult":
        return cls(
            technique_id=d["technique_id"],
            technique_name=d["technique_name"],
            source=d["source"],
            tier=Tier(d["tier"]),
            status=DetectionStatus(d["status"]),
            raw_output=d.get("raw_output"),
            evidence_path=d.get("evidence_path"),
            timestamp=datetime.fromisoformat(d["timestamp"]) if d.get("timestamp") else datetime.now(timezone.utc),
            notes=d.get("notes", ""),
            confidence=d.get("confidence", 1.0),
        )


@dataclass
class GapAnalysisEntry:
    """
    Final, per-technique row consumed by module3-reporting.
    Produced by the correlation tier by combining:
      - the eBPF ground-truth result (did it actually happen)
      - every adapter result for that technique_id (did any tool catch it)
      - any manual tier entries for that technique_id
    """

    technique_id: str
    technique_name: str
    ground_truth_confirmed: bool
    detected_by: list[str]          # sources that caught it, e.g. ["auditd"]
    missed_by: list[str]            # sources that should have caught it but didn't
    overall_status: DetectionStatus
    evidence_paths: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "ground_truth_confirmed": self.ground_truth_confirmed,
            "detected_by": self.detected_by,
            "missed_by": self.missed_by,
            "overall_status": self.overall_status.value,
            "evidence_paths": self.evidence_paths,
            "notes": self.notes,
        }