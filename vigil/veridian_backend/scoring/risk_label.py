from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskVerdict:
    label: str
    verdict: str
    attack_pattern: str


def label_for_score(score: int) -> RiskVerdict:
    """
    Map a 0–100 score into a human‑readable risk label and short verdict.
    """
    if score >= 80:
        return RiskVerdict(
            label="CRITICAL",
            verdict="Strong evidence of anti-forensic tampering.",
            attack_pattern="Coordinated timestamp and log manipulation across NTFS subsystems.",
        )
    if score >= 60:
        return RiskVerdict(
            label="HIGH",
            verdict="Likely targeted tampering with NTFS artifacts.",
            attack_pattern="Suspicious inconsistencies between timestamps, USN, and LogFile entries.",
        )
    if score >= 30:
        return RiskVerdict(
            label="MEDIUM",
            verdict="Anomalies present but may be explainable by system activity.",
            attack_pattern="Localized inconsistencies requiring analyst review.",
        )
    if score > 0:
        return RiskVerdict(
            label="LOW",
            verdict="Minor anomalies with low likelihood of deliberate tampering.",
            attack_pattern="Isolated inconsistencies within expected baseline variance.",
        )
    return RiskVerdict(
        label="NONE",
        verdict="No significant tampering indicators detected.",
        attack_pattern="No correlated anomalies across NTFS subsystems.",
    )

