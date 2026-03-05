from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from detection.types import Finding


@dataclass
class ModifierContext:
    """
    Context passed into modifier calculations.

    This is intentionally minimal for the MVP – it can be enriched later
    with baseline information, file type hints, and environment signals.
    """

    similar_system_wide_delta: bool = False
    benign_process: bool = False
    known_update_window: bool = False


def severity_multiplier(finding: Finding) -> float:
    """Map rule severity into a numeric multiplier."""
    sev = finding.severity.upper()
    if sev == "CRITICAL":
        return 1.4
    if sev == "HIGH":
        return 1.2
    if sev == "MEDIUM":
        return 1.0
    return 0.8


def specificity_multiplier(finding: Finding) -> float:
    """
    Very rough heuristic for how specific a finding is.

    For the MVP we key off the rule id – rules that imply deliberate
    manipulation get a stronger multiplier.
    """
    rid = finding.rule_id.upper()
    if rid in {"RULE_2", "RULE_6"}:
        return 1.4
    if rid in {"RULE_5", "RULE_8", "RULE_9"}:
        return 1.2
    return 1.0


def apply_modifiers(
    base_score: int,
    finding: Finding,
    ctx: ModifierContext | None = None,
) -> int:
    """
    Apply severity and specificity modifiers to a base score.
    """
    score = float(base_score) * severity_multiplier(finding) * specificity_multiplier(
        finding
    )

    if ctx:
        if ctx.similar_system_wide_delta:
            score *= 0.7
        if ctx.benign_process:
            score *= 0.6
        if ctx.known_update_window:
            score *= 0.8

    return max(1, int(round(score)))


def contributions_from_scores(scores: Iterable[int]) -> List[int]:
    """
    Return list of per-rule contributions according to diminishing returns.
    """
    sorted_scores = sorted(scores, reverse=True)
    if not sorted_scores:
        return []
    contribs: List[int] = []
    for idx, s in enumerate(sorted_scores):
        if idx == 0:
            weight = 1.0
        elif idx == 1:
            weight = 0.8
        elif idx == 2:
            weight = 0.6
        else:
            weight = 0.4
        contribs.append(int(round(s * weight)))
    return contribs

