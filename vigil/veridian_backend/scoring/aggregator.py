from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from detection.types import Finding

from .modifiers import apply_modifiers, contributions_from_scores


def per_file_scores(findings: Iterable[Finding]) -> Dict[int, Tuple[int, List[Finding]]]:
    """
    Aggregate scores per file according to the diminishing returns rule.

    Returns mapping:
        file_reference -> (score, findings_for_file)
    """
    by_file: Dict[int, List[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file_reference].append(f)

    result: Dict[int, Tuple[int, List[Finding]]] = {}
    for file_ref, flist in by_file.items():
        rule_scores: List[int] = []
        for f in flist:
            rule_scores.append(apply_modifiers(f.base_score, f))
        contribs = contributions_from_scores(rule_scores)
        score = sum(contribs)
        result[file_ref] = (score, flist)
    return result


def corroboration_multiplier(rule_ids: Iterable[str]) -> float:
    """
    Compute corroboration multiplier based on number of independent rules firing.

    Rules 3 and 7 count as one corroboration point.
    """
    normalized = set()
    for rid in rule_ids:
        r = rid.upper()
        if r in {"RULE_3", "RULE_7"}:
            normalized.add("RULE_3_7")
        else:
            normalized.add(r)

    n = len(normalized)
    if n <= 1:
        return 1.0
    if n == 2:
        return 1.4
    if n == 3:
        return 1.7
    return 2.0


def apply_corroboration(
    file_scores: Dict[int, Tuple[int, List[Finding]]],
) -> Dict[int, int]:
    """Apply corroboration multipliers to per-file scores."""
    result: Dict[int, int] = {}
    for file_ref, (score, flist) in file_scores.items():
        rules = [f.rule_id for f in flist]
        mult = corroboration_multiplier(rules)
        result[file_ref] = int(round(score * mult))
    return result


def aggregate_volume_score(file_scores: Dict[int, int]) -> int:
    """
    Aggregate file scores into a volume-wide score using the weighting
    scheme described in the prompt.
    """
    if not file_scores:
        return 0

    scores = sorted(file_scores.values(), reverse=True)
    top = scores + [0] * max(0, 6 - len(scores))  # pad for indexing

    volume_raw = (
        top[0] * 0.40
        + top[1] * 0.25
        + top[2] * 0.15
        + sum(top[3:5]) * 0.12
        + sum(top[5:]) * 0.08
    )

    # Normalise logarithmically to 0–100. The constant 1000.0 is a
    # conservative stand‑in for "max possible raw".
    max_possible_raw = 1000.0
    normalized = 100.0 * math.log(1.0 + volume_raw) / math.log(1.0 + max_possible_raw)
    return int(round(normalized))

