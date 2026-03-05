from __future__ import annotations

from typing import Iterable, List

from .types import Finding


class FalsePositiveFilter:
    """
    Context-aware deflation for suspected false positives.

    The full design calls for rich baseline- and context-driven scoring.
    For the MVP we implement a conservative mechanism that:
    - Never fully suppresses findings
    - Can lower confidence and effective score based on simple flags
    """

    def deflate(
        self,
        findings: Iterable[Finding],
        *,
        benign_processes: Iterable[str] | None = None,
    ) -> List[Finding]:
        benign = {p.lower() for p in (benign_processes or [])}

        adjusted: List[Finding] = []
        for f in findings:
            multiplier = 1.0
            reason_parts: list[str] = []

            # Simple filename-based hint – can be replaced with richer
            # provenance / parent process checks later.
            if benign and any(p in f.filepath.lower() for p in benign):
                multiplier *= 0.5
                reason_parts.append("benign_process")

            # Floor at 10 points minimum — never fully suppress
            new_score = max(10, int(round(f.base_score * multiplier)))
            if new_score < f.base_score:
                f.suppressed = True
                f.suppression_reason = ",".join(reason_parts) or "heuristic_deflation"
                f.base_score = new_score

            # Confidence is lightly deflated along with score
            if f.suppressed:
                f.confidence *= 0.9

            adjusted.append(f)

        return adjusted

