from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from .types import Finding


class CorroborationEngine:
    """
    Corroboration engine that groups findings by file and rule.

    The main responsibility here is to:
    - Attach corroborating rule ids to each finding
    - Provide grouped views for scoring and reporting
    """

    def group_by_file(self, findings: Iterable[Finding]) -> Dict[int, List[Finding]]:
        grouped: Dict[int, List[Finding]] = defaultdict(list)
        for f in findings:
            grouped[f.file_reference].append(f)
        return grouped

    def annotate_corroboration(
        self, findings: Iterable[Finding]
    ) -> List[Finding]:
        """
        For each finding, populate corroborated_by with the other rules
        that fired on the same file.
        """
        grouped = self.group_by_file(findings)
        annotated: List[Finding] = []
        for file_ref, flist in grouped.items():
            rule_ids = [f.rule_id for f in flist]
            for f in flist:
                others = [r for r in rule_ids if r != f.rule_id]
                f.corroborated_by = others
                annotated.append(f)
        return annotated

    def by_rule(self, findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
        by_rule: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            by_rule[f.rule_id].append(f)
        return by_rule

