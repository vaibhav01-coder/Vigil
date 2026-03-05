"""
Risk scoring pipeline for VERIDIAN.

Composed of:
- base_scores: base rule scores
- modifiers: severity and specificity multipliers
- aggregator: per-file and volume aggregation
- risk_label: final human-readable labels
"""

