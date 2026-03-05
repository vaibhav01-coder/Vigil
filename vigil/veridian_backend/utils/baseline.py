from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Dict, Iterable, List

from detection.types import FileRecord


@dataclass
class BaselineStats:
    mean_delta: float
    std_delta: float
    sample_size: int


def compute_timestamp_deltas(files: Iterable[FileRecord]) -> List[float]:
    deltas: List[float] = []
    for fr in files:
        delta = abs((fr.si_modified - fr.fn_modified).total_seconds())
        if delta > 0:
            deltas.append(delta)
    return deltas


def build_system_baseline(sample: Iterable[FileRecord]) -> Dict[str, float]:
    """
    Build a simple system baseline from a sample of FileRecord entries.
    """
    deltas = compute_timestamp_deltas(sample)
    if not deltas:
        return {
            "mean_delta": 0.0,
            "std_delta": 0.0,
            "sample_size": 0,
        }

    m = mean(deltas)
    s = pstdev(deltas) if len(deltas) > 1 else 0.0
    return {
        "mean_delta": m,
        "std_delta": s,
        "sample_size": len(deltas),
    }

