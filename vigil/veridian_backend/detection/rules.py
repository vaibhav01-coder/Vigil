from __future__ import annotations

from datetime import datetime
from typing import Iterable, List

from scoring.base_scores import BASE_SCORES

from .types import FileRecord, Finding, LogRecord, USNRecord


class RuleEngine:
    """
    Container for all 9 VERIDIAN detection rules.

    For the MVP implementation we focus on the plumbing and data flow –
    each rule method returns zero or more Finding instances. The detailed
    NTFS logic can be incrementally filled in while preserving this API.
    """

    def rule_1a_si_fn_modified(
        self, files: Iterable[FileRecord]
    ) -> List[Finding]:
        """
        Rule 1A: SI/FN Modified timestamp anomalies.
        """
        findings: List[Finding] = []
        for fr in files:
            delta = int(
                abs(
                    (fr.si_modified - fr.fn_modified).total_seconds()
                )
            )
            if delta <= 0:
                continue
            findings.append(
                Finding(
                    rule_id="RULE_1A",
                    rule_name="SI/FN Modified Timestamp Delta",
                    severity="MEDIUM",
                    file_reference=fr.file_reference,
                    filename=fr.fn_filename,
                    filepath="",
                    description="Difference between $SI and $FN Modified timestamps.",
                    technical_detail=f"si_modified={fr.si_modified.isoformat()} "
                    f"fn_modified={fr.fn_modified.isoformat()} delta={delta}s",
                    timestamp=fr.si_modified,
                    delta_seconds=delta,
                    base_score=BASE_SCORES["RULE_1A"],
                    evidence={},
                    corroborated_by=[],
                    confidence=0.5,
                )
            )
        return findings

    def rule_1b_si_fn_created(
        self, files: Iterable[FileRecord]
    ) -> List[Finding]:
        """
        Rule 1B: SI/FN Created timestamp anomalies.
        """
        findings: List[Finding] = []
        for fr in files:
            delta = int(
                abs(
                    (fr.si_created - fr.fn_created).total_seconds()
                )
            )
            if delta <= 0:
                continue
            findings.append(
                Finding(
                    rule_id="RULE_1B",
                    rule_name="SI/FN Created Timestamp Delta",
                    severity="HIGH",
                    file_reference=fr.file_reference,
                    filename=fr.fn_filename,
                    filepath="",
                    description="Difference between $SI and $FN Created timestamps.",
                    technical_detail=f"si_created={fr.si_created.isoformat()} "
                    f"fn_created={fr.fn_created.isoformat()} delta={delta}s",
                    timestamp=fr.si_created,
                    delta_seconds=delta,
                    base_score=BASE_SCORES["RULE_1B"],
                    evidence={},
                    corroborated_by=[],
                    confidence=0.6,
                )
            )
        return findings

    def rule_2_logical_impossibility(
        self, files: Iterable[FileRecord]
    ) -> List[Finding]:
        """
        Rule 2: Logical impossibility between timestamp ordering.
        """
        findings: List[Finding] = []
        for fr in files:
            if fr.fn_created > fr.si_modified:
                delta = int(
                    (fr.fn_created - fr.si_modified).total_seconds()
                )
                findings.append(
                    Finding(
                        rule_id="RULE_2",
                        rule_name="Logical Timestamp Impossibility",
                        severity="CRITICAL",
                        file_reference=fr.file_reference,
                        filename=fr.fn_filename,
                        filepath="",
                        description="$FN Created is later than $SI Modified.",
                        technical_detail=f"fn_created={fr.fn_created.isoformat()} "
                        f"si_modified={fr.si_modified.isoformat()} "
                        f"delta={delta}s",
                        timestamp=fr.fn_created,
                        delta_seconds=delta,
                        base_score=BASE_SCORES["RULE_2"],
                        evidence={},
                        corroborated_by=[],
                        confidence=0.8,
                    )
                )
        return findings

    def rule_3_usn_timestamp_rollback(
        self, usn_records: Iterable[USNRecord]
    ) -> List[Finding]:
        """
        Rule 3: USN timestamp rollback within the same file sequence.
        """
        findings: List[Finding] = []
        # Minimal placeholder – real implementation would group by
        # file_reference and check for monotonic timestamp / USN.
        return findings

    def rule_4_metadata_suppression(
        self, files: Iterable[FileRecord]
    ) -> List[Finding]:
        """
        Rule 4: Metadata suppression (e.g., real size mismatch).
        """
        findings: List[Finding] = []
        for fr in files:
            if fr.fn_real_size == 0 and fr.data_real_size > 0:
                findings.append(
                    Finding(
                        rule_id="RULE_4",
                        rule_name="Metadata Suppression",
                        severity="MEDIUM",
                        file_reference=fr.file_reference,
                        filename=fr.fn_filename,
                        filepath="",
                        description="Real data size present but $FN reports zero.",
                        technical_detail=f"fn_real_size={fr.fn_real_size} "
                        f"data_real_size={fr.data_real_size}",
                        timestamp=datetime.utcnow(),
                        delta_seconds=0,
                        base_score=BASE_SCORES["RULE_4"],
                        evidence={},
                        corroborated_by=[],
                        confidence=0.6,
                    )
                )
        return findings

    def rule_5_lsn_missing_from_log(
        self, files: Iterable[FileRecord], log_index: dict[int, LogRecord]
    ) -> List[Finding]:
        """
        Rule 5: LSN present in MFT but missing from active $LogFile.
        """
        findings: List[Finding] = []
        for fr in files:
            if fr.lsn and fr.lsn not in log_index:
                findings.append(
                    Finding(
                        rule_id="RULE_5",
                        rule_name="LSN Missing From Active Log",
                        severity="HIGH",
                        file_reference=fr.file_reference,
                        filename=fr.fn_filename,
                        filepath="",
                        description="MFT record LSN not present in active $LogFile range.",
                        technical_detail=f"lsn={fr.lsn}",
                        timestamp=datetime.utcnow(),
                        delta_seconds=0,
                        base_score=BASE_SCORES["RULE_5"],
                        evidence={},
                        corroborated_by=[],
                        confidence=0.7,
                    )
                )
        return findings

    def rule_6_lsn_wrong_file(
        self, files: Iterable[FileRecord], log_index: dict[int, LogRecord]
    ) -> List[Finding]:
        """
        Rule 6: LSN chain points to the wrong file.
        """
        findings: List[Finding] = []
        # Placeholder – real implementation would dereference LSN and
        # compare referenced MFT record number.
        return findings

    def rule_7_logfile_timestamp_rollback(
        self, log_records: Iterable[LogRecord]
    ) -> List[Finding]:
        """
        Rule 7: LogFile timestamp rollback anomalies.
        """
        findings: List[Finding] = []
        # Placeholder; depends on detailed LogRecord representation.
        return findings

    def rule_8_lsn_order_violation(
        self, files: Iterable[FileRecord]
    ) -> List[Finding]:
        """
        Rule 8: LSN order violations relative to USN and timestamps.
        """
        findings: List[Finding] = []
        # Placeholder for now.
        return findings

    def rule_9_usn_sequence_gap(
        self, usn_records: Iterable[USNRecord]
    ) -> List[Finding]:
        """
        Rule 9: USN sequence gaps within active ranges.
        """
        findings: List[Finding] = []
        # Placeholder for gap analysis.
        return findings

