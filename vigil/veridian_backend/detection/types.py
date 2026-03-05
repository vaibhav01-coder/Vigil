from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List


@dataclass
class FileRecord:
    mft_record_number: int
    file_reference: int  # record_num | seq_num << 48
    lsn: int  # from record header — CRITICAL
    sequence_number: int
    is_deleted: bool
    is_directory: bool
    si_created: datetime
    si_modified: datetime
    si_accessed: datetime
    si_entry_modified: datetime
    si_attributes: int
    si_last_usn: int  # CRITICAL for Rules 5, 6, 8
    fn_created: datetime
    fn_modified: datetime
    fn_accessed: datetime
    fn_entry_modified: datetime
    fn_filename: str
    fn_parent_ref: int
    fn_real_size: int
    fn_allocated_size: int
    fn_namespace: int
    data_real_size: int


@dataclass
class USNRecord:
    usn: int
    file_reference: int
    parent_reference: int
    timestamp: datetime
    reason: int  # bitmask
    filename: str
    file_attributes: int
    record_offset: int  # byte position in $J stream
    record_length: int


@dataclass
class LogRecord:
    lsn: int
    previous_lsn: int
    transaction_id: int
    record_type: int
    mft_record_ref: int  # which MFT record this touches
    redo_op: int
    undo_op: int
    page_offset: int
    is_checkpoint: bool


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str  # CRITICAL HIGH MEDIUM LOW
    file_reference: int
    filename: str
    filepath: str
    description: str  # plain English
    technical_detail: str  # raw values
    timestamp: datetime
    delta_seconds: int
    base_score: int
    evidence: Dict[str, object]
    corroborated_by: List[str]
    confidence: float
    suppressed: bool = False
    suppression_reason: str = ""

