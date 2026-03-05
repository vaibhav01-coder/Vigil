from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class ScanRequest(BaseModel):
    drive_letter: str  # e.g. "C"
    scan_depth: Literal["quick", "full", "deep"] = "full"
    file_path: Optional[str] = None  # single file
    folder_path: Optional[str] = None  # folder — scan all files inside


class ImageScanRequest(BaseModel):
    image_path: str  # path to .dd or .img file
    scan_depth: Literal["quick", "full", "deep"] = "full"


class DriveInfo(BaseModel):
    letter: str
    label: str
    total_bytes: int
    free_bytes: int
    ntfs_version: str
    usn_active: bool
    logfile_size: int


class FindingModel(BaseModel):
    rule_id: str
    rule_name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    file_reference: int
    filename: str
    filepath: str
    description: str
    technical_detail: str
    timestamp: datetime
    delta_seconds: int
    base_score: int
    evidence: dict
    corroborated_by: list[str]
    confidence: float
    suppressed: bool
    suppression_reason: str


class ScanResult(BaseModel):
    job_id: str
    volume: str
    scan_time: datetime
    duration_seconds: int
    risk_score: int
    confidence: float
    risk_label: str
    verdict: str
    attack_pattern: str
    mitre_techniques: list[str]
    findings: list[FindingModel]
    suppressed_findings: list[FindingModel]
    usn_health: dict
    logfile_health: dict
    baseline: dict
    smoking_gun: FindingModel | None
    file_results: list[dict] | None = None  # per-file results when folder scanned


class ScanStatus(BaseModel):
    job_id: str
    status: Literal["running", "complete", "error"]
    progress_percent: int
    current_stage: str
    current_file: str
    findings_count: dict
    elapsed_seconds: int
    error_message: str | None

