"""
Real-time NTFS forensic analysis for a single file.

Uses pywin32 to extract kernel-level metadata (GetFileInformationByHandle)
and USN Journal records, then applies VERIDIAN detection rules.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from scoring.base_scores import BASE_SCORES

try:
    import win32file
    import win32con
    import pywintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# IOCTLs
FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB

# FILE_READ_DATA for volume
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


@dataclass
class FileMetadata:
    """Kernel-level file metadata from GetFileInformationByHandle."""
    path: str
    filename: str
    created: datetime
    last_write: datetime
    last_access: datetime
    file_reference: int  # MFT ref: (nFileIndexHigh << 32) | nFileIndexLow
    file_size: int
    volume_letter: str


@dataclass
class USNRecord:
    """Parsed USN Journal record for the target file."""
    usn: int
    timestamp: datetime
    reason: int
    filename: str
    record_length: int


@dataclass
class AnalysisResult:
    """Result of real-time file analysis."""
    metadata: Optional[FileMetadata] = None
    usn_records: List[USNRecord] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def _filetime_to_datetime(ft: Any) -> datetime:
    """Convert FILETIME or PyTime to datetime."""
    if ft is None:
        return datetime.utcnow()
    if hasattr(ft, "timestamp"):
        try:
            return datetime.utcfromtimestamp(ft.timestamp())
        except (ValueError, OSError):
            pass
    if hasattr(ft, "year"):  # datetime-like
        return ft
    if isinstance(ft, (int, float)):
        from datetime import timedelta
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=int(ft) // 10)
        except (ValueError, OverflowError):
            pass
    return datetime.utcnow()


def _get_file_metadata(path: str) -> Optional[FileMetadata]:
    """Extract kernel-level metadata using GetFileInformationByHandle."""
    if not HAS_WIN32:
        return None
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return None
    try:
        handle = win32file.CreateFile(
            path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        try:
            info = win32file.GetFileInformationByHandle(handle)
            # info: (dwFileAttributes, ftCreationTime, ftLastAccessTime, ftLastWriteTime,
            #        dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks,
            #        nFileIndexHigh, nFileIndexLow)
            ft_creation = info[1]
            ft_access = info[2]
            ft_write = info[3]
            n_high = info[8]
            n_low = info[9]
            file_ref = (n_high << 32) | (n_low & 0xFFFFFFFF)
            size = (info[5] << 32) | (info[6] & 0xFFFFFFFF)

            created = _filetime_to_datetime(ft_creation)
            last_access = _filetime_to_datetime(ft_access)
            last_write = _filetime_to_datetime(ft_write)

            vol = path[0].upper() if len(path) >= 2 and path[1] == ":" else "?"
            return FileMetadata(
                path=path,
                filename=os.path.basename(path),
                created=created,
                last_write=last_write,
                last_access=last_access,
                file_reference=file_ref,
                file_size=size,
                volume_letter=vol,
            )
        finally:
            win32file.CloseHandle(handle)
    except Exception:
        return None
    return None


def _read_usn_for_file(volume_letter: str, file_reference: int) -> List[USNRecord]:
    """Read USN Journal records for a specific file reference."""
    if not HAS_WIN32 or file_reference == 0:
        return []
    volume_path = f"\\\\.\\{volume_letter}:"
    records: List[USNRecord] = []
    try:
        vol_handle = win32file.CreateFile(
            volume_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        try:
            # Query journal
            out_buf = win32file.DeviceIoControl(
                vol_handle,
                FSCTL_QUERY_USN_JOURNAL,
                b"",
                48,
            )
            if len(out_buf) < 48:
                return []
            # UsnJournalID at offset 0, NextUsn at 8, FirstUsn at 16
            next_usn = struct.unpack("<Q", out_buf[8:16])[0]
            first_usn = struct.unpack("<Q", out_buf[16:24])[0]
            journal_id = struct.unpack("<Q", out_buf[0:8])[0]

            # Read journal in chunks; stop when we have enough for our file or hit start
            start_usn = 0
            chunk_size = 65536
            max_records = 500
            seen_usns: set[int] = set()

            while len(records) < max_records:
                # READ_USN_JOURNAL_DATA: StartUsn(8), ReasonMask(4), ReturnOnlyOnClose(4),
                # Timeout(8), BytesToWaitFor(4), UsnJournalID(8)
                in_buf = struct.pack(
                    "<QIIQIQ",
                    start_usn,
                    0xFFFFFFFF,  # ReasonMask: all
                    0,  # ReturnOnlyOnClose
                    0,  # Timeout
                    0,  # BytesToWaitFor
                    journal_id,
                )
                out_buf = win32file.DeviceIoControl(
                    vol_handle,
                    FSCTL_READ_USN_JOURNAL,
                    in_buf,
                    chunk_size,
                )
                if len(out_buf) < 8:
                    break
                next_usn = struct.unpack("<Q", out_buf[0:8])[0]
                if next_usn == start_usn:
                    break
                start_usn = next_usn

                # Parse USN records (start at offset 8)
                offset = 8
                while offset + 60 <= len(out_buf):
                    rec_len = struct.unpack("<I", out_buf[offset : offset + 4])[0]
                    if rec_len == 0:
                        break
                    if offset + rec_len > len(out_buf):
                        break
                    major_ver = struct.unpack("<H", out_buf[offset + 4 : offset + 6])[0]
                    if major_ver != 2:
                        offset += rec_len
                        continue
                    file_ref = struct.unpack("<Q", out_buf[offset + 8 : offset + 16])[0]
                    if file_ref != file_reference:
                        offset += rec_len
                        continue
                    ts = struct.unpack("<Q", out_buf[offset + 24 : offset + 32])[0]
                    reason = struct.unpack("<I", out_buf[offset + 32 : offset + 36])[0]
                    fn_len = struct.unpack("<H", out_buf[offset + 56 : offset + 58])[0]
                    fn_offset = struct.unpack("<H", out_buf[offset + 58 : offset + 60])[0]
                    fn_start = offset + fn_offset
                    fn_end = min(fn_start + fn_len, offset + rec_len)
                    fn_bytes = out_buf[fn_start:fn_end]
                    try:
                        fn_str = fn_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
                    except Exception:
                        fn_str = "?"
                    if ts and ts not in seen_usns:
                        seen_usns.add(ts)
                        dt = datetime(1601, 1, 1)
                        from datetime import timedelta
                        try:
                            dt = datetime(1601, 1, 1) + timedelta(microseconds=ts // 10)
                        except Exception:
                            pass
                        records.append(
                            USNRecord(
                                usn=struct.unpack("<Q", out_buf[offset + 16 : offset + 24])[0],
                                timestamp=dt,
                                reason=reason,
                                filename=fn_str,
                                record_length=rec_len,
                            )
                        )
                    offset += rec_len
        finally:
            win32file.CloseHandle(vol_handle)
    except Exception:
        pass
    return records


def _apply_rules(meta: FileMetadata, usn_records: List[USNRecord]) -> Tuple[List[Dict[str, Any]], int, float, Dict[str, Any]]:
    """Apply VERIDIAN detection rules and return findings, risk_score, confidence, evidence."""
    findings: List[Dict[str, Any]] = []
    evidence: Dict[str, Any] = {
        "created": meta.created.isoformat(),
        "last_write": meta.last_write.isoformat(),
        "last_access": meta.last_access.isoformat(),
        "file_reference": meta.file_reference,
        "file_size": meta.file_size,
    }
    rule_scores: List[int] = []
    confidence_sum = 0.0
    n_rules = 0

    # Rule 1A: SI/FN Modified timestamp delta (we use kernel created vs last_write as proxy)
    delta_c_w = abs(int((meta.last_write - meta.created).total_seconds()))
    delta_w_a = abs(int((meta.last_access - meta.last_write).total_seconds()))
    evidence["delta_created_write_seconds"] = delta_c_w
    evidence["delta_write_access_seconds"] = delta_w_a

    if delta_c_w > 0:
        n_rules += 1
        base = BASE_SCORES["RULE_1A"]
        if delta_c_w > 86400:  # > 1 day
            base = int(base * 1.3)
        rule_scores.append(base)
        findings.append({
            "rule_id": "RULE_1A",
            "rule_name": "Created/Modified Timestamp Delta",
            "severity": "HIGH" if delta_c_w > 3600 else "MEDIUM",
            "description": f"Created and last-write timestamps differ by {delta_c_w} seconds.",
            "technical_detail": f"created={meta.created.isoformat()} last_write={meta.last_write.isoformat()}",
            "delta_seconds": delta_c_w,
            "base_score": base,
        })
        confidence_sum += 0.7 if delta_c_w > 3600 else 0.5

    # Rule 1B: Created vs Modified (same as 1A for single timestamp pair; treat as corroboration)
    if delta_c_w > 300 and delta_c_w != delta_w_a:
        n_rules += 1
        base = BASE_SCORES["RULE_1B"]
        rule_scores.append(base)
        findings.append({
            "rule_id": "RULE_1B",
            "rule_name": "Created/Modified Anomaly",
            "severity": "HIGH" if delta_c_w > 3600 else "MEDIUM",
            "description": "Significant gap between creation and modification times.",
            "technical_detail": f"delta={delta_c_w}s",
            "delta_seconds": delta_c_w,
            "base_score": base,
        })
        confidence_sum += 0.6

    # Rule 4: Metadata suppression (kernel file_size 0 but file has content)
    try:
        actual_size = os.path.getsize(meta.path)
        if meta.file_size == 0 and actual_size > 0:
            n_rules += 1
            base = BASE_SCORES["RULE_4"]
            rule_scores.append(base)
            findings.append({
                "rule_id": "RULE_4",
                "rule_name": "Metadata Suppression",
                "severity": "MEDIUM",
                "description": "Kernel reports file size 0 but file has content.",
                "technical_detail": f"kernel_size=0 actual_size={actual_size}",
                "delta_seconds": 0,
                "base_score": base,
            })
            evidence["actual_size"] = actual_size
            confidence_sum += 0.65
    except OSError:
        pass

    # Rule 2: Logical impossibility (created > last_write)
    if meta.created > meta.last_write:
        n_rules += 1
        base = BASE_SCORES["RULE_2"]
        rule_scores.append(base)
        delta_imp = int((meta.created - meta.last_write).total_seconds())
        findings.append({
            "rule_id": "RULE_2",
            "rule_name": "Logical Timestamp Impossibility",
            "severity": "CRITICAL",
            "description": "Creation time is later than last-write time — impossible under normal operation.",
            "technical_detail": f"created={meta.created.isoformat()} > last_write={meta.last_write.isoformat()}",
            "delta_seconds": delta_imp,
            "base_score": base,
        })
        confidence_sum += 0.9

    # Rule 3 & 9: USN timestamp rollback and sequence gaps
    if usn_records:
        evidence["usn_record_count"] = len(usn_records)
        sorted_usn = sorted(usn_records, key=lambda r: r.usn)
        for i, rec in enumerate(sorted_usn):
            evidence[f"usn_{i}"] = {
                "usn": rec.usn,
                "timestamp": rec.timestamp.isoformat(),
                "reason": hex(rec.reason),
            }
        # Check for timestamp rollback in USN sequence
        for i in range(1, len(sorted_usn)):
            prev_ts = sorted_usn[i - 1].timestamp
            curr_ts = sorted_usn[i].timestamp
            if curr_ts < prev_ts:
                n_rules += 1
                base = BASE_SCORES["RULE_3"]
                rule_scores.append(base)
                findings.append({
                    "rule_id": "RULE_3",
                    "rule_name": "USN Timestamp Rollback",
                    "severity": "HIGH",
                    "description": "USN Journal shows timestamp going backwards.",
                    "technical_detail": f"prev={prev_ts.isoformat()} curr={curr_ts.isoformat()}",
                    "delta_seconds": int((prev_ts - curr_ts).total_seconds()),
                    "base_score": base,
                })
                confidence_sum += 0.8
                break
        # Check for USN sequence gap
        for i in range(1, len(sorted_usn)):
            expected_next = sorted_usn[i - 1].usn + sorted_usn[i - 1].record_length
            actual_next = sorted_usn[i].usn
            if actual_next != expected_next and (actual_next - expected_next) > 8:
                n_rules += 1
                base = BASE_SCORES["RULE_9"]
                rule_scores.append(base)
                findings.append({
                    "rule_id": "RULE_9",
                    "rule_name": "USN Sequence Gap",
                    "severity": "MEDIUM",
                    "description": "Gap detected in USN Journal sequence.",
                    "technical_detail": f"expected_next={expected_next} actual={actual_next}",
                    "delta_seconds": 0,
                    "base_score": base,
                })
                confidence_sum += 0.65
                break

    # Aggregate risk score (diminishing returns)
    if rule_scores:
        sorted_scores = sorted(rule_scores, reverse=True)
        weights = [1.0, 0.8, 0.6] + [0.4] * max(0, len(sorted_scores) - 3)
        raw = sum(s * w for s, w in zip(sorted_scores, weights))
        # Corroboration: 2+ rules = 1.4x, 3+ = 1.7x, 4+ = 2.0x
        mult = 1.0
        if len(findings) >= 4:
            mult = 2.0
        elif len(findings) >= 3:
            mult = 1.7
        elif len(findings) >= 2:
            mult = 1.4
        risk_score = min(100, int(raw * mult / 2))
    else:
        risk_score = 0

    confidence = confidence_sum / max(1, n_rules) if n_rules else 0.3
    confidence = min(0.95, confidence)

    return findings, risk_score, confidence, evidence


def analyze_file(path: str) -> AnalysisResult:
    """
    Perform real-time NTFS forensic analysis on a single file.

    Returns AnalysisResult with findings, risk_score, and evidence.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return AnalysisResult(error=f"File not found: {path}")

    meta = _get_file_metadata(path)
    if not meta:
        # Fallback to os.stat if pywin32 unavailable
        try:
            st = os.stat(path)
            meta = FileMetadata(
                path=path,
                filename=os.path.basename(path),
                created=datetime.fromtimestamp(st.st_ctime),
                last_write=datetime.fromtimestamp(st.st_mtime),
                last_access=datetime.fromtimestamp(st.st_atime),
                file_reference=0,
                file_size=st.st_size,
                volume_letter=path[0].upper() if len(path) >= 2 and path[1] == ":" else "?",
            )
        except OSError as e:
            return AnalysisResult(error=str(e))

    usn_records = _read_usn_for_file(meta.volume_letter, meta.file_reference) if meta.file_reference else []

    findings, risk_score, confidence, evidence = _apply_rules(meta, usn_records)

    return AnalysisResult(
        metadata=meta,
        usn_records=usn_records,
        findings=findings,
        risk_score=risk_score,
        confidence=confidence,
        evidence=evidence,
    )
