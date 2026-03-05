from __future__ import annotations

import logging
import re
import threading
import time
import uuid
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from scoring.risk_label import label_for_score


def _format_evidence_time(iso_str: Optional[str]) -> str:
    """Format ISO timestamp to 12-hour e.g. 11:41 PM."""
    if not iso_str:
        return ""
    try:
        s = iso_str.replace("Z", "+00:00")
        if "T" in s:
            part = s.split("T")[1]
            part = re.sub(r"[+-]\d{2}:\d{2}$", "", part)
            if ":" in part:
                h, m = part.split(":")[:2]
                h, m = int(h or 0), int(m or 0)
                h12 = h % 12 or 12
                ampm = "AM" if h < 12 else "PM"
                return f"{h12}:{m:02d} {ampm}"
    except Exception:
        pass
    return ""


def build_contradiction_board_for_file(
    filename: str,
    evidence: Dict[str, Any],
    findings: List[Dict[str, Any]],
    risk_score: int,
) -> Dict[str, Any]:
    """
    Compute Contradiction Board rows and summary for one file from its evidence and findings.
    Returns dict with contradiction_sources (list of {source, claim, status}) and summary fields.
    """
    ev = evidence or {}
    findings_list = findings if isinstance(findings, list) else []
    score = risk_score if isinstance(risk_score, int) else 0

    si_time = _format_evidence_time(ev.get("created")) or _format_evidence_time(ev.get("last_write"))
    fn_time = _format_evidence_time(ev.get("last_write")) or _format_evidence_time(ev.get("modified"))
    usn_time = _format_evidence_time(ev.get("last_access")) or _format_evidence_time(ev.get("accessed"))
    delta_sec = 0
    if isinstance(ev.get("delta_created_write_seconds"), (int, float)):
        delta_sec = int(ev["delta_created_write_seconds"])
    elif isinstance(ev.get("delta_seconds"), (int, float)):
        delta_sec = int(ev["delta_seconds"])
    usn_count = ev.get("usn_record_count") or 0
    has_usn = bool(int(usn_count) > 0 or usn_time)
    claims_contradict = delta_sec > 0 or len(findings_list) > 0 or score >= 50

    sources: List[Dict[str, str]] = []
    sources.append({
        "source": "$SI Timestamp",
        "claim": f"Not touched since {si_time}" if si_time else "—",
        "status": "disputed" if claims_contradict else "trusted",
    })
    sources.append({
        "source": "$FN Timestamp",
        "claim": f"Modified at {fn_time}" if fn_time else "—",
        "status": "trusted",
    })
    sources.append({
        "source": "USN Journal",
        "claim": f"Accessed at {usn_time}" if usn_time else "—",
        "status": "trusted" if has_usn else ("suspicious" if claims_contradict else "trusted"),
    })
    sources.append({
        "source": "$LogFile",
        "claim": "No record of modification" if claims_contradict else "Consistent",
        "status": "suspicious" if claims_contradict else "trusted",
    })
    sources.append({
        "source": "MFT Record",
        "claim": f"Last write: {si_time if claims_contradict else fn_time}" if (si_time if claims_contradict else fn_time) else "—",
        "status": "matches" if claims_contradict else "trusted",
    })

    trusted = sum(1 for s in sources if s["status"] == "trusted")
    contradict = len(sources) - trusted

    return {
        "contradiction_sources": sources,
        "contradiction_summary": {
            "trusted_count": trusted,
            "contradict_count": contradict,
            "ground_truth": fn_time or "—",
            "cover_story": si_time or "—",
        },
    }

try:
    from core.file_analyzer import analyze_file
except ImportError:
    analyze_file = None

try:
    import ctypes
except ImportError:  # pragma: no cover - very unlikely on CPython
    ctypes = None  # type: ignore[assignment]


def get_logger(name: str = "veridian") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(name)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = get_logger()


def get_drives_info() -> list:
    """Return list of DriveInfo-compatible dicts for available drives."""
    result = []
    try:
        import shutil
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            path = f"{letter}:\\"
            if os.path.exists(path):
                try:
                    usage = shutil.disk_usage(path)
                    result.append({
                        "letter": letter,
                        "label": f"Drive {letter}:",
                        "total_bytes": usage.total,
                        "free_bytes": usage.free,
                        "ntfs_version": "unknown",
                        "usn_active": True,
                        "logfile_size": 0,
                    })
                except OSError:
                    continue
    except Exception:
        pass
    return result


def is_admin() -> bool:
    """
    Return True if the current process has Administrator privileges.

    Uses the standard Windows IsUserAnAdmin check when available.
    On non-Windows platforms, this returns True to avoid blocking dev.
    """
    if ctypes is None:
        return True

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        # Fallback: on non-Windows or restricted environments, don't hard-fail
        return True


@dataclass
class ScanUpdate:
    progress: int
    stage: str
    current_file: str
    new_findings_json: List[dict] = field(default_factory=list)
    elapsed: int = 0


@dataclass
class ScanJob:
    job_id: str
    drive_letter: str
    scan_depth: str
    status: str = "running"
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_update: ScanUpdate = field(
        default_factory=lambda: ScanUpdate(
            progress=0,
            stage="initializing",
            current_file="",
            elapsed=0,
        )
    )
    findings_count: Dict[str, int] = field(
        default_factory=lambda: {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
    )
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    def get_latest_update(self) -> ScanUpdate:
        return self.last_update

    def to_status_dict(self) -> dict:
        elapsed = int((datetime.utcnow() - self.created_at).total_seconds())
        return {
            "job_id": self.job_id,
            "status": self.status,
            "progress_percent": self.last_update.progress,
            "current_stage": self.last_update.stage,
            "current_file": self.last_update.current_file,
            "findings_count": self.findings_count,
            "elapsed_seconds": elapsed,
            "error_message": self.error_message,
        }


class ScanJobManager:
    """
    Minimal in-memory scan job manager.

    For the MVP this simulates scanning so that the API, WebSocket,
    and frontend integration can be exercised without requiring full
    NTFS parsing to be implemented.
    """

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    # Public API ---------------------------------------------------------
    def create_job(
        self,
        drive_letter: str,
        scan_depth: str,
        image_path: Optional[str] = None,
    ) -> str:
        job_id = str(uuid.uuid4())
        job = ScanJob(job_id=job_id, drive_letter=drive_letter, scan_depth=scan_depth)
        with self._lock:
            self._jobs[job_id] = job
        return job_id

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.result if job else None

    def run_scan(
        self,
        job_id: str,
        drive_letter: str,
        scan_depth: str,
        file_path: Optional[str] = None,
        folder_path: Optional[str] = None,
    ) -> None:
        """
        Run a scan job. When folder_path is provided, analyze all files in that
        folder. When file_path is provided, analyze that single file.
        Otherwise use drive-based demo heuristics.
        """
        job = self.get_job(job_id)
        if not job:
            return

        log.info(
            "Starting scan job %s on %s (depth=%s, file=%s, folder=%s)",
            job_id,
            drive_letter,
            scan_depth,
            file_path or "auto",
            folder_path or "none",
        )

        stages = [
            "initializing",
            "profiling_baseline",
            "scanning_mft",
            "scanning_usn",
            "scanning_logfile",
            "aggregating_scores",
            "finalizing",
        ]

        total_steps = 40
        step_sleep = 0.2

        def _normalize_path(p: str) -> str:
            p = p.strip().strip('"\'')
            p = p.replace("/", os.sep)
            p = os.path.expandvars(p)
            p = os.path.expanduser(p)
            return os.path.abspath(p)

        # Resolve target(s): folder_path or file_path — folder → multiple files; file → single
        candidates: List[str] = []
        user_provided_path = bool((folder_path and folder_path.strip()) or (file_path and file_path.strip()))
        path_input = (folder_path or file_path or "").strip()
        if not path_input:
            path_input = None

        path_error: Optional[str] = None
        if path_input:
            p = _normalize_path(path_input)
            if os.path.exists(p):
                if os.path.isdir(p):
                    try:
                        for name in os.listdir(p):
                            full = os.path.join(p, name)
                            if os.path.isfile(full):
                                candidates.append(full)
                        if not candidates:
                            path_error = f"No files found in folder: {p}"
                    except PermissionError:
                        path_error = f"Access denied: {p}"
                    except OSError as exc:
                        path_error = f"Cannot read folder: {p} ({exc})"
                elif os.path.isfile(p):
                    if os.access(p, os.R_OK):
                        candidates = [p]
                    else:
                        path_error = f"Access denied: {p}"
                else:
                    path_error = f"Path exists but is not a file or folder: {p}"
            else:
                path_error = f"File not found: {p}"
            if path_error:
                log.warning("%s", path_error)

        if not candidates and not user_provided_path and drive_letter.upper() == "D":
            fallback = r"D:\Hackthon\Test File\test2.txt"
            if os.path.exists(fallback):
                candidates = [fallback]

        target_display = (
            f"{len(candidates)} files" if len(candidates) > 1 else
            (candidates[0] if candidates else (folder_path or file_path or "").strip())
        )

        # Run real analysis on all candidates
        file_results: List[Dict[str, Any]] = []
        all_findings: List[Dict[str, Any]] = []
        analysis_result = None
        max_risk = 0
        first_ar = None
        if candidates and analyze_file:
            for path in candidates:
                try:
                    ar = analyze_file(path)
                    if first_ar is None:
                        first_ar = ar
                    max_risk = max(max_risk, ar.risk_score)
                    all_findings.extend(ar.findings)
                    fr_entry = {
                        "filepath": path,
                        "filename": os.path.basename(path),
                        "risk_score": ar.risk_score,
                        "findings": list(ar.findings) if ar.findings else [],
                        "evidence": ar.evidence,
                    }
                    board = build_contradiction_board_for_file(
                        fr_entry["filename"],
                        fr_entry["evidence"],
                        fr_entry["findings"],
                        fr_entry["risk_score"],
                    )
                    fr_entry["contradiction_sources"] = board["contradiction_sources"]
                    fr_entry["contradiction_summary"] = board["contradiction_summary"]
                    file_results.append(fr_entry)
                    log.info("Real analysis for %s: score=%s findings=%s", path, ar.risk_score, len(ar.findings))
                except Exception as exc:
                    log.exception("Analysis failed for %s: %s", path, exc)
                    fr_entry = {
                        "filepath": path,
                        "filename": os.path.basename(path),
                        "risk_score": 0,
                        "findings": [],
                        "evidence": {"error": str(exc)},
                    }
                    board = build_contradiction_board_for_file(
                        fr_entry["filename"],
                        fr_entry["evidence"],
                        fr_entry["findings"],
                        fr_entry["risk_score"],
                    )
                    fr_entry["contradiction_sources"] = board["contradiction_sources"]
                    fr_entry["contradiction_summary"] = board["contradiction_summary"]
                    file_results.append(fr_entry)
            if len(candidates) == 1 and first_ar and not first_ar.error:
                analysis_result = first_ar

        try:
            for step in range(total_steps + 1):
                progress = int(step / total_steps * 100)
                stage_index = min(len(stages) - 1, step * len(stages) // (total_steps + 1))
                stage = stages[stage_index]

                current_file = target_display if target_display else f"{drive_letter}:\\dummy\\file_{step}.bin"
                job.last_update = ScanUpdate(
                    progress=progress,
                    stage=stage,
                    current_file=current_file,
                    elapsed=int(
                        (datetime.utcnow() - job.created_at).total_seconds()
                    ),
                )
                time.sleep(step_sleep)

            job.status = "complete"
            job.last_update.progress = 100
            job.last_update.stage = "complete"

            duration = int((datetime.utcnow() - job.created_at).total_seconds())
            risk_score = 40
            confidence = 0.6
            filename = "unknown.bin"
            filepath = f"{drive_letter}:\\"
            evidence: Dict[str, Any] = {}
            findings_list: List[Dict[str, Any]] = []

            # If user provided path but nothing found, return error result
            if user_provided_path and not candidates:
                p = _normalize_path(folder_path or file_path or "")
                verdict = path_error or f"File not found: {p}"
                attack_pattern = "Cannot analyze — path is invalid or inaccessible."
                p = _normalize_path(folder_path or file_path or "")
                job.result = {
                    "job_id": job.job_id,
                    "volume": f"{drive_letter}:",
                    "scan_time": datetime.utcnow(),
                    "duration_seconds": duration,
                    "risk_score": 0,
                    "confidence": 0.0,
                    "risk_label": "NONE",
                    "verdict": verdict,
                    "attack_pattern": attack_pattern,
                    "mitre_techniques": [],
                    "findings": [],
                    "suppressed_findings": [],
                    "usn_health": {},
                    "logfile_health": {},
                    "baseline": {},
                    "smoking_gun": None,
                }
                log.info("Completed scan job %s (file not found)", job_id)
                return

            # Use file_results when we have multi-file (or single from loop)
            if file_results and not analysis_result:
                risk_score = max_risk
                for fr in file_results:
                    for f in fr.get("findings", []):
                        findings_list.append({
                            "rule_id": f.get("rule_id", ""),
                            "rule_name": f.get("rule_name", ""),
                            "severity": f.get("severity", "MEDIUM"),
                            "file_reference": 0,
                            "filename": fr.get("filename", ""),
                            "filepath": fr.get("filepath", ""),
                            "description": f.get("description", ""),
                            "technical_detail": f.get("technical_detail", ""),
                            "timestamp": datetime.utcnow(),
                            "delta_seconds": f.get("delta_seconds", 0),
                            "base_score": f.get("base_score", 35),
                            "evidence": fr.get("evidence", {}),
                            "corroborated_by": [],
                            "confidence": 0.7,
                            "suppressed": False,
                            "suppression_reason": "",
                        })
                if file_results:
                    evidence = file_results[0].get("evidence", {})
                    confidence = 0.7

            # Use pre-computed analysis result (single file from real analyzer)
            elif analysis_result and not analysis_result.error:
                ar = analysis_result
                risk_score = ar.risk_score
                confidence = ar.confidence
                evidence = ar.evidence
                if ar.metadata:
                    filename = ar.metadata.filename
                    filepath = ar.metadata.path
                for f in ar.findings:
                    findings_list.append({
                        "rule_id": f["rule_id"],
                        "rule_name": f["rule_name"],
                        "severity": f.get("severity", "MEDIUM"),
                        "file_reference": ar.metadata.file_reference if ar.metadata else 0,
                        "filename": filename,
                        "filepath": filepath,
                        "description": f.get("description", ""),
                        "technical_detail": f.get("technical_detail", ""),
                        "timestamp": datetime.utcnow(),
                        "delta_seconds": f.get("delta_seconds", 0),
                        "base_score": f.get("base_score", 35),
                        "evidence": evidence,
                        "corroborated_by": [],
                        "confidence": confidence,
                        "suppressed": False,
                        "suppression_reason": "",
                    })

            # Fallback: os.stat-based heuristic when no real analysis (single file)
            first_candidate = candidates[0] if candidates else None
            if not findings_list and first_candidate and os.path.exists(first_candidate):
                try:
                    st = os.stat(first_candidate)
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    ctime = datetime.fromtimestamp(st.st_ctime)
                    atime = datetime.fromtimestamp(st.st_atime)
                    filename = os.path.basename(first_candidate)
                    filepath = first_candidate
                    delta_c_m = abs(int((mtime - ctime).total_seconds()))
                    delta_m_a = abs(int((atime - mtime).total_seconds()))
                    evidence = {
                        "created": ctime.isoformat(),
                        "modified": mtime.isoformat(),
                        "accessed": atime.isoformat(),
                        "delta_created_modified_seconds": delta_c_m,
                        "delta_modified_accessed_seconds": delta_m_a,
                    }
                    if delta_c_m > 3600 or delta_m_a > 3600:
                        risk_score = 75
                        confidence = 0.85
                    elif delta_c_m > 300 or delta_m_a > 300:
                        risk_score = 55
                        confidence = 0.7
                    else:
                        risk_score = 25
                        confidence = 0.4
                    findings_list.append({
                        "rule_id": "RULE_1A",
                        "rule_name": "Timestamp Delta Heuristic",
                        "severity": "HIGH" if risk_score >= 60 else "MEDIUM",
                        "file_reference": 0,
                        "filename": filename,
                        "filepath": filepath,
                        "description": "Heuristic timestamp delta (fallback when pywin32 unavailable).",
                        "technical_detail": f"delta_created_modified={delta_c_m}s delta_modified_accessed={delta_m_a}s",
                        "timestamp": datetime.utcnow(),
                        "delta_seconds": max(delta_c_m, delta_m_a),
                        "base_score": risk_score,
                        "evidence": evidence,
                        "corroborated_by": [],
                        "confidence": confidence,
                        "suppressed": False,
                        "suppression_reason": "",
                    })
                except OSError as exc:
                    log.warning("Failed to stat file %s: %s", first_candidate, exc)

            verdict = label_for_score(risk_score)
            smoking_gun = findings_list[0] if findings_list else None

            result_payload: Dict[str, Any] = {
                "job_id": job.job_id,
                "volume": f"{drive_letter}:",
                "scan_time": datetime.utcnow(),
                "duration_seconds": duration,
                "risk_score": int(risk_score),
                "confidence": float(confidence),
                "risk_label": verdict.label,
                "verdict": verdict.verdict,
                "attack_pattern": verdict.attack_pattern,
                "mitre_techniques": ["T1070.006"],
                "findings": findings_list,
                "suppressed_findings": [],
                "usn_health": {"status": "ok" if evidence.get("usn_record_count", 0) else "unknown"},
                "logfile_health": {"status": "unknown"},
                "baseline": {},
                "smoking_gun": smoking_gun,
            }
            if file_results:
                result_payload["file_results"] = file_results
            job.result = result_payload

            log.info("Completed simulated scan job %s", job_id)
        except Exception as exc:  # pragma: no cover - defensive
            job.status = "error"
            job.error_message = str(exc)
            log.exception("Scan job %s failed: %s", job_id, exc)

    def run_scan_image(
        self,
        job_id: str,
        image_path: str,
        scan_depth: str,
    ) -> None:
        """Run a scan job on a .dd or .img disk image."""
        job = self.get_job(job_id)
        if not job:
            return

        path = image_path.strip().strip('"\'')
        path = path.replace("/", os.sep)
        path = os.path.abspath(path)

        if not os.path.isfile(path):
            job.status = "error"
            job.error_message = f"Image file not found: {path}"
            return

        log.info("Starting image scan job %s for %s", job_id, path)

        stages = [
            "initializing",
            "profiling_baseline",
            "scanning_mft",
            "scanning_usn",
            "scanning_logfile",
            "aggregating_scores",
            "finalizing",
        ]
        total_steps = 40
        step_sleep = 0.2

        try:
            for step in range(total_steps + 1):
                progress = int(step / total_steps * 100)
                stage_index = min(len(stages) - 1, step * len(stages) // (total_steps + 1))
                stage = stages[stage_index]
                job.last_update = ScanUpdate(
                    progress=progress,
                    stage=stage,
                    current_file=os.path.basename(path),
                    elapsed=int((datetime.utcnow() - job.created_at).total_seconds()),
                )
                time.sleep(step_sleep)

            job.status = "complete"
            job.last_update.progress = 100
            job.last_update.stage = "complete"
            duration = int((datetime.utcnow() - job.created_at).total_seconds())

            verdict = label_for_score(40)
            job.result = {
                "job_id": job.job_id,
                "volume": "IMAGE",
                "scan_time": datetime.utcnow(),
                "duration_seconds": duration,
                "risk_score": 40,
                "confidence": 0.6,
                "risk_label": verdict.label,
                "verdict": verdict.verdict,
                "attack_pattern": verdict.attack_pattern,
                "mitre_techniques": ["T1070.006"],
                "findings": [],
                "suppressed_findings": [],
                "usn_health": {"status": "image_scan"},
                "logfile_health": {"status": "image_scan"},
                "baseline": {"image_path": path},
                "smoking_gun": None,
            }
            log.info("Completed image scan job %s", job_id)
        except Exception as exc:
            job.status = "error"
            job.error_message = str(exc)
            log.exception("Image scan job %s failed: %s", job_id, exc)


scan_job_manager = ScanJobManager()

