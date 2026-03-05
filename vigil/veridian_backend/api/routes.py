import asyncio
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException

from utils.helpers import get_drives_info, is_admin, scan_job_manager

from .models import (
    DriveInfo,
    ImageScanRequest,
    ScanRequest,
    ScanResult,
    ScanStatus,
)


router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    return {
        "status": "ok",
        "version": "1.0.0",
        "admin_mode": is_admin(),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.post("/scan/start", response_model=dict)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    job_id = scan_job_manager.create_job(
        drive_letter=request.drive_letter,
        scan_depth=request.scan_depth,
    )
    background_tasks.add_task(
        scan_job_manager.run_scan,
        job_id=job_id,
        drive_letter=request.drive_letter,
        scan_depth=request.scan_depth,
        file_path=request.file_path,
        folder_path=request.folder_path,
    )
    # Basic depth-based estimate in seconds
    depth_estimates = {
        "quick": 120,
        "full": 240,
        "deep": 600,
    }
    estimated = depth_estimates.get(request.scan_depth, 240)
    return {
        "job_id": job_id,
        "status": "started",
        "estimated_seconds": estimated,
    }


@router.get("/scan/{job_id}/status", response_model=ScanStatus)
async def get_scan_status(job_id: str) -> ScanStatus:
    job = scan_job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    # simulate a very small async boundary
    await asyncio.sleep(0)
    return ScanStatus(**job.to_status_dict())


@router.get("/drives", response_model=list[DriveInfo])
async def get_drives() -> list[DriveInfo]:
    """Return available NTFS drives with basic info."""
    return [DriveInfo(**d) for d in get_drives_info()]


@router.post("/scan/image", response_model=dict)
async def start_image_scan(
    request: ImageScanRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """Start a scan of a .dd or .img disk image."""
    job_id = scan_job_manager.create_job(
        drive_letter="IMAGE",
        scan_depth=request.scan_depth,
        image_path=request.image_path,
    )
    background_tasks.add_task(
        scan_job_manager.run_scan_image,
        job_id=job_id,
        image_path=request.image_path,
        scan_depth=request.scan_depth,
    )
    depth_estimates = {"quick": 120, "full": 240, "deep": 600}
    return {
        "job_id": job_id,
        "status": "started",
        "estimated_seconds": depth_estimates.get(request.scan_depth, 240),
    }


@router.get("/scan/{job_id}/result", response_model=ScanResult)
async def get_scan_result(job_id: str) -> ScanResult:
    job = scan_job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not job.result:
        raise HTTPException(status_code=404, detail="Result not ready")
    return ScanResult(**job.result)

