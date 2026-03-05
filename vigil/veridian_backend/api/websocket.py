import asyncio

from fastapi import FastAPI, WebSocket
from starlette.websockets import WebSocketDisconnect

from utils.helpers import scan_job_manager


def register_websocket_routes(app: FastAPI) -> None:
    @app.websocket("/ws/scan/{job_id}")
    async def websocket_scan(websocket: WebSocket, job_id: str) -> None:  # type: ignore[unused-ignore]  # noqa: F811
        await websocket.accept()
        try:
            while True:
                job = scan_job_manager.get_job(job_id)
                if not job:
                    await websocket.send_json({"error": "job not found"})
                    break

                update = job.get_latest_update()
                await websocket.send_json(
                    {
                        "progress_percent": update.progress,
                        "stage": update.stage,
                        "current_file": update.current_file,
                        "new_findings": update.new_findings_json,
                        "elapsed": update.elapsed,
                    }
                )

                if job.status in ("complete", "error"):
                    break

                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            # Client disconnected; nothing special to do for MVP
            return

