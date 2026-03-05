import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router as api_router
from api.websocket import register_websocket_routes
from utils.helpers import get_logger, is_admin


log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if not is_admin():
        msg = (
            "VERIDIAN must be run with Administrator privileges to access "
            "raw NTFS structures. Please restart the process elevated."
        )
        log.error(msg)
        raise RuntimeError(msg)
    log.info("VERIDIAN Forensic API starting with admin privileges.")
    port = int(os.environ.get("PORT", "8000"))
    log.info("API docs available at http://localhost:%s/docs", port)
    yield
    # Shutdown (nothing to do)


def create_app() -> FastAPI:
    app = FastAPI(
        title="VERIDIAN Forensic API",
        description="NTFS Live Tampering Detection Engine",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:5000",
            "http://127.0.0.1:5500",
            "*",
        ],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include REST routes
    app.include_router(api_router, prefix="/api")

    # Register WebSocket handler
    register_websocket_routes(app)

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level=logging.INFO,
    )

