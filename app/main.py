"""NetView — agentless network inventory. FastAPI application entrypoint."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import credentials, devices, scans, settings_routes
from .api.deps import require_auth
from .config import get_settings
from .database import init_db
from .scheduler import start_scheduler, stop_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("netview")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio

    from .scan_manager import manager
    init_db()
    log.info("Database ready")
    manager.set_loop(asyncio.get_running_loop())
    start_scheduler()
    yield
    stop_scheduler()


settings = get_settings()
app = FastAPI(
    title="NetView",
    description="Agentless network inventory with MeshCentral correlation",
    version="1.0.0",
    root_path=settings.root_path,
    lifespan=lifespan,
)

app.include_router(devices.router)
app.include_router(scans.router)
app.include_router(credentials.router)
app.include_router(settings_routes.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# Serve the SPA. Static assets under /static; index at root.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", dependencies=[Depends(require_auth)])
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
