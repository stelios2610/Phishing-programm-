"""Local web UI. It listens for the browser on this computer; it does not upload readings."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel

from netwatch import __version__
from netwatch.monitor import Monitor, MonitorError
from netwatch.store import default_state_path

STATIC = Path(__file__).resolve().parent / "static"

_ERRORS = {
    "no_gateway": "No default gateway is visible.",
    "no_mac": "The router has not answered ARP yet, so there is no MAC to confirm.",
    "mismatch": (
        "The router MAC does not match the one you confirmed. Pinning keeps the old one. "
        "Accept the new one only after checking it on the device."
    ),
    "invalid": "Invalid address. Nothing was changed.",
}


class ConfirmBody(BaseModel):
    accept_change: bool = False


def _interval() -> float:
    raw = os_interval()
    return min(30.0, max(0.5, raw))


def os_interval() -> float:
    import os

    try:
        return float(os.environ.get("NETWATCH_INTERVAL", "2"))
    except ValueError:
        return 2.0


def _polling_enabled() -> bool:
    import os

    return os.environ.get("NETWATCH_DISABLE_POLL") != "1"


@asynccontextmanager
async def lifespan(app: FastAPI):
    monitor = Monitor(
        state_path=default_state_path(),
        poll=_polling_enabled(),
        interval=_interval(),
    )
    app.state.monitor = monitor
    if monitor.poll:
        monitor.tick()
        monitor.start()
    try:
        yield
    finally:
        monitor.stop()


app = FastAPI(
    title="NetWatch",
    description="Local sentinel for pings and LAN man-in-the-middle signs.",
    version=__version__,
    lifespan=lifespan,
)


def _monitor(request: Request) -> Monitor:
    return request.app.state.monitor


@app.exception_handler(MonitorError)
def monitor_error(request: Request, exc: MonitorError) -> JSONResponse:
    message = _ERRORS.get(exc.code, "That could not be completed.")
    return JSONResponse(
        status_code=409,
        content={
            "ok": False,
            "error": exc.code,
            "message": message,
            "state": request.app.state.monitor.state_dict(),
        },
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "netwatch"}


@app.get("/api/state")
def state(request: Request) -> JSONResponse:
    return JSONResponse(
        _monitor(request).state_dict(),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/gateway/confirm")
def confirm(request: Request, body: ConfirmBody | None = None) -> dict:
    accept = bool(body and body.accept_change)
    return _monitor(request).confirm(accept)


@app.post("/api/gateway/forget")
def forget(request: Request) -> dict:
    return _monitor(request).forget()


@app.post("/api/protect")
def protect(request: Request) -> dict:
    return _monitor(request).protect()


@app.post("/api/demo/ping")
def demo_ping(request: Request) -> dict:
    return _monitor(request).demo_ping()


@app.post("/api/demo/mitm")
def demo_mitm(request: Request) -> dict:
    return _monitor(request).demo_mitm()


@app.post("/api/demo/redirect")
def demo_redirect(request: Request) -> dict:
    return _monitor(request).demo_redirect()


@app.post("/api/demo/reset")
def demo_reset(request: Request) -> dict:
    return _monitor(request).demo_reset()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
