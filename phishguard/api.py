"""FastAPI app: local phishing URL analyzer. Does not fetch submitted URLs."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishguard.engine import analyze

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="PhishGuard",
    description="Local phishing URL detector. Submitted URLs are never fetched.",
    version="1.0.0",
)


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=8000)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def api_analyze(body: AnalyzeRequest) -> dict:
    return analyze(body.url).to_dict()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
