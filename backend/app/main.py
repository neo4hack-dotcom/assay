"""FastAPI app: API + optional token auth + single-origin SPA serving."""
from __future__ import annotations

import hmac
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .deps import container as c
from .engine import __version__

app = FastAPI(title="Assay — MCP production readiness auditor", version=__version__)

# Dev only: Vite on :3100 calls the API on :3101. Production is same-origin.
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3100", "http://127.0.0.1:3100"],
                   allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security(request: Request, call_next):
    token = c.settings.auth_token
    path = request.url.path
    if token and path.startswith("/api/") and path != "/api/health":
        got = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(got.encode(), token.encode()):
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


app.include_router(router)


def _static_dir() -> Path:
    if c.settings.static_dir:
        return Path(c.settings.static_dir).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


STATIC = _static_dir()
if (STATIC / "index.html").is_file():
    if (STATIC / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        if path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        cand = (STATIC / path).resolve()
        if cand.is_file() and STATIC in cand.parents:
            return FileResponse(cand)
        return FileResponse(STATIC / "index.html")
