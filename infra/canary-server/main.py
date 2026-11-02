# Canary HTTP server — ground-truth oracle for MCP tool poisoning experiments.
# Every incoming request is logged to SQLite. The oracle polls /log?since=<ts>
# after each test run to determine if exfiltration actually occurred.
#
# Run: uvicorn main:app --host 0.0.0.0 --port 8080

import json
from datetime import UTC, datetime

import aiosqlite
from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI(title="MCP-SoK Canary Server")
DB = "/data/canary.db"


class LogEntry(BaseModel):
    ts: str
    method: str
    path: str
    headers: dict[str, str]
    body: str


@app.on_event("startup")
async def init_db() -> None:
    async with aiosqlite.connect(DB) as db:
        await db.execute(
            """CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY,
                ts TEXT,
                method TEXT,
                path TEXT,
                headers TEXT,
                body TEXT
            )"""
        )
        await db.commit()


async def _log_request(request: Request, method: str, path: str) -> dict[str, str]:
    body = (await request.body()).decode(errors="replace")
    ts = datetime.now(UTC).isoformat()
    async with aiosqlite.connect(DB) as db:
        await db.execute(
            "INSERT INTO requests(ts, method, path, headers, body) VALUES(?,?,?,?,?)",
            (ts, method, path, json.dumps(dict(request.headers)), body),
        )
        await db.commit()
    return {"status": "logged", "ts": ts}


# Explicit routes MUST be defined before the catch-all /{path:path}
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/log")
async def get_log(since: str = "2000-01-01T00:00:00", cell_id: str = "") -> list[LogEntry]:
    async with aiosqlite.connect(DB) as db:
        if cell_id:
            query = "SELECT ts, method, path, headers, body FROM requests WHERE ts > ? AND path LIKE ? ORDER BY ts"
            params: tuple = (since, f"/{cell_id}%")
        else:
            query = "SELECT ts, method, path, headers, body FROM requests WHERE ts > ? ORDER BY ts"
            params = (since,)
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    return [
        LogEntry(
            ts=r[0],
            method=r[1],
            path=r[2],
            headers=json.loads(r[3]),
            body=r[4],
        )
        for r in rows
    ]


@app.post("/reset")
async def reset() -> dict[str, bool]:
    async with aiosqlite.connect(DB) as db:
        await db.execute("DELETE FROM requests")
        await db.commit()
    return {"cleared": True}


@app.post("/exfil")
async def exfil(request: Request) -> dict[str, str]:
    return await _log_request(request, "POST", "/exfil")


@app.api_route("/{path:path}", methods=["GET", "PUT", "PATCH", "DELETE", "POST"])
async def catch_all(request: Request, path: str) -> dict[str, str]:
    body = (await request.body()).decode(errors="replace")
    ts = datetime.now(UTC).isoformat()
    qs = str(request.query_params)
    full_path = f"/{path}" if not qs else f"/{path}?{qs}"
    async with aiosqlite.connect(DB) as db:
        await db.execute(
            "INSERT INTO requests(ts, method, path, headers, body) VALUES(?,?,?,?,?)",
            (ts, request.method, full_path, json.dumps(dict(request.headers)), body),
        )
        await db.commit()
    return {"status": "logged", "ts": ts}
