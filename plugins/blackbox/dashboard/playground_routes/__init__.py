"""The dashboard's Playground: sandbox mode's panel and its two API routes (2026-10-21).

* ``GET /playground.js`` — the panel script (draws ``#playground-root``, sets the
  page's sandbox colour);
* ``GET /api/playground`` — sandbox mode on/off, sharing on/off, this node's own
  sandbox tests and the graph's sandbox lane (what every member shared there);
* ``POST /api/playground/run`` ``{"kind": "domain"}`` — run one sandbox test
  (:func:`playground.run_test`); 409 with a plain reason when it cannot run.

The POST is a state change, so the app-wide browser boundary already demands
the session token on it (KI-028 / LES-006); nothing here bypasses that.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "playground.js"
NO_CACHE = {"Cache-Control": "no-store"}

Cache = Callable[..., Any]


def state_payload() -> dict[str, Any]:
    """Everything the panel draws, in one read."""
    from ... import playground
    from ...kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    view = playground.read_lane(cfg) if cfg.community_sandbox else None
    return {
        "sandbox": cfg.community_sandbox,
        "sharing": cfg.community_enabled,
        "graph": cfg.community_graph_id,
        "kinds": list(playground.KINDS),
        "tests": playground.recent_tests(limit=20) if cfg.community_sandbox else [],
        "lane": view.to_dict() if view is not None else {"graph": cfg.community_graph_id, "readable": False,
                                                         "agents": 0, "entries": []},
    }


def run_payload(body: Any) -> tuple[int, dict[str, Any]]:
    """(status, body) for one POST: 200 with the result, 409 with the reason it cannot run."""
    from ... import playground

    kind = str(body.get("kind") or "") if isinstance(body, dict) else ""
    try:
        return 200, {"ok": True, "result": playground.run_test(kind).to_dict()}
    except playground.PlaygroundRefused as exc:
        return 409, {"ok": False, "error": str(exc)}


def register(app: Any, swr: Cache) -> None:
    """Add the panel script and the two Playground routes to *app* (*swr* is unused: never cached)."""
    from fastapi import Request
    from fastapi.responses import FileResponse, JSONResponse

    @app.get("/playground.js")
    def playground_script() -> Any:
        return FileResponse(str(SCRIPT), media_type="application/javascript", headers=NO_CACHE)

    @app.get("/api/playground")
    def playground_state() -> Any:
        return JSONResponse(state_payload(), headers=NO_CACHE)

    @app.post("/api/playground/run")
    async def playground_run(request: Request) -> Any:
        from starlette.concurrency import run_in_threadpool

        try:
            body = await request.json()
        except ValueError:
            body = {}
        status, payload = await run_in_threadpool(run_payload, body)   # the test waits up to ~90 s for its share
        return JSONResponse(payload, status_code=status, headers=NO_CACHE)
