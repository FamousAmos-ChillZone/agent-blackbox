"""One owned DKG snapshot job, with explicit configured-core or independent RPC trust.

--wait waits for fresh inventory coverage; usable rules and full coverage remain
separate facts. Detection always queries local DKG and writes no rule export.
"""
from __future__ import annotations

import http.client
import json
import time
from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient, DkgError, signed_request_headers
from ..kernel.local_http import request
from ..ruleset.direct.client import local_url
from .. import ruleset
from . import state

PATH = "/api/context-graph/snapshot-sync"
POLL_SECONDS = 2.0


class SnapshotSyncClient(DkgClient):
    """Bounded local operator transport, separate from the detection read client."""
    def __init__(self, cfg):
        super().__init__(url=local_url(cfg.dkg_url), dkg_home=cfg.dkg_home)

    def request(self, method, path, body=None, timeout=15):
        if (method, path) not in {("GET", PATH), ("POST", PATH),
                                  ("POST", "/api/context-graph/subscribe")}:
            raise DkgError("SNAPSHOT_ROUTE_REFUSED")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            headers.update(signed_request_headers(self.token, method, path, data))
        try:
            code, raw = request(self.url, method, path, data, headers,
                                deadline=time.monotonic() + (timeout or 15), max_bytes=65536)
            if code >= 300:
                raise DkgError("DKG_UPGRADE_REQUIRED" if code == 404 else "SNAPSHOT_REQUEST_REFUSED", status_code=code)
            reply = json.loads(raw)
            if not isinstance(reply, dict):
                raise ValueError
            return reply
        except (ValueError, OSError, http.client.HTTPException) as exc:
            raise DkgError("SNAPSHOT_UNAVAILABLE") from exc


def sync(args):
    cfg = load_blackbox_config()
    return run(SnapshotSyncClient(cfg), cfg, args)


def run(client, cfg, args):
    settings = cfg.snapshot_sync
    if settings is None or cfg.detection_backend != "dkg":
        raise ValueError("A snapshot sync requires configured direct DKG mode")
    payload = {"contextGraphId": cfg.context_graph_id, "onChainId": settings.on_chain_id,
               "trustedCorePeerIds": list(settings.trusted_core_peers), "mode": settings.mode}
    budget = max(1.0, float(getattr(args, "timeout", 3600) or 3600))
    deadline = time.monotonic() + budget
    usable = 0
    cursor = {}
    job_id = None

    def record(status, phase, *, error="", result=None):
        result = result or {}
        state.write(status, context_graph_id=cfg.context_graph_id, phase=phase,
                    chain_evidence_mode=settings.mode, job_id=job_id,
                    public_entries=usable, count_kind="sampled-usable-rules",
                    detection_ready=usable > 0, graph_complete=result.get("current") is True,
                    complete=result.get("current") is True,
                    assets=result.get("assets"), committed=result.get("committed"),
                    snapshot_digest=result.get("snapshotDigest"), error=error)

    try:
        # Check capability before subscribing or starting a transfer. Never silently fall back.
        job = client.request("GET", PATH)
        if job.get("state") not in {"idle", "running", "complete", "failed"}:
            raise DkgError("SNAPSHOT_RESPONSE_INVALID")
        if job["state"] == "running":
            if job.get("request") != payload:
                raise DkgError("ANOTHER_SNAPSHOT_JOB_IS_RUNNING")
        else:
            subscribed = client.subscribe_context_graph(cfg.context_graph_id)
            if subscribed.get("subscribed") is not True:
                raise DkgError("SNAPSHOT_SUBSCRIPTION_REFUSED")
            job = client.request("POST", PATH, payload)
        job_id = job.get("id")
        if not isinstance(job_id, str) or not job_id:
            raise DkgError("SNAPSHOT_RESPONSE_INVALID")
        while time.monotonic() < deadline:
            if job.get("id") != job_id or job.get("request") != payload:
                raise DkgError("SNAPSHOT_JOB_CHANGED")
            if job.get("state") == "failed":
                raise DkgError("SNAPSHOT_RECOVERY_FAILED")
            if job.get("state") not in {"running", "complete"}:
                raise DkgError("SNAPSHOT_RESPONSE_INVALID")
            try:
                usable = ruleset.ready_sample(cfg, cursor=cursor)
            except DkgError:
                usable = 0
            if job["state"] == "complete":
                result = job.get("result")
                if (not isinstance(result, dict) or result.get("mode") != settings.mode
                        or result.get("completeAsOfSnapshot") is not True
                        or type(result.get("assets")) is not int or result["assets"] < 0
                        or result.get("committed") != result["assets"]):
                    raise DkgError("SNAPSHOT_RESPONSE_INVALID")
                complete = result.get("current") is True
                record("complete" if complete else "partial", "snapshot-coverage-checked", result=result)
                print(f"Snapshot coverage: {result['committed']}/{result['assets']} assets; "
                      f"current={complete}; usable rule sample={usable}.")
                return 0 if complete and (usable > 0 or not getattr(args, "require_rules", False)) else 2
            record("running", "recovering-core-snapshot")
            if not getattr(args, "wait", False):
                record("partial", "snapshot-job-running")
                print("The DKG snapshot job is running. Run sync --wait to observe its coverage result.")
                return 0
            time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            job = client.request("GET", PATH)
        record("partial", "snapshot-observation-timeout", error="The owned DKG job may still be running")
        return 2
    except DkgError as exc:
        # Detailed peer/endpoint errors stay in the DKG log, not user-facing status.
        record("failed", "snapshot-recovery-unavailable", error=str(exc))
        print(f"Snapshot sync unavailable: {exc}")
        return 2
    except KeyboardInterrupt:
        record("partial", "snapshot-observation-cancelled", error="The owned DKG job may still be running")
        return 130
