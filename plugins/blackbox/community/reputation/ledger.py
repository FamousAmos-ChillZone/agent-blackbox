"""The curator-PRIVATE reputation ledger (R4, plan §10 / §13 data protection).

Never published. Each reporter is keyed by a pseudonym — HMAC of its key
under a per-reporter random salt — and ERASURE deletes the salt, after which
nothing in the file can be tied to the key again (crypto-shredding). Entries
inactive for :data:`RETENTION_DAYS` are dropped on load. One lock, atomic
tmp+rename writes, the same shape as every other store in the plugin.

Usage (curator machine)::

    ledger = ReputationLedger()                                   # $BLACKBOX_HOME/curate/reputation.json
    ledger.record(key, Outcome("2026-10-02", confirmed=True), novel=True, first_seen_day="2026-09-10")
    standing = ledger.standing(key)                               # ReporterStanding
    ledger.reputation(key, today="2026-10-02")                    # Beta mean with forgetting
    ledger.erase(key)                                             # deletes the salt: the entry is unreadable forever
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...kernel import constants
from .bands import ReporterStanding, ReputationBand
from .scoring import Outcome, beta_reputation

logger = logging.getLogger(__name__)

#: Entries with no outcome for two years are deleted on load.
RETENTION_DAYS = 730
_LEDGER_FILE = "reputation.json"


def pseudonym(salt_hex: str, key: str) -> str:
    """HMAC-SHA256(salt, reporter key) — the ledger's only handle on a reporter."""
    return hmac.new(bytes.fromhex(salt_hex), key.lower().encode("utf-8"), hashlib.sha256).hexdigest()


class ReputationLedger:
    """``$BLACKBOX_HOME/curate/reputation.json``: ``{"salts": {key: salt}, "entries": {pseudonym: entry}}``.

    An entry holds the standing fields plus its outcome list. The salt map is
    the only link from a key to its entry; erasing a key deletes its salt.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / "curate" / _LEDGER_FILE)
        self._lock = threading.Lock()

    # -- reads ---------------------------------------------------------------

    def standing(self, key: str) -> ReporterStanding:
        with self._lock:
            data = self._load()
            entry = self._entry(data, key)
        return _standing_from(key, entry) if entry is not None else ReporterStanding(key=key)

    def reputation(self, key: str, today: str) -> float:
        with self._lock:
            entry = self._entry(self._load(), key)
        outcomes = [Outcome(o["day"], bool(o["confirmed"])) for o in (entry or {}).get("outcomes", [])]
        return beta_reputation(outcomes, today)

    def keys(self) -> List[str]:
        with self._lock:
            return sorted(self._load()["salts"])

    # -- writes --------------------------------------------------------------

    def record(self, key: str, outcome: Outcome, *, novel: bool = False, strike: bool = False,
               first_seen_day: str = "") -> ReporterStanding:
        """Add one curator outcome (creating the entry and its salt on first use)."""
        with self._lock:
            data = self._load()
            salt = data["salts"].setdefault(key.lower(), secrets.token_hex(16))
            entry = data["entries"].setdefault(pseudonym(salt, key), _new_entry(first_seen_day or outcome.day))
            entry["outcomes"].append({"day": outcome.day, "confirmed": outcome.confirmed})
            entry["confirmed" if outcome.confirmed else "rejected"] += 1
            entry["novel_credits"] += 1 if (novel and outcome.confirmed) else 0
            entry["strikes"] += 1 if strike else 0
            entry["last_day"] = max(entry.get("last_day", ""), outcome.day)
            self._save(data)
            return _standing_from(key, entry)

    def set_standing(self, standing: ReporterStanding) -> None:
        """Store band / org / sponsor / lockout decisions (counters come from outcomes)."""
        with self._lock:
            data = self._load()
            salt = data["salts"].setdefault(standing.key.lower(), secrets.token_hex(16))
            entry = data["entries"].setdefault(pseudonym(salt, standing.key), _new_entry(standing.first_seen_day))
            entry.update({"band": standing.band.value, "org": standing.org, "sponsor": standing.sponsor,
                          "lockout_until": standing.lockout_until, "first_seen_day": standing.first_seen_day,
                          "confirmed": standing.confirmed, "rejected": standing.rejected, "strikes": standing.strikes,
                          "novel_credits": standing.novel_credits})
            if standing.lockout_until:
                entry["outcomes"] = []   # re-graduation starts from zero
            self._save(data)

    def erase(self, key: str) -> bool:
        """Crypto-shred: drop the salt (and the now-unreachable entry). True when something was erased."""
        with self._lock:
            data = self._load()
            salt = data["salts"].pop(key.lower(), None)
            if salt is None:
                return False
            data["entries"].pop(pseudonym(salt, key), None)
            self._save(data)
            return True

    # -- storage -------------------------------------------------------------

    def _entry(self, data: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
        salt = data["salts"].get(key.lower())
        return data["entries"].get(pseudonym(salt, key)) if salt else None

    def _load(self) -> Dict[str, Any]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            salts = {str(k): str(v) for k, v in data.get("salts", {}).items()}
            entries = {str(k): dict(v) for k, v in data.get("entries", {}).items() if isinstance(v, dict)}
        except (OSError, ValueError, AttributeError):
            return {"salts": {}, "entries": {}}
        cutoff = (date.today() - timedelta(days=RETENTION_DAYS)).isoformat()
        live = {p: e for p, e in entries.items() if e.get("last_day", "") >= cutoff or not e.get("outcomes")}
        return {"salts": salts, "entries": live}

    def _save(self, data: Dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            logger.warning("blackbox: could not save the reputation ledger (%s)", exc)


def _new_entry(first_seen_day: str) -> Dict[str, Any]:
    return {"band": ReputationBand.PROBATION.value, "first_seen_day": first_seen_day, "confirmed": 0, "rejected": 0,
            "strikes": 0, "novel_credits": 0, "org": "", "sponsor": "", "lockout_until": "", "last_day": "",
            "outcomes": []}


def _standing_from(key: str, entry: Dict[str, Any]) -> ReporterStanding:
    try:
        band = ReputationBand(entry.get("band") or "probation")
    except ValueError:
        band = ReputationBand.PROBATION
    return replace(ReporterStanding(key=key), band=band, first_seen_day=str(entry.get("first_seen_day") or ""),
                   confirmed=int(entry.get("confirmed") or 0), rejected=int(entry.get("rejected") or 0),
                   strikes=int(entry.get("strikes") or 0), novel_credits=int(entry.get("novel_credits") or 0),
                   org=str(entry.get("org") or ""), sponsor=str(entry.get("sponsor") or ""),
                   lockout_until=str(entry.get("lockout_until") or ""))
