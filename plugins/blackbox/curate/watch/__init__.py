"""Watch — this node's checks of what was published against what it signed.

Pattern: pure comparisons of two ledgers, each returning ``kernel.health``
``HealthItem`` s; the curator beat (``curate.service``) schedules them.

Public surface:

* ``SigningLog`` / ``SigningRow`` (``signing_log.py``) — append-only JSONL, one
  lock, ``<curate home>/signing_log.jsonl``; written ONLY by
  ``CurateContext.sign`` / ``.cosign`` (``curate/context.py``).
* ``reconcile(signing_log, published_under_my_key)`` (``reconciler.py``) — published
  statements under this node's key compared with its signing log; one missing
  from the log → SECURITY.
* ``unexpected_assets(new_assets, expected)`` (``graph_watch.py``) — new
  verified-graph assets compared with the expected set: ``LedgerExpectation``
  (the publish ledger, publisher node) or ``CosignExpectation`` (this node's
  co-sign log, second curator node); an asset neither explains → SECURITY.
  Beside it ``proposal_rate`` (a lane at 5× its normal → ACTION) and
  ``dead_man_beat`` (the watcher's once-per-UTC-day "all quiet" record).
* ``wallet_drift(chain_record, ledger)`` (``wallet_watch.py``) — the publishing
  wallet's balance drop compared with the ledger's spend; more → SECURITY.

* ``node_sink`` / ``WebhookSink`` / ``TelegramSink`` / ``manifest_items``
  (``delivery.py``) — where this node's announcements, alarms and metrics go:
  each node's OWN sink credential (``<curate home>/alarm_sink.json``) and
  the manifest watcher's items (W1). ``curate.intake.AlarmWatcher`` decides
  what is new and calls the sink. The F-035 metrics record it posts is
  ``curate.console.PipelineMetrics`` (C4), typed here as ``MetricsRecord``.

No function here does I/O except through the readers its caller injects —
except ``delivery.py``, the one module that posts outward.
"""

from .delivery import (NODE_SINK_FILE, IntakeEvent, IntakeSink, MetricsRecord, SinkCredentialError, TelegramSink,
                       WebhookSink, manifest_items, node_sink)
from .graph_watch import (CosignExpectation, DeadManBeat, GraphAsset, LedgerExpectation, dead_man_beat,
                          proposal_rate, unexpected_assets)
from .reconciler import PublishedStatement, reconcile
from .signing_log import SigningLog, SigningRow
from .wallet_watch import ChainRecord, wallet_drift

__all__ = ["NODE_SINK_FILE", "ChainRecord", "CosignExpectation", "DeadManBeat", "GraphAsset", "IntakeEvent",
           "IntakeSink", "LedgerExpectation", "MetricsRecord", "PublishedStatement", "SigningLog", "SigningRow",
           "SinkCredentialError", "TelegramSink", "WebhookSink", "dead_man_beat", "manifest_items", "node_sink",
           "proposal_rate", "reconcile", "unexpected_assets", "wallet_drift"]
