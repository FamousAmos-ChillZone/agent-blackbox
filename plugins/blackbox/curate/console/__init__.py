"""Console — the curator node's key console: a small web app over the existing ``curate`` verbs.

Pattern: Facade. The console is HTTP in front of what ``curate`` already does
(build, sign and publish a key manifest; answer join requests); it holds no
business logic of its own.

Public surface:

* ``create_console_app(settings) -> FastAPI`` — the app, bound to 127.0.0.1 and
  guarded server-side by ``kernel.browser_boundary`` plus its own login.
* ``add_console_routes(app, ConsoleServices(...))`` (``routes.py``) — join
  requests, approve/decline, immediate removal (a narrowing list), renewal
  and publishing, over ``roster.py`` (the K2-validated next list, the join
  store, renewal reminders at days 40/50/55 and the alarm inside 5 days).
* ``collect_metrics(MetricsSources(), context, now) -> PipelineMetrics``
  (``metrics.py``, C4) — the F-035 pipeline numbers read from the typed stores;
  ``GET /api/metrics`` answers ``as_dict()`` and the watch verb (W3,
  ``curate.intake``) posts ``as_payload()`` / ``lines()`` — one record, one set
  of metric names (``METRIC_NAMES``); a store that cannot be read is
  ``UNAVAILABLE``, an event that never happened yet is ``NEVER``.
* ``blackbox curate console`` — registered from this package's ``commands.py``
  (``add_console_parser``), never from ``curate/commands.py``.
* ``ConsoleSessions`` (``session.py``) — login sessions and per-session CSRF
  tokens; memory only, one lock, a login expires after 15 idle minutes.
* ``RootSigner`` (``root_signer.py``, a Command) — decrypts the root key, signs
  ONE prepared manifest and discards the key inside the request; no object holds
  the decrypted key between requests.
* ``EncryptedRootStore`` (``root_store.py``) — the root key at rest, encrypted,
  ``<curate home>/root_a.enc.pem`` mode 0600.

Must not be imported from ``dashboard`` (the map forbids ``dashboard`` -> ``curate``).
"""

from .commands import add_console_parser, cmd_console
from .metrics import (METRIC_NAMES, NEVER, UNAVAILABLE, MetricsSources, PipelineMetrics, UpdateUptake, WalletBalance,
                      collect_metrics)
from .routes import ConsoleServices, add_console_routes

__all__ = ["ConsoleServices", "METRIC_NAMES", "NEVER", "UNAVAILABLE", "MetricsSources", "PipelineMetrics", "UpdateUptake",
           "WalletBalance", "add_console_parser", "add_console_routes", "cmd_console", "collect_metrics"]
