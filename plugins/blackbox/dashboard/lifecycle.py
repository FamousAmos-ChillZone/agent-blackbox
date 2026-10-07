"""Startup and shutdown hooks for the dashboard app, without FastAPI's deprecated ``on_event``.

``@app.on_event("startup")`` is deprecated in FastAPI (it raises a
DeprecationWarning per registration, ~140 extra warnings per suite run) in
favour of a *lifespan*. These decorators chain each hook onto the app's
existing lifespan, so any module that is handed an app (``server.create_app``,
``community_routes``) can add hooks, in any order, with no shared registry.

Pattern: Decorator (each registration wraps the previous lifespan — a chain
of async context managers). Startup hooks run in registration order; shutdown
hooks run in reverse, like nested ``with`` blocks.

Usage::

    @on_startup(app)
    def _start_worker() -> None: ...

    @on_shutdown(app)
    def _stop_worker() -> None: ...
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, TypeVar

Hook = TypeVar("Hook", bound=Callable[[], Any])


def _chain(app: Any, startup: Callable[[], Any] | None, shutdown: Callable[[], Any] | None) -> None:
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(the_app: Any) -> AsyncIterator[Any]:
        async with inner(the_app) as state:
            if startup is not None:
                startup()
            try:
                yield state
            finally:
                if shutdown is not None:
                    shutdown()

    app.router.lifespan_context = lifespan


def on_startup(app: Any) -> Callable[[Hook], Hook]:
    """Decorator: run the (synchronous) function when *app* starts."""
    def register(hook: Hook) -> Hook:
        _chain(app, hook, None)
        return hook
    return register


def on_shutdown(app: Any) -> Callable[[Hook], Hook]:
    """Decorator: run the (synchronous) function when *app* shuts down."""
    def register(hook: Hook) -> Hook:
        _chain(app, None, hook)
        return hook
    return register
