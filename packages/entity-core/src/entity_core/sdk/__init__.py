"""SDK surface — the language-level contracts that compose over the protocol.

Per ``SDK-EXTENSION-OPERATIONS.md`` v0.8 §11 (closure-completion landing):
the ``Dispatcher`` Protocol unifies handler-internal and cross-peer outer-caller
dispatch into a single contract that SDK affordances (e.g.,
``content.EnsureClosure``) compose against. Both :class:`HandlerContext` and
:class:`Connection` are adapted to this contract via thin wrappers; existing
APIs are untouched.

The Dispatcher / ExecuteRequest split is the Python answer to the cross-impl
question raised in pass-1 of the materialization proposal review: the request
shape MUST carry V7 §6.8 propagation (capability override + chain) and V7 §3.3
v7.51 envelope-``included`` preservation so cross-peer chain dispatch composes
per EXTENSION-CONTINUATION §4.2 case 3.
"""

from __future__ import annotations

from entity_core.sdk.dispatcher import (
    ConnectionDispatcher,
    Dispatcher,
    ExecuteRequest,
    HandlerContextDispatcher,
)

__all__ = [
    "Dispatcher",
    "ExecuteRequest",
    "HandlerContextDispatcher",
    "ConnectionDispatcher",
]
