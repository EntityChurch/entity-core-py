"""PROPOSAL-CONTINUATION-STANDING-MODEL §3 / O1 — the administrative
advance-authority gate, exercised over a REAL wire EXECUTE (not a
directly-constructed HandlerContext).

`tests/integration/test_continuation_advance_authority.py` proves the split
at the handler level, including `test_administrative_empty_cap_trusted`
(`caller_capability={}` on the administrative path -> 200). O1's 2026-07-28
resolution pins the load-bearing case precisely: "an administrative advance
whose caller presents no capability on the continuation path is DENIED
(403)... exercised by AT-4, not assumed" — and flags that Go's
no-op-on-absent-cap and Python's require-cap-present must be shown, not
assumed, to agree.

The reconciliation: the handler-level `{}`-trusted branch is only ever
reachable from a genuinely INTERNAL dispatch (a chain's onward hop, a
delivery mechanism) — a real external wire caller with no capability at all
never reaches the continuation handler in the first place. `check_handler_scope`
(peer.py `_handle_execute`, unconditional Steps 1-2 — runs before the
resource-target check and before any handler executes) iterates
`capability_data.get("grants", [])`; an empty/absent grants list makes that
loop a no-op, and the function falls through to `return False` ->
403 `capability_denied` at the dispatcher, before the continuation handler's
own (trusting) `{}` branch is ever reached. This file proves that
end-to-end, over a real connection, rather than asserting it from reading
the source.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.continuation import CONTINUATION_TYPE


@pytest.fixture
async def peer_b():
    kp = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19094)
    yield peer, kp
    await peer.stop()


def _install_administrative_continuation(peer, path: str) -> None:
    """Install a bare forward continuation directly (bypassing the wire
    install-authorization flow — irrelevant to what this file tests)."""
    dispatch_cap = Entity(
        type="system/capability/token",
        data={"grants": [{"handlers": {"include": ["*"]},
                          "resources": {"include": ["*"]},
                          "operations": {"include": ["*"]}}]},
    )
    dispatch_cap_hash = peer.content_store.put(dispatch_cap)
    continuation = Entity(
        type=CONTINUATION_TYPE,
        data={
            "target": "system/tree",
            "operation": "put",
            "params": {"tree_id": "default"},
            "dispatch_capability": dispatch_cap_hash,
        },
    )
    full_uri = peer.emit_pathway.entity_tree.normalize_uri(path)
    peer.emit_pathway.emit(full_uri, continuation, EmitContext.bootstrap())


def _self_issued_cap(kp, parent_hash, *, grants: list) -> tuple[Entity, Entity, Entity]:
    """A minimal self-issued capability entity, chained under the
    connection's own cap (parent), signed by kp."""
    ident = create_identity_entity(kp)
    ident_hash = ident.compute_hash()
    cap = Entity(
        type="system/capability/token",
        data={
            "grants": grants,
            "granter": ident_hash,
            "grantee": ident_hash,
            "parent": parent_hash,
            "created_at": 0,
        },
    )
    sig = create_signature_entity(kp, cap.compute_hash(), ident_hash)
    return cap, sig, ident


@pytest.mark.asyncio
async def test_at4_administrative_advance_with_zero_capability_is_denied(peer_b):
    """AT-4 (O1, load-bearing) — a bare `advance` EXECUTE whose presented
    capability grants NOTHING is denied fail-closed, never allowed by
    omission. Presented with `resource.targets` set (the wire-standard
    shape), so the dispatcher's V7 §5.2 resource check is also live —
    denial here is at the earlier, unconditional handler-scope gate."""
    peer, kp_b = peer_b
    cont_path = "system/continuation/suspended/wire-at4"
    _install_administrative_continuation(peer, cont_path)

    kp_a = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19094, kp_a)
    try:
        parent_hash = conn.capability["content_hash"]
        zero_cap, zero_sig, a_id = _self_issued_cap(kp_a, parent_hash, grants=[])
        bundle = [
            zero_cap.to_dict(), zero_sig.to_dict(), a_id.to_dict(),
            conn.capability, *(conn.capability_chain or []),
        ]

        resp = await conn.execute(
            uri=f"entity://{peer.peer_id}/system/continuation",
            operation="advance",
            params={"result": {"value": 1}},
            resource={"targets": [cont_path]},
            capability_override=zero_cap.to_dict(),
            capability_chain_override=bundle,
        )
        assert resp.status == 403, (
            f"expected fail-closed 403 for zero-capability administrative "
            f"advance, got {resp.status}: {resp.result}"
        )
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_at2_administrative_advance_present_but_insufficient_cap_is_denied(peer_b):
    """AT-2's real-wire companion — a PRESENT capability that grants
    `advance` on `system/continuation` in general (so the dispatcher's
    handler-scope check passes) but not on THIS path, sent with no
    `resource.targets` at all (so the dispatcher's resource-scope check
    doesn't run either) — isolates the continuation handler's own
    defense-in-depth `check_caller_permission` as the sole remaining gate,
    and proves it still denies a present-but-insufficient cap. This is the
    scenario the handler-level `{}`-trusted branch does NOT cover (that
    branch only trusts an ABSENT cap, never a present insufficient one)."""
    peer, kp_b = peer_b
    cont_path = "system/continuation/suspended/wire-at2"
    _install_administrative_continuation(peer, cont_path)

    kp_a = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19094, kp_a)
    try:
        parent_hash = conn.capability["content_hash"]
        # Grants `advance` on `system/continuation` broadly, but scoped to a
        # DIFFERENT resource — present, but insufficient for this path.
        narrow_cap, narrow_sig, a_id = _self_issued_cap(
            kp_a, parent_hash,
            grants=[{
                "handlers": {"include": ["system/continuation"]},
                "resources": {"include": ["system/continuation/suspended/some-other-path"]},
                "operations": {"include": ["advance"]},
            }],
        )
        bundle = [
            narrow_cap.to_dict(), narrow_sig.to_dict(), a_id.to_dict(),
            conn.capability, *(conn.capability_chain or []),
        ]

        resp = await conn.execute(
            uri=f"entity://{peer.peer_id}/system/continuation",
            operation="advance",
            # No `resource=` — relies on params.continuation_path, which
            # skips the dispatcher's resource-target check entirely and
            # isolates the handler's own path-cap gate.
            params={"continuation_path": cont_path, "result": {"value": 1}},
            capability_override=narrow_cap.to_dict(),
            capability_chain_override=bundle,
        )
        assert resp.status == 403, (
            f"a present-but-insufficient administrative capability must "
            f"still be denied at the continuation path, got {resp.status}: "
            f"{resp.result}"
        )
    finally:
        conn.close()
        await conn.wait_closed()
