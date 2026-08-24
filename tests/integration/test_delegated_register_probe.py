"""§5.5a cap-resource canonicalization on a self-delegated child cap — the
granter frame, probed on the axis that decides it.

**History, because the correction is the point of this file.** core-go asked the
cohort: *can a delegated child cap `register` in your tree?* They answered "no,
under five scope variants" and said a sibling's yes would make it a go defect.
py answered yes. go went looking for their bug and found the spec instead:
`ENTITY-CORE-PROTOCOL` §5.5a already answers it, their 403 was spec-required, and
the finding was retracted.

**py's yes was not an answer to go's question.** All three of our rows carried
`/*/*` alongside `*`, so every one of them was go's *fourth* row — the absolute
form — while go's refused rows were peer-relative. Two probes, different axes,
compared as if they were the same experiment.

**What §5.5a requires.** Cap resource patterns canonicalize against the
**granter's** peer_id, not the verifier's. A bare `*` on a cap granted by the
client means `/{client}/*` and covers nothing in the responder's namespace; cross-
peer authority MUST be written absolutely (`/*/...`, `/{peer}/...`). Canonicalizing
against the verifier instead leaves the bug **latent** — the two frames are
byte-identical for same-peer caps, so only a foreign-granter cap exposes it. All
three impls shipped that bug once and were fixed away from it (the v7.73 V2(a)
substrate-FAIL).

**py's answer, with form as the axis: conformant, and identical to go.**
Peer-relative refused, absolute accepted. The `[*]` and `[/*/*]` rows below are
the two that matter; together they are the shape neither impl had a vector for.

**The method note both repos are keeping.** A control row and a mutation test ran
against the original probe and neither caught the flaw, because both varied
*scope* while holding *form* fixed. A control varies the dimension you suspect; it
cannot catch the one you never thought to vary. Only reading the normative text
did. That is why resource form is the outer parameter here and scope is the inner
one.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity

_PORT = 19311

# The absolute cross-peer form §5.5a requires for a cap that is meant to authorize
# action in another peer's namespace. Every row that is *not* about the resource
# frame uses this, so its result is attributable to the dimension it varies.
_CROSS_PEER = ["/*/*"]


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _mint_child(
    *,
    delegator_kp: Keypair,
    parent_hash: bytes,
    grants: list[dict],
) -> tuple[dict, dict]:
    """Client-side self-attenuation: the parent's grantee mints a child under it
    and signs it. Grantee stays the delegator, which is the shape py's own
    `capability:delegate` produces — and, from the responder's frame, makes the
    granter a **foreign peer**. That is what puts §5.5a in play at all.

    py's `capability:delegate` is same-peer-only in v1 (§6.2 v7.63 F1) and answers
    a cross-peer caller 501, naming client-side self-attenuation as the supported
    route, so this is the only construction path there is.
    """
    identity = create_identity_entity(delegator_kp)
    identity_hash = identity.compute_hash()
    token = Entity(
        type="system/capability/token",
        data={
            "grants": grants,
            "granter": identity_hash,
            "grantee": identity_hash,
            "created_at": _now_ms(),
            "parent": parent_hash,
        },
    )
    sig = create_signature_entity(
        delegator_kp,
        target_hash=token.compute_hash(),
        signer_identity_hash=identity_hash,
    )
    return token.to_dict(), sig.to_dict()


def _register_params(pattern: str) -> dict:
    return {
        "pattern": pattern,
        "manifest": {
            "name": "probe",
            "pattern": pattern,
            "operations": {"ping": {"input_type": "system/protocol/ack"}},
        },
    }


def _register_resource(pattern: str) -> dict:
    """py's register takes its pattern from ``resource.targets[0]``, not
    ``params.data.path`` — and the V7 dispatch check reads `grant.resources`
    against it **before** the handler runs. Sending it is what puts the delegated
    cap in front of the check this file is about."""
    return {"targets": [f"system/handler/{pattern}"]}


@pytest.fixture
async def peer():
    p = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await p.start("127.0.0.1", _PORT)
    try:
        yield p
    finally:
        await p.stop()


async def _connect(peer) -> Connection:
    return await Connection.connect("127.0.0.1", _PORT, Keypair.generate())


async def _register_under_child(peer, conn, *, label, grants) -> tuple[int, str]:
    """Mint a self-delegated child with `grants`, register under it, return
    (status, error_code)."""
    child, child_sig = _mint_child(
        delegator_kp=conn.keypair,
        parent_hash=conn.capability["content_hash"],
        grants=grants,
    )
    chain = [child_sig, conn.capability, *(conn.capability_chain or [])]
    resp = await asyncio.wait_for(
        conn.execute(
            uri=f"entity://{peer.keypair.peer_id}/system/handler",
            operation="register",
            params=_register_params(f"app/probe/{label}"),
            resource=_register_resource(f"app/probe/{label}"),
            capability_override=child,
            capability_chain_override=chain,
        ),
        timeout=5.0,
    )
    code = ""
    if isinstance(resp.result, dict):
        code = (resp.result.get("data") or {}).get("code", "")
    return resp.status, code


def _grants(resources: list[str], *, handlers=("*",), operations=("*",)) -> list[dict]:
    return [{
        "handlers": {"include": list(handlers)},
        "resources": {"include": resources},
        "operations": {"include": list(operations)},
        "peers": {"include": ["*"]},
    }]


# ---------------------------------------------------------------------------
# The axis that decides it: resource FORM, scope held wide open
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "label,resources",
    [
        ("bare-star", ["*"]),
        ("relative-path", ["app/*"]),
    ],
)
async def test_peer_relative_resources_on_a_foreign_granted_cap_are_refused(
    peer, label, resources,
):
    """§5.5a: *"presenting such a cap cross-peer MUST fail at dispatch with 403
    `capability_denied`."*

    The grants are otherwise maximal — `handlers: ["*"]`, `operations: ["*"]`,
    `peers: ["*"]`. Only the resource **form** is peer-relative, and under §5.5a
    that alone reduces the cap to the *client's* namespace, where
    `/{responder}/system/handler/...` does not live.

    This is the security shape stated plainly: if this returned 200, a cap minted
    by peer A carrying a bare `*` would be treated by peer B as covering B's
    entire namespace — a cross-peer authority escalation, invisible in same-peer
    testing because both canonicalizations agree there.
    """
    conn = await _connect(peer)
    try:
        status, code = await _register_under_child(
            peer, conn, label=label, grants=_grants(resources),
        )
        assert status == 403, f"{resources} must not authorize the responder's namespace"
        assert code == "capability_denied"
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "label,resources",
    [
        ("cross-peer-wildcard", ["/*/*"]),
        ("mixed-forms", ["*", "/*/*"]),
    ],
)
async def test_absolute_resources_on_a_foreign_granted_cap_register(
    peer, label, resources,
):
    """The other half of the same rule, and the half that makes the rows above
    mean something: in the **absolute** form §5.5a requires for cross-peer
    authority, the identical delegation registers.

    Same machinery, same handler, same operation, same scope — only the form
    changes. Without this row a blanket 403 above would be indistinguishable from
    "py refuses delegated caps outright", which is exactly the wrong conclusion go
    drew from their own probe and retracted.

    `mixed-forms` is the row our first probe actually ran while reporting it as
    the peer-relative case.
    """
    conn = await _connect(peer)
    try:
        status, _ = await _register_under_child(
            peer, conn, label=label, grants=_grants(resources),
        )
        assert status == 200
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_operation_scope_is_irrelevant_when_the_resource_frame_excludes(peer):
    """go's row 5 — a literal `register` operation scope, which they built to
    falsify an F40 id-scope hypothesis. Under §5.5a the operation scope never gets
    consulted: the resource frame has already excluded the target. Same 403,
    for a reason that has nothing to do with operations."""
    conn = await _connect(peer)
    try:
        status, code = await _register_under_child(
            peer, conn, label="literal-register-op",
            grants=_grants(["*"], handlers=("system/handler",), operations=("register",)),
        )
        assert status == 403
        assert code == "capability_denied"
    finally:
        conn.close()
        await conn.wait_closed()


# ---------------------------------------------------------------------------
# Controls — each varies exactly one dimension, with resource form held at the
# cross-peer form so no result below is explicable by §5.5a instead.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_control_undelegated_connection_cap_registers(peer):
    """The connection cap, undelegated. Without this a 403 anywhere above could be
    the handler, the pattern, or the transport."""
    conn = await _connect(peer)
    try:
        resp = await asyncio.wait_for(
            conn.execute(
                uri=f"entity://{peer.keypair.peer_id}/system/handler",
                operation="register",
                params=_register_params("app/probe/control"),
                resource=_register_resource("app/probe/control"),
            ),
            timeout=5.0,
        )
        assert resp.status == 200, resp.result
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_control_handler_scope_is_enforced_in_the_cross_peer_form(peer):
    """Handler scope narrowed off `system/handler`, resources in the cross-peer
    form → 403.

    The first version of this control used peer-relative `app/*` resources, so its
    403 was fully explained by §5.5a and said nothing whatever about handler
    scope — an unattributable control masquerading as an attributable one. Holding
    the form at `/*/*` is what makes the handler scope the only thing varying.
    """
    conn = await _connect(peer)
    try:
        status, code = await _register_under_child(
            peer, conn, label="narrow-handler",
            grants=_grants(_CROSS_PEER, handlers=("system/tree",), operations=("get",)),
        )
        assert status == 403
        assert code == "capability_denied"
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_control_child_with_unreachable_parent_is_refused(peer):
    """Cross-peer resource form, maximal scope, but the parent link points at a
    hash that is not the connection cap → refused. Isolates the *chain*: without
    it, the accepting rows would only be telling us the peer ignores `parent`."""
    conn = await _connect(peer)
    try:
        child, child_sig = _mint_child(
            delegator_kp=conn.keypair,
            parent_hash=b"\x00" + b"\xab" * 32,
            grants=_grants(_CROSS_PEER),
        )
        chain = [child_sig, conn.capability, *(conn.capability_chain or [])]
        resp = await asyncio.wait_for(
            conn.execute(
                uri=f"entity://{peer.keypair.peer_id}/system/handler",
                operation="register",
                params=_register_params("app/probe/orphan"),
                resource=_register_resource("app/probe/orphan"),
                capability_override=child,
                capability_chain_override=chain,
            ),
            timeout=5.0,
        )
        assert resp.status in (401, 403), resp.result
    finally:
        conn.close()
        await conn.wait_closed()
