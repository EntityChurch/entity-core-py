"""§3.10 marker path injection — wire-supplied coordinates must not escape the sink.

Python's answer to entity-core-go's cross-impl probe
(`security.marker_path_injection_contained`, arch ruling 25; report
`entity-core-go/docs/validation/reports/2026-07-16-marker-path-injection-cohort.md`).
Go found a tree node literally named `..` in our marker tree and Rust's, put there
by an unauthorized peer, and confirmed it with a second tool before reporting.

The §3.10.3 `rejected` marker path interpolates two values the SENDER chooses:

    system/runtime/chain-errors/rejected/{chain_id}/{step_index}/{reason}/{marker_hash}
                                         └ bounds.chain_id ┘  └ request_id ┘

and the sender is *unauthorized by construction* — the rejected marker is bound
BECAUSE the cap check failed, so reaching the binding site requires no capability
at all. That is what makes this more than an input-validation nit.

Two properties are asserted, and the first is the one that matters:

1. **Containment on the CLEANED path, not the literal one.** `sink/{X}/..` is
   inside the sink by string prefix while naming somewhere else. Our
   `clean_path` rejects a *leading* `../`; these values land in the *middle*,
   where a normalizer RESOLVES the `..` and walks the marker out of the sink.
   Our `EntityTree.normalize_uri` happens not to resolve interior `..` today, so
   the live consequence is tree pollution and coordinate forking rather than a
   write-anywhere primitive — but that is one normalizer away, and normalizing
   after concatenation is a rule this ecosystem's own guidance directs.

2. **Safe values pass through byte-identical.** This is the no-de-convergence
   evidence: sanitizing changes no conformant coordinate, so it cannot move a
   seat's markers and does not wait on the `{step_index}` spelling ruling.

Unsafe values are HASHED, not dropped and not collapsed: markers are
observational, so dropping loses the event and collapsing to a constant merges
distinct failures onto one coordinate. The original survives in the marker body,
which is where an untrusted value is safe to carry.
"""

from __future__ import annotations

import posixpath

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.path import is_safe_path_segment
from entity_handlers.continuation import (
    CHAIN_ID_UNSPECIFIED,
    STEP_INDEX_UNSPECIFIED,
    _bind_lost_marker,
    bind_dispatcher_rejected_marker,
)

SINK = "system/runtime/chain-errors"

# The exact values Go's probe puts on the wire.
HOSTILE = "../../../../authority/keys"

# Other shapes a hostile (or merely broken) sender can choose. Each must stay
# in the sink; each must land somewhere DISTINCT (no collapsing).
HOSTILE_CASES = [
    pytest.param("../../../../authority/keys", id="interior-dotdot-escape"),
    pytest.param("..", id="bare-dotdot"),
    pytest.param(".", id="bare-dot"),
    pytest.param("a/b", id="embedded-slash"),
    pytest.param("", id="empty"),
    pytest.param("x\x00y", id="nul-byte"),
    pytest.param("x\ny", id="newline"),
]


def _pathway(peer_id: str) -> EmitPathway:
    return EmitPathway(ContentStore(), EntityTree(peer_id))


def _ctx(emit_pathway: EmitPathway, peer_id: str, chain_id, request_id):
    permissive = create_full_access_grant()
    ctx = HandlerContext(
        local_peer_id=peer_id,
        remote_peer_id="remote-peer-id",
        handler_grant=permissive,
        caller_capability=permissive,
        emit_pathway=emit_pathway,
        chain_id=chain_id,
        request_id=request_id,
    )
    return ctx


def _bound_uris(emit_pathway: EmitPathway) -> list[str]:
    return emit_pathway.entity_tree.list_prefix(
        emit_pathway.entity_tree.normalize_uri(SINK)
    )


def _assert_contained(
    emit_pathway: EmitPathway, uris: list[str], supplied: str, *, depth: int = 4
) -> None:
    """Every bound marker must still be in the sink AFTER normalization, and
    occupy exactly the §3.10.1 coordinate shape.

    ``depth`` is the number of segments the scheme puts under the ``{kind}``
    node: {chain_id}/{step_index}/{reason}/{marker_hash}. Asserting it pins the
    no-forking property — a value carrying a ``/`` would silently add a level,
    which is contained but still wrong (it is the same forking that made marker
    walks need impl-specific depth caps).
    """
    sink_abs = emit_pathway.entity_tree.normalize_uri(SINK)
    assert uris, (
        f"no marker bound for supplied value {supplied!r}; the containment "
        f"property is untestable if nothing binds (see the probe's WARN-not-FAIL "
        f"grading for the no-marker case)"
    )
    for uri in uris:
        tail = uri.split(f"{SINK}/", 1)[1].split("/")
        # tail[0] is {kind}; the rest is the coordinate.
        assert len(tail) == depth + 1, (
            f"marker coordinate forked: supplied {supplied!r} produced "
            f"{len(tail) - 1} segments under {tail[0]!r}, want {depth} "
            f"({'/'.join(tail[1:])}). A value containing '/' must occupy ONE "
            f"segment — sanitize it rather than letting it add a tree level."
        )
        for seg in tail[1:]:
            assert is_safe_path_segment(seg), (
                f"unsafe segment {seg!r} on a bound marker path (supplied "
                f"{supplied!r}): {uri}. A segment is safe when non-empty, "
                f"slash-free, neither '.' nor '..', and control-character-free."
            )
    for uri in uris:
        resolved = posixpath.normpath(uri)
        assert resolved.startswith(sink_abs + "/") or resolved == sink_abs, (
            f"MARKER PATH INJECTION: a wire-supplied coordinate escaped the "
            f"chain-errors sink.\n"
            f"  supplied:    {supplied!r}\n"
            f"  bound at:    {uri}\n"
            f"  resolves to: {resolved}\n"
            f"A value the SENDER chooses reached the path. The rejected marker "
            f"is bound because the sender's cap check FAILED, so an unauthorized "
            f"caller reaches this site by construction — no capability required "
            f"to choose where the entity lands. Sanitize at construction: a "
            f"segment is safe when non-empty, slash-free, neither '.' nor '..', "
            f"and control-character-free."
        )
        # The literal `..` node is the shape Go saw with probe-peer on our tree.
        assert "/.." not in uri and "/." not in uri.rstrip("/"), (
            f"marker path contains a relative-navigation segment: {uri} "
            f"(supplied {supplied!r}). Contained today only because "
            f"EntityTree.normalize_uri does not resolve interior '..' — this is "
            f"a write-anywhere primitive the moment any normalizer does."
        )


@pytest.mark.parametrize("supplied", HOSTILE_CASES)
def test_rejected_marker_chain_id_cannot_escape_sink(supplied: str) -> None:
    """§3.10.3 receiver-side bind — `bounds.chain_id` is wire-supplied.

    This is the coordinate Go's probe drives, via an over-scope EXECUTE that is
    guaranteed a 403.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    bind_dispatcher_rejected_marker(
        emit_pathway,
        kp.peer_id,
        chain_id=supplied,
        request_id="req-safe",
        code="capability_denied",
        status=403,
        requesting_peer_id="attacker-peer",
        attempted_uri="system/capability",
    )

    _assert_contained(emit_pathway, _bound_uris(emit_pathway), supplied)


@pytest.mark.parametrize("supplied", HOSTILE_CASES)
def test_rejected_marker_step_index_cannot_escape_sink(supplied: str) -> None:
    """§3.10.3 receiver-side bind — `request_id` is wire-supplied too."""
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    bind_dispatcher_rejected_marker(
        emit_pathway,
        kp.peer_id,
        chain_id="chain-safe",
        request_id=supplied,
        code="capability_denied",
        status=403,
        requesting_peer_id="attacker-peer",
        attempted_uri="system/capability",
    )

    _assert_contained(emit_pathway, _bound_uris(emit_pathway), supplied)


@pytest.mark.parametrize("supplied", HOSTILE_CASES)
def test_lost_marker_coordinates_cannot_escape_sink(supplied: str) -> None:
    """Sender-side `lost` bind — not reachable by Go's probe, but Go had the
    same defect at all three of its binding sites and told us to check all of
    ours. Our subscription engine reaches this one with a chain_id taken
    straight from wire-supplied notification bounds.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)
    ctx = _ctx(emit_pathway, kp.peer_id, chain_id=supplied, request_id=supplied)

    _bind_lost_marker(
        ctx,
        code="capability_denied",
        status=403,
        request_id=supplied,
        target_uri="system/tree",
    )

    _assert_contained(emit_pathway, _bound_uris(emit_pathway), supplied)


def test_reason_from_remote_handler_cannot_escape_sink() -> None:
    """`result.data.code` becomes `{reason}` and is remote-controlled — a remote
    handler picks its own error code. Go sanitizes it; not probed cross-impl.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)
    ctx = _ctx(emit_pathway, kp.peer_id, chain_id="chain-safe", request_id="req-safe")

    _bind_lost_marker(
        ctx,
        code=HOSTILE,
        status=502,
        request_id="req-safe",
        target_uri="system/tree",
    )

    _assert_contained(emit_pathway, _bound_uris(emit_pathway), HOSTILE)


def test_safe_coordinates_pass_through_byte_identical() -> None:
    """The no-de-convergence evidence: sanitizing moves no conformant marker.

    If this fails, the fix is not safe to land ahead of the `{step_index}`
    spelling ruling, because it would be silently re-spelling live coordinates.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    bind_dispatcher_rejected_marker(
        emit_pathway,
        kp.peer_id,
        chain_id="network-maintain-8e8a9dd88e80147a",
        request_id="7f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b",
        code="capability_denied",
        status=403,
        requesting_peer_id="peer",
        attempted_uri="system/capability",
    )

    uris = _bound_uris(emit_pathway)
    assert len(uris) == 1
    uri = uris[0]
    assert "/network-maintain-8e8a9dd88e80147a/" in uri, (
        f"a conformant chain_id was rewritten: {uri}. Safe values MUST pass "
        f"through byte-identical or the fix de-converges the cohort."
    )
    assert "/7f3a1c2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b/" in uri, (
        f"a conformant step_index (a plain request-id UUID) was rewritten: "
        f"{uri}. Safe values MUST pass through byte-identical."
    )


def test_distinct_unsafe_values_collapse_to_one_node_but_keep_both_events() -> None:
    """Collapse, do NOT hash — and lose no occurrence (arch ruling 13 as amended,
    ROUTING-2026-07-17 §1).

    This vector previously asserted the opposite (hash, stay distinct). The
    distinctness it was protecting was never at risk: §3.4/§3.10.1 puts each
    occurrence at its own ``{marker_hash}`` TERMINAL segment, so two hostile
    values sharing one quarantine node still produce two distinct markers —
    different bodies, different hashes. The property lives one segment down
    from where we were defending it.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    for supplied in ("../../../../authority/keys", "../../../../authority/certs"):
        bind_dispatcher_rejected_marker(
            emit_pathway,
            kp.peer_id,
            chain_id=supplied,
            request_id="req-safe",
            code="capability_denied",
            status=403,
            requesting_peer_id="attacker-peer",
            attempted_uri="system/capability",
        )

    uris = _bound_uris(emit_pathway)
    chain_segments = {
        uri.split(f"{SINK}/rejected/")[1].split("/")[0]
        for uri in uris
        if f"{SINK}/rejected/" in uri
    }
    assert chain_segments == {CHAIN_ID_UNSPECIFIED}, (
        f"hostile chain_ids landed at {chain_segments} — each MUST collapse to "
        f"the fixed sentinel {CHAIN_ID_UNSPECIFIED!r}. A per-value coordinate "
        f"(hashed or raw) lets an attacker mint unbounded path nodes."
    )
    assert len(set(uris)) == 2, (
        f"two distinct hostile values produced {len(set(uris))} marker(s) — "
        f"collapsing the chain_id segment MUST NOT merge the occurrences. "
        f"Distinctness is the terminal {{marker_hash}}'s job."
    )


def test_sanitize_does_not_let_an_attacker_mint_nodes() -> None:
    """The reason collapse beats hash, as an invariant rather than a comment.

    Hashing bounded the tree only by GC: each distinct hostile value earned its
    own node, which re-opened the pollution vector the injection fix had just
    closed, one layer up. Neither implementing seat found this — it was arch's
    decisive third reason for amending ruling 13, and it is the one that would
    have changed our answer on its own. So it gets a vector, not a docstring.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    for i in range(1000):
        bind_dispatcher_rejected_marker(
            emit_pathway,
            kp.peer_id,
            chain_id=f"../../../../authority/keys/{i}",
            request_id="req-safe",
            code="capability_denied",
            status=403,
            requesting_peer_id="attacker-peer",
            attempted_uri="system/capability",
        )

    chain_segments = {
        uri.split(f"{SINK}/rejected/")[1].split("/")[0]
        for uri in _bound_uris(emit_pathway)
    }
    assert chain_segments == {CHAIN_ID_UNSPECIFIED}, (
        f"1000 distinct hostile values minted {len(chain_segments)} path nodes "
        f"— an attacker MUST NOT be able to grow the tree by varying the value. "
        f"Exactly one quarantine node, bounded by the sentinel."
    )


def test_unsafe_original_is_preserved_in_the_marker_body() -> None:
    """The body is the record; the path is an index (ROUTING-2026-07-17 §2).

    Collapsing to a sentinel is only safe BECAUSE the body recovers the
    original. Otherwise this — the one marker whose whole purpose is to observe
    a hostile failure — would record that something hostile happened and
    nothing about what. `chain_id` is the coordinate a remote fully controls,
    and until this ruling no impl had a body field for it: the actual gap.
    """
    kp = Keypair.generate()
    emit_pathway = _pathway(kp.peer_id)

    bind_dispatcher_rejected_marker(
        emit_pathway,
        kp.peer_id,
        chain_id=HOSTILE,
        request_id="req-safe",
        code="capability_denied",
        status=403,
        requesting_peer_id="attacker-peer",
        attempted_uri="system/capability",
    )

    uris = _bound_uris(emit_pathway)
    assert len(uris) == 1
    marker = emit_pathway.content_store.get(emit_pathway.entity_tree.get(uris[0]))

    bound_segment = uris[0].split(f"{SINK}/rejected/")[1].split("/")[0]
    assert bound_segment == CHAIN_ID_UNSPECIFIED, (
        f"the hostile chain_id was bound at {bound_segment!r} rather than the "
        f"sentinel — the path MUST NOT carry a remote-controlled value."
    )
    assert marker.data["chain_id"] == HOSTILE, (
        f"the marker body's chain_id is {marker.data['chain_id']!r}, not the "
        f"original the sender supplied. The body field holds the ORIGINAL — it "
        f"is the only surviving evidence of what the attacker sent, and the "
        f"sentinel on the path is a one-way loss without it."
    )
    assert marker.data["step_index"] == "req-safe", (
        "a safe step_index must still round-trip into the body verbatim"
    )
