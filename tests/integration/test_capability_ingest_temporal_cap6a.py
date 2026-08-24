"""CAP-6a INGEST — a received token with an unrepresentable temporal field.

`GUIDE-CAPABILITIES` §6.2 CAP-6a (0.8.1; rust CAP-6b): a **received** token whose
`expires_at`, `not_before`, **or** `created_at` does not fit `uint64` — a bignum
above 2^64, a negative, out of range — is *malformed*, and MUST be refused via
the §5.2 `capability_denied` disposition. Not collapsed to "absent" (which for
`expires_at` means *never expires*), and not dropped silently at the decode
layer.

**Python is the implementation where this fails quietly.** In Go and Rust the
CBOR decode into a `u64` fails and the token never reaches the comparison. Here
`cbor2` hands back an arbitrary-precision `int`, `2**64 + 1000 < now` evaluates
to `False`, and the token sails through the same expiry check that would catch
an ordinary stale one. The value is not rejected and not truncated — it is
compared, correctly, and found to be in the future forever.

The matrix below is the one `entity-core-go`'s `validate-peer` probe drives
(`ingest_rejects_unrepresentable_expiry`): three fields × two shapes, plus the
**teeth control** — the same construction carrying a normal expiry, which MUST
be honored. Without the control a refusal proves nothing: a re-signed,
re-hashed cap that any peer would reject for unrelated reasons would score six
green refusals.
"""

from __future__ import annotations

import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_authenticated_request,
    create_identity_entity,
    create_signature_entity,
    verify_request_integrity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.messages import Execute

from entity_handlers.capability import (
    CAPABILITY_HANDLER_PATTERN,
    capability_handler,
)

UINT64_MAX = 2**64 - 1

#: The two shapes the probe sends, per field. `over` is the exact shape our own
#: pre-CAP-6 mint used to emit; `under` is the one where "treat as absent" is
#: not merely lossy but backwards — a negative `not_before` means *already
#: valid*, and a negative `expires_at` means *already expired*, so collapsing
#: either to absence grants more authority than the token asks for.
HOSTILE_SHAPES = {
    "over": UINT64_MAX + 1000,
    "under": -1,
}

TEMPORAL_FIELDS = ("expires_at", "not_before", "created_at")


def _full_access_cap() -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*", "/*/*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
        }]
    }


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


async def _mint(peer) -> tuple[dict, list[dict]]:
    """Mint a peer-rooted cap for the peer's own key; return (cap, chain)."""
    caller_identity = create_identity_entity(peer.keypair)
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant=_full_access_cap(),
        caller_capability=_full_access_cap(),
        emit_pathway=peer.emit_pathway,
        keypair=peer.keypair,
        included={},
        author_identity_hash=caller_identity.compute_hash(),
        remote_identity_hash=caller_identity.compute_hash(),
    )
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["app/*"]},
            "operations": {"include": ["get"]},
        }]}},
        ctx,
    )
    assert mint["status"] == 200, mint
    cap_hash = mint["result"]["data"]["token"]
    cap_dict = mint["envelope_included"][cap_hash]
    chain: list[dict] = []
    for h, ent in mint["envelope_included"].items():
        if h == cap_hash:
            continue
        chain.append(ent)
        peer.content_store.put(Entity.from_dict(ent))
    peer.content_store.put(Entity.from_dict(cap_dict))
    return cap_dict, chain


def _retemporal(peer, cap_dict: dict, chain: list[dict], field: str, value: object):
    """Rebuild the cap with ``field = value`` and a valid granter signature.

    Everything else — granter, grantee, grants, parent link — is carried
    verbatim, and the peer (which is the granter) re-signs the new hash. That
    is what makes a refusal attributable to the mutated field: the token is
    structurally valid and cryptographically sound, and differs from an honored
    one in exactly one value.
    """
    data = dict(cap_dict["data"])
    data[field] = value
    cap_entity = Entity(type=cap_dict["type"], data=data)
    new_hash = cap_entity.compute_hash()
    new_cap = cap_entity.to_dict()
    new_cap["content_hash"] = new_hash

    old_hash = cap_dict["content_hash"]
    new_chain = [
        e for e in chain
        if not (e.get("type") == "system/signature"
                and e.get("data", {}).get("target") == old_hash)
    ]
    granter_identity = create_identity_entity(peer.keypair)
    new_chain.append(
        create_signature_entity(
            peer.keypair, new_hash, granter_identity.compute_hash(),
        ).to_dict()
    )
    peer.content_store.put(Entity.from_dict(new_cap))
    return new_cap, new_chain


def _present(peer, cap: dict, chain: list[dict]):
    """Present the cap on an authenticated EXECUTE and run §5.2 verification."""
    execute = Execute.create(
        uri=f"entity://{peer.keypair.peer_id}/app/anything",
        operation="get",
    )
    auth = create_authenticated_request(
        keypair=peer.keypair, execute=execute,
        capability_dict=cap, capability_chain=chain,
    )
    return verify_request_integrity(auth.to_envelope(), local_peer_id=peer.peer_id)


class TestTheTeethControl:
    """Without this, every assertion below is unfalsifiable."""

    @pytest.mark.asyncio
    async def test_the_same_construction_with_a_normal_expiry_is_honored(self, peer):
        cap, chain = await _mint(peer)
        normal = int(time.time() * 1000) + 3_600_000
        cap, chain = _retemporal(peer, cap, chain, "expires_at", normal)

        result = _present(peer, cap, chain)

        assert result.valid is True, (
            f"the control must pass, or a refusal below is attributable to the "
            f"re-sign rather than to the field: {result.error}"
        )


class TestCap6aIngest:
    @pytest.mark.parametrize("field", TEMPORAL_FIELDS)
    @pytest.mark.parametrize("shape", sorted(HOSTILE_SHAPES))
    @pytest.mark.asyncio
    async def test_an_unrepresentable_temporal_field_is_refused(self, peer, field, shape):
        cap, chain = await _mint(peer)
        cap, chain = _retemporal(peer, cap, chain, field, HOSTILE_SHAPES[shape])

        result = _present(peer, cap, chain)

        assert result.valid is False, (
            f"{field}={shape} was HONORED — an undecodable temporal field "
            f"treated as absent is a never-expiring capability (CAP-6a)"
        )
        # §5.2: the refusal is the capability_denied disposition, which this
        # layer spells as the default (no error_code). A subcode here would
        # move the dispatcher off 403 — `authentication_failed` and
        # `unresolvable_grantee` both map to 401, and neither is what a
        # malformed temporal field means.
        assert result.error_code is None, result.error_code

    @pytest.mark.asyncio
    async def test_created_at_counts_even_though_nothing_compares_it(self, peer):
        """The field this repo had no reason to look at.

        Our chain walk compares `expires_at` and `not_before` and ignores
        `created_at` entirely — so an unrepresentable `created_at` was not
        "checked and passed", it was never read. CAP-6a names all three
        because a token carrying a value no conformant peer could have encoded
        is malformed whether or not *this* peer's logic depends on it: the next
        consumer's might, and two peers disagreeing about whether a token is
        well-formed is worse than either verdict.
        """
        cap, chain = await _mint(peer)
        assert "created_at" in cap["data"], "mint stopped emitting created_at"
        cap, chain = _retemporal(peer, cap, chain, "created_at", UINT64_MAX + 1000)

        assert _present(peer, cap, chain).valid is False

    @pytest.mark.asyncio
    async def test_a_representable_boundary_value_still_passes(self, peer):
        """uint64 max is representable — the check is a range, not a heuristic.

        A `not_before` of exactly `2**64 - 1` is a token that is not yet valid,
        which is a *temporal* verdict (refused as not-yet-valid), not a
        malformed one. The distinction matters because the two carry different
        meanings to the caller, and because a check that rejected the boundary
        would be rejecting values a conformant peer can legitimately encode.
        """
        cap, chain = await _mint(peer)
        cap, chain = _retemporal(peer, cap, chain, "expires_at", UINT64_MAX)

        result = _present(peer, cap, chain)
        assert result.valid is True, result.error
