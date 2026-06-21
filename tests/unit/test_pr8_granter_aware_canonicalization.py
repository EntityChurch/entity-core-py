"""V7 §PR-8 — granter-aware capability RESOURCE-pattern canonicalization.

Pins the fix for cohort validator vector V2(a)
(`captok_form_dispatch_minted_pl_presented_xpeer`): a capability minted
**peer-local** by granter A (a bare `*` resource) and presented **cross-peer**
at verifier B MUST NOT be admitted over B's surface. The bare wildcard names
the *granter's* namespace, so it canonicalizes to `/A/*`, which does not match
a request target under `/B/...`.

The bug was latent because every impl canonicalized grant patterns against the
verifier's `local_peer_id` throughout — byte-identical to the granter for the
self-issued case (the same-peer-dominant test path). The frame only diverges
for a foreign-granter cap, which is exactly what V2(a) exercises.

See PROPOSAL-V7-V7.73-CLOSEOUT §3.2.1 + §PR-8.
"""

from __future__ import annotations

from typing import Any

from entity_core.capability.checking import (
    canonicalize,
    check_path_permission,
    check_resource_scope,
    granter_frame_peer_id,
    matches_pattern,
)
from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import create_identity_entity

# Two distinct peers: A is the (foreign) granter, B is the verifier.
KP_A = Keypair.from_seed(b"pr8-granter-a" + b"\x00" * 19)
KP_B = Keypair.from_seed(b"pr8-verifier-b" + b"\x00" * 18)
A_PEER = KP_A.peer_id
B_PEER = KP_B.peer_id
A_ID = create_identity_entity(KP_A).to_dict()
A_HASH = A_ID["content_hash"]


def _bare_wildcard_cap(granter_hash: bytes) -> dict[str, Any]:
    """A peer-local cap: bare `*` resources, all handlers/ops, granted by
    `granter_hash`. The bare `*` is the load-bearing PR-8 surface."""
    return {
        "granter": granter_hash,
        "grants": [
            {
                "handlers": {"include": ["*"]},
                "operations": {"include": ["*"]},
                "resources": {"include": ["*"]},
            }
        ],
    }


def _resolver(mapping: dict[bytes, dict[str, Any]]):
    def _resolve(h: bytes) -> dict[str, Any] | None:
        ent = mapping.get(h)
        return {"data": ent["data"]} if ent is not None else None

    return _resolve


class TestGranterFramePeerId:
    """granter_frame_peer_id resolution + safe fallbacks."""

    def test_resolves_granter_peer_id_from_identity(self):
        frame = granter_frame_peer_id(
            _bare_wildcard_cap(A_HASH), B_PEER, _resolver({A_HASH: A_ID})
        )
        assert frame == A_PEER
        assert frame != B_PEER

    def test_falls_back_to_local_when_granter_unresolvable(self):
        # Granter present but identity not in the resolver -> self-issued frame.
        frame = granter_frame_peer_id(
            _bare_wildcard_cap(A_HASH), B_PEER, _resolver({})
        )
        assert frame == B_PEER

    def test_falls_back_to_local_when_granter_absent(self):
        frame = granter_frame_peer_id({"grants": []}, B_PEER, _resolver({}))
        assert frame == B_PEER

    def test_falls_back_to_local_for_multisig_granter(self):
        # Multi-sig granter is a map, not a hash. Multi-sig caps are root-only
        # and root MUST be local, so the frame collapses to local by construction.
        cap = _bare_wildcard_cap(A_HASH)
        cap["granter"] = {"signers": [A_HASH], "threshold": 1}
        frame = granter_frame_peer_id(cap, B_PEER, _resolver({A_HASH: A_ID}))
        assert frame == B_PEER


class TestResourceScopeGranterFrame:
    """check_resource_scope — the dispatch-level V2(a) surface."""

    def test_foreign_granter_peer_local_cap_denied_cross_peer(self):
        """V2(a): A's bare-`*` cap MUST NOT cover a target under B."""
        cap = _bare_wildcard_cap(A_HASH)
        target = f"/{B_PEER}/foo"  # request target on the verifier's surface
        # FIXED: framed on the granter (A), `*` -> /A/* -> does not match /B/foo.
        assert not check_resource_scope(
            cap, "system/tree", "get", [target], None, B_PEER,
            granter_peer_id=A_PEER,
        )

    def test_latent_bug_shape_when_framed_on_verifier(self):
        """Documents the pre-fix shape: framing the grant on the verifier
        wrongly admits the peer-local cap (this is precisely what §PR-8
        forbids and what passing granter_peer_id=A_PEER corrects)."""
        cap = _bare_wildcard_cap(A_HASH)
        target = f"/{B_PEER}/foo"
        assert check_resource_scope(
            cap, "system/tree", "get", [target], None, B_PEER,
            granter_peer_id=B_PEER,  # wrong frame == old default
        )

    def test_self_issued_cap_still_admitted(self):
        """Self-issued (granter == verifier) is unaffected by the fix."""
        cap = _bare_wildcard_cap(A_HASH)  # granter hash irrelevant here
        target = f"/{B_PEER}/foo"
        assert check_resource_scope(
            cap, "system/tree", "get", [target], None, B_PEER,
            granter_peer_id=B_PEER,
        )

    def test_explicit_cross_peer_grant_still_works(self):
        """Legitimate cross-peer authority is `/*/*`, which matches any peer's
        surface regardless of the granter frame."""
        cap = {
            "granter": A_HASH,
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "operations": {"include": ["*"]},
                    "resources": {"include": ["/*/*"]},
                }
            ],
        }
        target = f"/{B_PEER}/foo"
        assert check_resource_scope(
            cap, "system/tree", "get", [target], None, B_PEER,
            granter_peer_id=A_PEER,
        )

    def test_target_in_granter_namespace_admitted(self):
        """A's bare-`*` cap DOES cover a target under A's own namespace."""
        cap = _bare_wildcard_cap(A_HASH)
        target = f"/{A_PEER}/foo"
        assert check_resource_scope(
            cap, "system/tree", "get", [target], None, B_PEER,
            granter_peer_id=A_PEER,
        )


class TestPathPermissionGranterFrame:
    """check_path_permission — handler-level defense-in-depth surface."""

    def test_foreign_granter_peer_local_cap_denied_cross_peer(self):
        cap = _bare_wildcard_cap(A_HASH)
        path = f"/{B_PEER}/foo"
        assert not check_path_permission(
            cap, "get", path, B_PEER, granter_peer_id=A_PEER,
        )

    def test_self_issued_cap_admitted(self):
        cap = _bare_wildcard_cap(A_HASH)
        path = f"/{B_PEER}/foo"
        assert check_path_permission(
            cap, "get", path, B_PEER, granter_peer_id=B_PEER,
        )

    def test_granter_namespace_path_admitted(self):
        cap = _bare_wildcard_cap(A_HASH)
        path = f"/{A_PEER}/foo"
        assert check_path_permission(
            cap, "get", path, B_PEER, granter_peer_id=A_PEER,
        )


class TestCanonicalizeFrameInvariant:
    """The pure transform is correct; PR-8 is about *which frame* callers pass."""

    def test_bare_wildcard_is_peer_local_to_its_frame(self):
        assert canonicalize("*", A_PEER) == f"/{A_PEER}/*"
        assert matches_pattern(canonicalize("*", A_PEER), f"/{A_PEER}/x")
        assert not matches_pattern(canonicalize("*", A_PEER), f"/{B_PEER}/x")
