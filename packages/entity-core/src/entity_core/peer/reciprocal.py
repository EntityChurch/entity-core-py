"""The reciprocal reentry grant — EXTENSION-SIGNALING §6.5 (b).

On a §6.5 (b) *symmetric* establishment — one reached by meeting at a §3
rendezvous key, which is the mutual-authorization act — the **dialer** mints
a capability for the **acceptor** and sends it over the connection it just
opened. The §6.6 handshake already gives the dialer authority to originate
to the acceptor; this is the one missing mirror, and together they make the
pair symmetric. Without it the acceptor fails closed on any spontaneous
origination.

Trigger (a) — a profile-driven dial to a resolved endpoint — is asymmetric
(one party requested service) and mints nothing. The discriminator is the
rendezvous key, classified **locally** and never carried on the wire (a
field the counterpart sets is the §7.4.1 one-sided-claim failure shape);
meeting proves both peers brought the same key, so both classify
identically by construction.

The wire shape `[cross-impl]`
-----------------------------

::

    EXECUTE  uri=system/protocol/connect  operation=reentry-grant
             request_id=connect-reentry-grant  params=<the cap entity>
    included { cap, cap signature (signer = granter), granter identity }

The frame carries **no author, capability or signature of its own**. It
cannot: it arrives before any authority relationship exists that could
authorize it, and §4.4's default connection grants reach no deposit
handler, so an authorized deposit would be refused `403` by the acceptor's
own advertised grants. It self-verifies instead, through the granter
signature enclosed in the frame. It is fire-and-forget — the acceptor sends
no EXECUTE_RESPONSE and the dialer awaits none.

**This shape is matched to the two shipped impls, not derived from the
spec, and that is a finding, not a convenience.** The folded Carriage
bullet names the ratified §7a.2a in-band-params carriage and forbids both a
new frame and an intercept lane, while naming no URI, no operation and no
response-expectation — three free choices on a cross-peer seam. Both
`entity-core-rust` (`build_reentry_grant_envelope`) and `entity-core-go`
(`core/protocol/reentry_grant.go`, which matched Rust's shipped shape
deliberately) run exactly the frame above; the ruled shape has been built
by nobody. A third implementation reading only the spec diverges on all
three choices, silently — so this one matched the shipped shape to stay
runnable against the cohort, and seconds Go's routed spec issue with a
from-scratch reader's evidence rather than treating cohort agreement as
conformance.
"""

from __future__ import annotations

import logging
from typing import Any

from entity_core.capability.grant import create_capability_token
from entity_core.capability.token import Grant
from entity_core.crypto.identity import ENTITY_DATA_KEY_TYPE_TO_BYTE
from entity_core.crypto.signing import verify_for_key_type
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import Execute
from entity_core.utils.ecf import normalize_hash

logger = logging.getLogger(__name__)

#: The connect-handler operation that carries a reciprocal grant.
REENTRY_GRANT_OPERATION = "reentry-grant"

#: The fixed request_id on the grant frame. Fixed rather than sequenced
#: because the frame is fire-and-forget — nothing correlates a response.
REENTRY_GRANT_REQUEST_ID = "connect-reentry-grant"

#: The connect handler's URI (the frame's carriage target).
CONNECT_URI = "system/protocol/connect"

#: How long an acceptor waits for the grant before originating anyway —
#: and failing closed. Implementation-local (§6.5 (b) "Delivery + timing"
#: Q3 ruling: pin a floor, not a value).
RECIPROCAL_GRANT_WAIT_SECONDS: float = 2.0

#: The conformance-vector floor, named SEPARATELY from the bound above and
#: deliberately not merged with it. A vector that waits only its own
#: author's bound fails a slower-but-correct peer and calls it the peer's
#: fault; the vector MUST allow at least this long (Q3, 2026-08-05).
RECIPROCAL_GRANT_VECTOR_FLOOR: float = 2.0

CAPABILITY_TOKEN_TYPE = "system/capability/token"
SIGNATURE_TYPE = "system/signature"


class ReentryGrantError(Exception):
    """An inbound reciprocal grant was refused.

    Never a connection error: a refused grant simply leaves the acceptor
    without originating authority — the pre-adoption state, which fails
    closed.
    """


def build_reentry_grant_envelope(
    keypair: Any,
    grantee_identity: Entity,
    grants: list[Grant],
    active_hash_format: int,
) -> Envelope:
    """Mint the reciprocal capability and wrap it in its carriage frame.

    ``grantee_identity`` MUST be the acceptor's identity entity **as the
    acceptor authored it** — the grantee is its *content hash*, what the
    core verify contract resolves and compares to the author, and never the
    §3.2 rendezvous `system/peer-id`. Conflating the two mints a cap that
    fails `grantee_mismatch` at the far side (the #67 id-encoding hazard,
    one field over).

    ``grants`` is the **assembled** inbound-dialer grant for this
    counterpart (:meth:`Peer.assemble_inbound_grants`), never the flat §4.4
    floor: minting the floor while an inbound dialer receives the assembled
    set gives the establishment whose justification is symmetry asymmetric
    authority (§6.5 (b) Contents, Q2).

    ``active_hash_format`` is the connection's negotiated
    `content_hash_format` (§4.5a): every entity on a connection is authored
    under it, and a cap chain that crosses a format boundary cannot be
    walked.

    Raises:
        ReentryGrantError: if there is nothing legitimate to mint.
    """
    if not grants:
        # An empty assembly is a real outcome, not a nil-guard: the
        # advertisement filter can drop every entry on a peer that
        # registers none of what it resolves. An all-denying cap would
        # advertise authority that dispatches to nothing, so decline to
        # mint — the counterpart stays pre-adoption, which fails closed.
        raise ReentryGrantError(
            "assembled grant set is empty (nothing to authorize)"
        )

    cap_entity, granter_identity, cap_signature = create_capability_token(
        keypair, grantee_identity, grants, algorithm=active_hash_format,
    )

    execute = Execute(
        request_id=REENTRY_GRANT_REQUEST_ID,
        uri=CONNECT_URI,
        operation=REENTRY_GRANT_OPERATION,
        params=cap_entity.to_dict(),
    )
    # The acceptor's handshake `auth_included` cannot contain these — we
    # authored them — so they travel here, and the acceptor re-injects them
    # when it later originates under this cap.
    return Envelope(
        root=execute.to_entity(),
        included=[
            cap_entity.to_dict(),
            cap_signature.to_dict(),
            granter_identity.to_dict(),
        ],
    )


def is_reentry_grant(envelope: Envelope) -> bool:
    """Is this frame a reciprocal-grant carriage frame?

    Cheap enough to run on every post-handshake EXECUTE: it looks at the
    root's decoded data only when the type already matches.
    """
    root = envelope.root
    if not isinstance(root, dict) or root.get("type") != Execute.TYPE:
        return False
    data = root.get("data")
    if not isinstance(data, dict):
        return False
    return data.get("operation") == REENTRY_GRANT_OPERATION


def accept_reentry_grant(
    envelope: Envelope,
    remote_identity_hash: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate an inbound reciprocal grant; return (cap, supporting).

    ``remote_identity_hash`` is the identity hash of the peer we
    **authenticated** on this connection — not one read out of the frame. A
    grant claiming any other granter is both useless (the far side roots
    the chain at its own identity) and dishonest to store.

    The checks are exactly the legs the frame carries, and no more
    (§6.5 (b) "The mint"):

    * the cap's claimed content hash recomputes (a substituted entity would
      otherwise index under the wrong hash);
    * `granter` **is** the authenticated peer;
    * a signature entity targets the cap, its signer **is** the granter,
      and it verifies under the granter's key.

    It deliberately does **not** run the full chain walk. That walk also
    resolves the *grantee* — us — whose identity entity is absent from a
    grant the dialer authored, and it roots at the local peer, so it
    rejects every valid grant. Fail-fast here rather than letting the far
    side's walk be the only thing that ever checks it: an unverifiable
    grant authorizes nothing, so installing it only trades this named local
    drop for a `403 missing_signature` one dispatch later, at the
    cross-peer seam, where it is hardest to attribute.

    Raises:
        ReentryGrantError: with the reason. The caller logs and drops.
    """
    included = [e for e in (envelope.included or []) if isinstance(e, dict)]

    caps = [e for e in included if e.get("type") == CAPABILITY_TOKEN_TYPE]
    if not caps:
        raise ReentryGrantError("no capability token in included")
    if len(caps) > 1:
        raise ReentryGrantError("more than one capability token in included")
    cap_dict = caps[0]

    claimed_hash = normalize_hash(cap_dict.get("content_hash"))
    if not claimed_hash:
        raise ReentryGrantError("capability carries no content hash")
    cap_entity, _ = Entity.from_wire_dict(cap_dict)
    # Structural integrity: recompute the hash the entity claims, under the
    # algorithm the claimed hash itself names (§1.8 — validate, then trust).
    rebuilt = Entity(
        type=cap_entity.type,
        data=cap_entity.data,
        hash_algorithm=claimed_hash[0],
    )
    if rebuilt.compute_hash() != claimed_hash:
        raise ReentryGrantError("capability failed hash validation")

    cap_data = cap_dict.get("data")
    if not isinstance(cap_data, dict):
        raise ReentryGrantError("capability data is not a map")
    granter_hash = normalize_hash(cap_data.get("granter"))
    if not granter_hash:
        raise ReentryGrantError("capability names no single granter")
    if granter_hash != remote_identity_hash:
        raise ReentryGrantError(
            "granter is not the peer authenticated on this connection"
        )

    _verify_granter_signature(included, claimed_hash, granter_hash)

    supporting = [
        e for e in included
        if normalize_hash(e.get("content_hash")) != claimed_hash
    ]
    return cap_dict, supporting


def _verify_granter_signature(
    included: list[dict[str, Any]],
    cap_hash: bytes,
    granter_hash: bytes,
) -> None:
    """The single-sig signature leg of the §5.5 walk, run against the frame.

    Find a signature targeting the cap whose signer is the granter, resolve
    the granter identity out of the same frame, and verify. A single-sig
    root cap without it is rejected `missing_signature` at the far side's
    chain walk anyway (§5.5).
    """
    granter_identity = next(
        (
            e for e in included
            if normalize_hash(e.get("content_hash")) == granter_hash
        ),
        None,
    )
    if granter_identity is None:
        raise ReentryGrantError("granter identity entity not in included")
    identity_data = granter_identity.get("data")
    if not isinstance(identity_data, dict):
        raise ReentryGrantError("granter identity data is not a map")
    public_key = identity_data.get("public_key")
    key_type = identity_data.get("key_type", "ed25519")
    if not isinstance(public_key, (bytes, bytearray)) or not public_key:
        raise ReentryGrantError("granter identity carries no public key")
    key_type_byte = ENTITY_DATA_KEY_TYPE_TO_BYTE.get(key_type)
    if key_type_byte is None:
        raise ReentryGrantError(f"granter key_type {key_type!r} not supported")

    for entry in included:
        if entry.get("type") != SIGNATURE_TYPE:
            continue
        sig_data = entry.get("data")
        if not isinstance(sig_data, dict):
            continue
        if normalize_hash(sig_data.get("target")) != cap_hash:
            continue
        if normalize_hash(sig_data.get("signer")) != granter_hash:
            continue
        signature = sig_data.get("signature")
        if not isinstance(signature, (bytes, bytearray)):
            continue
        if verify_for_key_type(
            key_type_byte, bytes(public_key), cap_hash, bytes(signature),
        ):
            return
        raise ReentryGrantError("granter signature does not verify")
    raise ReentryGrantError("no granter signature targeting the capability")
