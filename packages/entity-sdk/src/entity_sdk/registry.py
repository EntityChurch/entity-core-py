"""Registry operations — `EXTENSION-REGISTRY` v1 §6a.9 / §6a.9.2.

.. rubric:: Why this module is shaped locally rather than transcribed

`SDK-EXTENSION-OPERATIONS` v0.8 has **no registry section** — registry appears
in neither §14's surface table nor §15's availability table — and
`EXTENSION-REGISTRY` says why: *"This extension stops at the handler contract;
the L5 browse SDK consumes it."* So unlike §3 tree or §9 discovery there is no
SDK signature to implement, and the method names here are ours under
`GUIDE-SDK-PATTERNS`' advisory tier (`SDK-OPERATIONS` §16.3).

**The wire is not ours.** §6a.9 and §6a.9.2 pin the request types, the result
types, the statuses and the codes exactly, and this module is a thin, typed
projection of them. Nothing below invents a payload.

.. rubric:: The four things a caller rolling this by hand gets wrong

1. **The replay-defense discriminator is per-operation, and it is not the op
   name.** §6a.9.2: a signed request carries `nonce` + `issued_at` *iff replay
   has a non-idempotent state effect.* `register` and `renew` do (a replay can
   roll a name back to a superseded binding, or extend a binding past its
   intended lapse). `revoke` does **not** — it is monotonic on a
   content-addressed target, so replay is a provable no-op — and the spec is
   explicit that the fields would be *"harmless but add no security and break
   cohort convergence."* :func:`revoke` therefore omits them by construction,
   not by the caller remembering to.
2. **`get-issuer-policy` takes the §3.2 empty-params shape**, which is a
   `primitive/any` whose data is canonical-CBOR `a0`. It is *not* a zero-value
   entity (rejected `400 invalid_params` at the envelope layer, before the
   handler ever runs) and *not* a `primitive/map` (`400 unexpected_params`).
   The SDK's `execute` passes `params=None` straight through, so a caller
   reaching for the obvious spelling sends one of the two rejected shapes.
   §6a.9.2 notes a unit test calling the handler directly never crosses the
   envelope layer and so cannot see either failure — core-go found both on
   first contact with a live peer.
3. **`set-issuer-policy` replaces the policy whole** `[MUST]` — an absent
   optional field means *unset*, never *unchanged*, because a merge would make
   the stored policy depend on write order, which two peers cannot reconstruct.
   :func:`set_issuer_policy` takes a whole :class:`IssuerPolicy` rather than
   keyword deltas so there is no spelling for a partial update.
4. **`register-result` has three statuses, and 202 is not a failure.**
   `bound` (200) carries `binding_hash`; `pending_review` (202) carries
   `pending_hash`; `denied` carries neither. §6a.9 records this as a real
   three-way cohort divergence — an undeclared outcome made each implementation
   invent a carrier — and pins that `system/protocol/error` MUST NOT carry the
   202, since a client branching on result type would otherwise reach the
   opposite conclusion from one branching on status.

.. rubric:: Layer-1 proof is not optional, so it is not a parameter

Every `register` / `renew` / `revoke` request MUST carry a `system/signature`
by `target_peer_id` (§6a.9 ownership-proof layer 1): it proves the requester
holds the key they are binding the name to, so nobody can register *someone
else's* peer-id under a name. These wrappers take a :class:`Keypair` and always
sign, and always set `target_peer_id` from that keypair — the spec's *"the
requester IS `target_peer_id`"*. There is deliberately no way to express an
unsigned request or a mismatched target.
"""

from __future__ import annotations

import os
import time
import unicodedata
from dataclasses import dataclass
from typing import Any

from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity

from entity_sdk.errors import BadRequest

__all__ = [
    "REGISTRY_PATTERN",
    "ISSUER_POLICY_TYPE",
    "REGISTER_REQUEST_TYPE",
    "RENEW_REQUEST_TYPE",
    "REVOKE_REQUEST_TYPE",
    "ISSUER_MODES",
    "IssuerPolicy",
    "RegisterResult",
    "RenewResult",
    "RevokeResult",
    "normalize_registry_name",
    "set_issuer_policy",
    "get_issuer_policy",
    "register",
    "renew",
    "revoke",
]

#: The handler's dispatch pattern (`REGISTRY_HANDLER_PATTERN`, EXTENSION-REGISTRY
#: §6a). A pattern string, not an import — the SDK never imports handlers.
REGISTRY_PATTERN = "system/registry"

ISSUER_POLICY_TYPE = "system/registry/issuer-policy"
REGISTER_REQUEST_TYPE = "system/registry/register-request"
RENEW_REQUEST_TYPE = "system/registry/renew-request"
REVOKE_REQUEST_TYPE = "system/registry/revoke-request"

#: §6a.9.1. `domain-control` is accepted by this constant because it is a real
#: mode name, and refused by the registry with `400 unsupported_mode` until the
#: challenge format lands. The SDK does not pre-empt that refusal: the ratified
#: server-side rule is the one worth having under test.
ISSUER_MODES = frozenset({"open", "allowlist", "manual", "domain-control"})

#: §3.2 empty-params: a `primitive/any` whose data encodes to canonical-CBOR
#: `a0`. See the module docstring — the two obvious alternatives are both
#: rejected before the handler runs.
_EMPTY_PARAMS: dict[str, Any] = {"type": "primitive/any", "data": {}}


# ---------------------------------------------------------------------------
# Typed projections of the pinned entities
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuerPolicy:
    """§6a.9.2 `system/registry/issuer-policy` — admission config, whole.

    Every optional field is written on each `set`, absent meaning *unset*. That
    is the spec's replace-whole rule surfacing as a value type: there is no way
    to spell "leave this one alone."

    **`default_ttl` and `max_ttl` are optional here and required on the wire**
    for any live-registration mode (§6a.9.2 D11, §6a.9.1 v1.11). They stay
    `None`-able on this type deliberately: a client that cannot express the
    refused shape cannot exercise the refusal, and the peer's `400` is the
    contract — an SDK-side pre-check would hide which side enforces it.
    """

    mode: str
    allowlist: list[str] | None = None
    name_constraints: Any | None = None
    default_ttl: int | None = None
    max_ttl: int | None = None

    def to_data(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "allowlist": self.allowlist,
            "name_constraints": self.name_constraints,
            "default_ttl": self.default_ttl,
            "max_ttl": self.max_ttl,
        }

    @classmethod
    def from_data(cls, data: Any) -> IssuerPolicy:
        d = data if isinstance(data, dict) else {}
        allowlist = d.get("allowlist")
        return cls(
            mode=d.get("mode", ""),
            allowlist=list(allowlist) if isinstance(allowlist, list) else None,
            name_constraints=d.get("name_constraints"),
            default_ttl=d.get("default_ttl"),
            max_ttl=d.get("max_ttl"),
        )


@dataclass(frozen=True, slots=True)
class RegisterResult:
    """§6a.9 `system/registry/register-result`.

    The presence rules are the contract, not decoration: `binding_hash` is
    REQUIRED on `bound` and `pending_hash` on `pending_review`, and **both are
    absent on `denied`** — the request is decided and nothing was published, so
    there is no hash to hand back.
    """

    status: str
    binding_hash: bytes | None = None
    pending_hash: bytes | None = None

    @property
    def bound(self) -> bool:
        return self.status == "bound"

    @property
    def pending(self) -> bool:
        """202 accepted-pending. **Not a failure** — see the module docstring."""
        return self.status == "pending_review"

    @property
    def denied(self) -> bool:
        return self.status == "denied"


@dataclass(frozen=True, slots=True)
class RenewResult:
    """§6a.9 `system/registry/renew-result` — the new binding in the chain."""

    binding_hash: bytes | None = None


@dataclass(frozen=True, slots=True)
class RevokeResult:
    """§6a.9 `system/registry/revoke-result` — the §3.1 revocation emitted."""

    revoked: bool = False
    revocation_hash: bytes | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_registry_name(name: str) -> str:
    """NFC-normalize and check a registry name for §6.3 path safety.

    A name becomes a tree path segment (the by-name index at
    `system/registry/binding/by-name/{name}`), so a `/` would silently write a
    *different* path than the caller asked for, and a control character would
    make the binding unaddressable. Both are refused rather than escaped.

    Raises:
        BadRequest: 400 `invalid_params` if the name is unsafe or empty.
    """
    normalized = unicodedata.normalize("NFC", name)
    if not normalized:
        raise BadRequest(400, "invalid_params", "registry name must not be empty")
    if "/" in normalized:
        raise BadRequest(
            400, "invalid_params",
            f"registry name {name!r} must not contain '/' — it is one path segment",
        )
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in normalized):
        raise BadRequest(
            400, "invalid_params",
            f"registry name {name!r} must not contain control characters",
        )
    return normalized


def _data_of(result: Any) -> dict[str, Any]:
    """The `data` map of a result entity, tolerating a bare map."""
    if not isinstance(result, dict):
        return {}
    inner = result.get("data")
    if isinstance(inner, dict):
        return inner
    return result


def _as_hash(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def _signed_included(keypair: Keypair, request: Entity) -> list[dict[str, Any]]:
    """The layer-1 ownership proof: identity + target-matched signature.

    The signature's target is the request's own `content_hash` (V7 §5.2
    target-matching), which is how the registry finds it in `included` — this
    architecture is refless, so there is no pointer to follow.
    """
    identity = create_identity_entity(keypair)
    signature = create_signature_entity(
        keypair, request.compute_hash(), identity.compute_hash()
    )
    return [identity.to_dict(), signature.to_dict()]


def _replay_fields(nonce: bytes | None, issued_at: int | None) -> dict[str, Any]:
    """`nonce` + `issued_at` for the replay-defended operations only.

    Both are injectable so a test can drive `REG-REGISTER-REPLAY-1` — replaying
    a seen nonce — without racing a clock or hoping for a collision.
    """
    return {
        "nonce": os.urandom(16) if nonce is None else nonce,
        "issued_at": int(time.time() * 1000) if issued_at is None else issued_at,
    }


# ---------------------------------------------------------------------------
# §6a.9.2 — policy management
# ---------------------------------------------------------------------------


async def set_issuer_policy(client: Any, policy: IssuerPolicy) -> IssuerPolicy:
    """Install/replace the registry's issuer-policy (§6a.9.2).

    Writing a policy is what turns a curated/static registry (§6a.8) *live*: it
    begins accepting `register-request`.

    Replace-whole `[MUST]` — the whole :class:`IssuerPolicy` is written and an
    absent optional field means unset. Returns the stored policy as written,
    which is the handler's own output and not an echo of the input.

    Raises:
        BadRequest: 400 `unsupported_mode` for `domain-control`, which the
            registry refuses to *store* until the challenge format lands
            (§6a.9.1). Surfaced rather than pre-empted, so the ratified
            server-side rule stays the thing under test.
    """
    result = await client.execute(
        REGISTRY_PATTERN,
        "set-issuer-policy",
        {"type": ISSUER_POLICY_TYPE, "data": policy.to_data()},
    )
    return IssuerPolicy.from_data(_data_of(result))


async def get_issuer_policy(client: Any) -> IssuerPolicy:
    """Read the stored issuer-policy (§6a.9.2).

    Raises:
        NotFound: 404 when no policy is stored. **Unset is not a mode** — a
            registry with no policy entity is a conformant curated-only one
            (§6a.8) that does not run live registration at all. Synthesizing a
            default `open` here would silently turn it into first-come,
            first-served, so the 404 is propagated rather than absorbed.
    """
    result = await client.execute(REGISTRY_PATTERN, "get-issuer-policy", _EMPTY_PARAMS)
    return IssuerPolicy.from_data(_data_of(result))


# ---------------------------------------------------------------------------
# §6a.9 — live registration and its follow-on operations
# ---------------------------------------------------------------------------


async def register(
    client: Any,
    keypair: Keypair,
    name: str,
    *,
    transports: list[Any] | None = None,
    requested_ttl: int | None = None,
    nonce: bytes | None = None,
    issued_at: int | None = None,
) -> RegisterResult:
    """Self-register ``name`` → ``keypair.peer_id`` at a live registry (§6a.9).

    Signed by ``keypair`` (layer-1 proof) and replay-defended with
    `nonce` + `issued_at`, because a replayed register can roll a name back to
    a superseded binding.

    ``target_peer_id`` is taken from ``keypair`` and is not a parameter: §6a.9
    requires the signature to be *by* `target_peer_id`, so the two can never
    legitimately differ, and letting a caller pass them separately only creates
    a request the registry must reject.

    Returns:
        The typed §6a.9 result. Check :attr:`RegisterResult.pending` before
        treating a non-`bound` outcome as failure — a 202 is accepted, not
        refused.
    """
    request_data = {
        "name": normalize_registry_name(name),
        "target_peer_id": keypair.peer_id,
        "transports": list(transports) if transports else [],
        "requested_ttl": requested_ttl,
        **_replay_fields(nonce, issued_at),
    }
    request = Entity(type=REGISTER_REQUEST_TYPE, data=request_data)
    result = await client.execute(
        REGISTRY_PATTERN,
        "register-request",
        {"type": REGISTER_REQUEST_TYPE, "data": request_data},
        included=_signed_included(keypair, request),
    )
    data = _data_of(result)
    return RegisterResult(
        status=data.get("status", ""),
        binding_hash=_as_hash(data.get("binding_hash")),
        pending_hash=_as_hash(data.get("pending_hash")),
    )


async def renew(
    client: Any,
    keypair: Keypair,
    binding_hash: bytes,
    *,
    ttl: int | None = None,
    nonce: bytes | None = None,
    issued_at: int | None = None,
) -> RenewResult:
    """Extend a binding's lifetime via the supersedes-chain (§6a.9).

    Replay-defended: each accepted renew extends expiry, so a captured renew
    could otherwise be replayed to keep a binding alive past the registrant's
    intended lapse.
    """
    request_data: dict[str, Any] = {
        "binding_hash": binding_hash,
        "ttl": ttl,
        **_replay_fields(nonce, issued_at),
    }
    request = Entity(type=RENEW_REQUEST_TYPE, data=request_data)
    result = await client.execute(
        REGISTRY_PATTERN,
        "renew-request",
        {"type": RENEW_REQUEST_TYPE, "data": request_data},
        included=_signed_included(keypair, request),
    )
    return RenewResult(binding_hash=_as_hash(_data_of(result).get("binding_hash")))


async def revoke(
    client: Any,
    keypair: Keypair,
    binding_hash: bytes,
    *,
    reason: str | None = None,
) -> RevokeResult:
    """Revoke a binding, emitting a §3.1 revocation (§6a.9).

    **Deliberately not replay-defended, and that is the spec's call, not an
    omission.** Revocation is monotonic and target-pinned: it acts on one
    content-addressed `binding_hash`, cannot be undone, and cannot reach a
    later re-issued binding (different hash), so a replay is a provable no-op.
    §6a.9 states that `nonce` / `issued_at` here *"would be harmless but add no
    security and break cohort convergence"* — a request carrying them is a
    different request, and this is a cross-impl seam. The signature is
    unchanged: layer-1 proof is still required.

    ``reason`` is operator-supplied prose and is never parsed (§6a.9.3).
    """
    request_data: dict[str, Any] = {"binding_hash": binding_hash, "reason": reason}
    request = Entity(type=REVOKE_REQUEST_TYPE, data=request_data)
    result = await client.execute(
        REGISTRY_PATTERN,
        "revoke-request",
        {"type": REVOKE_REQUEST_TYPE, "data": request_data},
        included=_signed_included(keypair, request),
    )
    data = _data_of(result)
    return RevokeResult(
        revoked=bool(data.get("revoked", False)),
        revocation_hash=_as_hash(data.get("revocation_hash")),
    )
