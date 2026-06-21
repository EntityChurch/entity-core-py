"""Handler-grant signing and validation (spec-gap §S1, §S2).

Per V7 §6.2 and the spec-gap-handler-grant-authority document, handler
grants stored at `system/capability/grants/{pattern}` MUST be:
  - signed by the local peer (granter+grantee = local identity hash;
    a separate `system/signature` entity covers the grant's content hash,
    stored at the §3.5 invariant-pointer path `system/signature/{grant_hash}`
    per v7.74 v0.4 §3.4)
  - validated at dispatch read (granter must equal local identity;
    signature must verify; grant must not be expired)

The Go reference implementation lives at
`core/capability/grant_validity.go::VerifyHandlerGrant`.
"""

from __future__ import annotations

import time
from typing import Any

from entity_core.crypto.identity import (
    Keypair,
    UnsupportedKeyTypeError,
    key_type_byte_from_entity_data,
)
from entity_core.crypto.signing import verify_for_key_type
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity


def grant_signature_path(grant_hash: bytes) -> str:
    """Tree path for the signature entity covering a grant.

    V7 §3.5 invariant-pointer-by-hash (v7.74 v0.4 §3.4 CONVERGENT ruling):
    `system/signature/{grant_hash_hex}` — the same convention used
    everywhere else in the address space (`system/peer/{hash}`,
    `system/type/{name}`, `system/handler/{pattern}`). The dispatcher
    looks here at validation time, keyed by the grant entity's own
    content hash.

    Replaces the pre-v7.74 colocated `{grant_path}/signature` form (which
    was a 3-way cohort split — Go/Python colocated, Rust sibling-registry;
    keystone already at the invariant-pointer path). `grant_hash` is the
    grant entity's content_hash bytes; hex is lowercase and includes the
    format-code prefix.
    """
    return f"system/signature/{grant_hash.hex()}"


def build_signed_handler_grant(
    keypair: Keypair,
    grants: list[dict[str, Any]],
    *,
    expires_at: int | None = None,
    not_before: int | None = None,
) -> tuple[Entity, Entity, Entity]:
    """Build (grant_entity, signature_entity, identity_entity) for a handler.

    Per spec-gap §S1, sets granter = grantee = identity hash, populates
    `created_at`, and produces a separate `system/signature` entity over
    the grant's content hash. Caller emits the grant at
    `system/capability/grants/{pattern}` and the signature at
    `system/signature/{grant_hash}` (v7.74 v0.4 §3.4 invariant-pointer
    convergence — see ``grant_signature_path``). The identity entity
    should also be retained (in content store at minimum) so the granter
    hash resolves.
    """
    identity_entity = create_identity_entity(keypair)
    identity_hash = identity_entity.compute_hash()

    grant_data: dict[str, Any] = {
        "grants": grants,
        "granter": identity_hash,
        "grantee": identity_hash,
        "created_at": int(time.time() * 1000),
    }
    if expires_at is not None:
        grant_data["expires_at"] = expires_at
    if not_before is not None:
        grant_data["not_before"] = not_before

    grant_entity = Entity(type="system/capability/token", data=grant_data)

    signature_entity = create_signature_entity(
        keypair,
        target_hash=grant_entity.compute_hash(),
        signer_identity_hash=identity_hash,
    )
    return grant_entity, signature_entity, identity_entity


# ---------------------------------------------------------------------------
# Validation (spec-gap §S2)
# ---------------------------------------------------------------------------

class GrantValidationError(Exception):
    """Raised when handler grant validation fails. Treated as
    permission_denied at dispatch (same as §7.1 fail-closed)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def verify_handler_grant(
    grant_entity: Entity,
    signature_entity: Entity | None,
    granter_identity: Entity | None,
    local_identity_hash: bytes,
    *,
    now: int | None = None,
) -> None:
    """Validate a handler grant per V7 §6.2 / spec-gap §S2.

    Raises GrantValidationError on any failure; returns None on success.

    Checks (in order):
      1. granter is set (not None / not zero bytes)
      2. granter == local_identity_hash (handler grants must be locally issued)
      3. signature entity present, well-formed, and targets the grant's hash
      4. signature.signer == granter
      5. ed25519 signature verifies against granter identity's public key
      6. grant not expired (`expires_at` < now) or not-yet-valid
         (`now < not_before`)
    """
    if now is None:
        now = int(time.time() * 1000)

    grant_data = grant_entity.data
    granter = grant_data.get("granter")

    # 1. granter must be set.
    if not granter:
        raise GrantValidationError(
            "permission_denied",
            "Handler grant has no granter (V7 §6.2)",
        )
    if not isinstance(granter, bytes):
        raise GrantValidationError(
            "permission_denied",
            "Handler grant granter is not a content hash",
        )

    # 2. granter must be the local peer.
    if granter != local_identity_hash:
        raise GrantValidationError(
            "permission_denied",
            "Handler grant granter does not match local peer identity "
            "(spec-gap §S2 — foreign-granter rejection)",
        )

    # 3. signature entity must be present and well-formed.
    if signature_entity is None:
        raise GrantValidationError(
            "permission_denied",
            "Handler grant signature missing",
        )
    if signature_entity.type != "system/signature":
        raise GrantValidationError(
            "permission_denied",
            f"Expected system/signature, got {signature_entity.type}",
        )
    sig_data = signature_entity.data
    sig_target = sig_data.get("target")
    sig_signer = sig_data.get("signer")
    sig_algorithm = sig_data.get("algorithm")
    sig_bytes = sig_data.get("signature")

    if sig_target != grant_entity.compute_hash():
        raise GrantValidationError(
            "permission_denied",
            "Signature target does not match grant content hash",
        )
    # 4. signer matches granter.
    if sig_signer != granter:
        raise GrantValidationError(
            "permission_denied",
            "Signature signer does not match grant granter",
        )
    if not isinstance(sig_bytes, bytes):
        raise GrantValidationError(
            "permission_denied",
            "Signature is not bytes",
        )

    # 5. resolve granter identity → public key → verify.
    if granter_identity is None:
        raise GrantValidationError(
            "permission_denied",
            "Granter identity entity not resolvable",
        )
    if granter_identity.type != "system/peer":
        raise GrantValidationError(
            "permission_denied",
            f"Granter is not a system/peer entity ({granter_identity.type})",
        )
    public_key_bytes = granter_identity.data.get("public_key")
    if not isinstance(public_key_bytes, bytes):
        raise GrantValidationError(
            "permission_denied",
            "Granter identity has no public key",
        )

    # V7 v7.67 Phase 2 — the signature's `algorithm` MUST match the granter's
    # key_type (both entity-data strings), and the verifier dispatches on that
    # key_type. A mismatch is the cohort blocker symptom
    # ("unsupported_signature_algorithm: signature algorithm X does not match
    # granter key_type Y").
    granter_key_type = granter_identity.data.get("key_type", "ed25519")
    if sig_algorithm != granter_key_type:
        raise GrantValidationError(
            "permission_denied",
            f"unsupported_signature_algorithm: signature algorithm "
            f"{sig_algorithm!r} does not match granter key_type "
            f"{granter_key_type!r}",
        )
    try:
        granter_key_type_byte = key_type_byte_from_entity_data(granter_key_type)
    except UnsupportedKeyTypeError as exc:
        raise GrantValidationError("permission_denied", str(exc))
    if not verify_for_key_type(
        granter_key_type_byte, public_key_bytes, sig_target, sig_bytes,
    ):
        raise GrantValidationError(
            "permission_denied",
            "Handler grant signature verification failed",
        )

    # 6. temporal bounds.
    expires_at = grant_data.get("expires_at")
    if expires_at is not None and expires_at < now:
        raise GrantValidationError(
            "permission_denied",
            "Handler grant expired",
        )
    not_before = grant_data.get("not_before")
    if not_before is not None and now < not_before:
        raise GrantValidationError(
            "permission_denied",
            "Handler grant not yet valid",
        )
