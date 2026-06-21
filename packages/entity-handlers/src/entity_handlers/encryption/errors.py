"""EXTENSION-ENCRYPTION §15 — error-code domain.

Per V7 §3.3 each extension owns its error codes. These map directly to the
``(status, code)`` pairs the handler returns; resource-bound exceedance reuses
V7 §4.10 codes verbatim (``payload_too_large`` etc.) and is not redefined here.
"""

from __future__ import annotations

# 400 — malformed / policy-refused input
AEAD_FAILED = ("encryption_aead_failed", 400)
UNSUPPORTED_SUITE = ("encryption_unsupported_suite", 400)
NO_COMMON_SUITE = ("encryption_no_common_suite", 400)
KDF_PARAMS_EXCESSIVE = ("encryption_kdf_params_excessive", 400)
INVALID_WRAPPER = ("encryption_invalid_wrapper", 400)
# R6 (arch v2.5): encryption pubkey MUST NOT be the identity key or its
# birational X25519 image (§2 / §9.4 / ENC-KEY-SEPARATION-1).
KEY_DERIVED_FROM_IDENTITY = ("encryption_key_derived_from_identity", 400)

# 403 — key / authorization failures
RECIPIENT_UNKNOWN = ("encryption_recipient_unknown", 403)
KEY_UNAVAILABLE = ("encryption_key_unavailable", 403)
KEY_REVOKED = ("encryption_key_revoked", 403)
SIGNATURE_INVALID = ("encryption_signature_invalid", 403)
UNSIGNED_SENDER = ("encryption_unsigned_sender", 403)

# 413 — resource bounds
WRAPPED_KEYS_TOO_MANY = ("encryption_wrapped_keys_too_many", 413)


class EncryptionError(Exception):
    """Carries a §15 ``(code, status)`` pair up to the handler boundary."""

    def __init__(self, code_status: tuple[str, int], message: str = ""):
        self.code, self.status = code_status
        super().__init__(message or self.code)
