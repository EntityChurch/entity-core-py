"""V7 v7.64-era PIM peer-id-form conformance vectors — rescoped under v7.65/v7.66.

Per V7 v7.65 §9.2 direction (Go-owned restructuring; analogous Python-side
treatment): the v7.64 PIM categories that asserted SHA-256-form Keypair
construction are rescoped as **legacy-decode-validation** tests under the
§5 wire-acceptance carve-out. Keypair construction under v7.65 §4 is
canonical-only (identity-multihash). Per v7.66 §3, the public mint API
no longer accepts a ``hash_type`` kwarg; SHA-256-form fixture bytes for
the §5 wire-acceptance decode path are produced via the internal
``_peer_id_from_bytes`` assembly helper (corpus-authoring path, not a
live mint API; see identity.py docstring).

The v7.65 PEER-CANON-1/2 + PEER-PATTERN-1/2 + PEER-MUT-1/2 + COMPOSITION-1
conformance vectors supersede these PIM categories for cross-impl
convergence; this file pins the legacy-decode invariants that remain
load-bearing for the §5 carve-out.
"""

from __future__ import annotations

import base58

from entity_core.crypto.identity import (
    HASH_TYPE_IDENTITY,
    HASH_TYPE_SHA256,
    KEY_TYPE_ED25519,
    KEY_TYPE_TEST_SYNTHETIC,
    Keypair,
    _peer_id_from_bytes,
    decode_peer_id,
    derive_peer_from_peer_id,
    derive_peer_id,
    peer_id_from_public_key_bytes,
)


def _legacy_form_for_corpus(pubkey_bytes: bytes) -> str:
    """V7 v7.66 §3.4 — corpus-authoring helper for legacy SHA-256-form bytes.

    The public mint API is canonical-only (v7.66 §3); this helper produces
    the opaque legacy-form bytestring used by §5 wire-acceptance fixtures
    that exercise the decoder + canonicalize-on-receipt path. Tests-only.
    """
    return _peer_id_from_bytes(
        pubkey_bytes, key_type=KEY_TYPE_ED25519, hash_type=HASH_TYPE_SHA256,
    )


SEED_A = b"\xa0" * 32
SEED_B = b"\xb0" * 32


# ---------- PIM-1: identity form encode/decode round-trip (canonical) ----------

def test_pim1_identity_form_encode_decode_roundtrip() -> None:
    kp = Keypair.from_seed(SEED_A)  # v7.65 §4: canonical-only
    key_type, hash_type, digest = decode_peer_id(kp.peer_id)
    assert key_type == KEY_TYPE_ED25519
    assert hash_type == HASH_TYPE_IDENTITY
    assert digest == kp.public_key_bytes()

    recovered = derive_peer_from_peer_id(kp.peer_id)
    assert recovered is not None
    public_key, recovered_kt = recovered
    assert public_key == kp.public_key_bytes()
    assert recovered_kt == KEY_TYPE_ED25519


# ---------- PIM-2: SHA-256 wire form is NOT self-resolving (legacy decode) ----------

def test_pim2_sha256_form_is_not_self_resolving() -> None:
    """SHA-256-form wire peer_ids (§5 legacy-decode targets) cannot recover
    pubkey from the peer_id alone — this is the structural reason §4 mandates
    canonical identity-form for Ed25519 (cap patterns matched on string)."""
    kp = Keypair.from_seed(SEED_A)
    # Synthesize the SHA-256-form wire peer_id for legacy-decode testing.
    sha_pid = _legacy_form_for_corpus(kp.public_key_bytes())
    key_type, hash_type, digest = decode_peer_id(sha_pid)
    assert key_type == KEY_TYPE_ED25519
    assert hash_type == HASH_TYPE_SHA256
    import hashlib
    assert digest == hashlib.sha256(kp.public_key_bytes()).digest()

    # The helper MUST return None — pubkey is not recoverable from sha-form.
    assert derive_peer_from_peer_id(sha_pid) is None


# ---------- PIM-3: legacy-decode wire-shape symmetry ----------

def test_pim3_mixed_form_construction_and_decode() -> None:
    """v7.65 §5 carve-out: decoders accept both forms. Construction under
    v7.65 §4 is canonical-only; SHA-256-form is synthesized here from the
    canonical Keypair's pubkey strictly to exercise the legacy-decode path."""
    kp = Keypair.from_seed(SEED_A)
    canonical_pid = kp.peer_id
    legacy_pid = _legacy_form_for_corpus(kp.public_key_bytes())

    for pid in (canonical_pid, legacy_pid):
        kt, ht, digest = decode_peer_id(pid)
        assert kt == KEY_TYPE_ED25519
        assert ht in (HASH_TYPE_IDENTITY, HASH_TYPE_SHA256)
        assert len(digest) == 32


# ---------- PIM-4: byte-stability across runs (cross-impl proxy) ----------

def test_pim4_peer_id_byte_stability() -> None:
    """Same (key_type, hash_type, public_key) MUST produce byte-identical
    peer_ids. Canonical-form pinned via Keypair construction; legacy-form
    pinned via peer_id_from_public_key_bytes."""
    kp1 = Keypair.from_seed(SEED_A)
    kp2 = Keypair.from_seed(SEED_A)
    assert kp1.peer_id == kp2.peer_id

    legacy1 = _legacy_form_for_corpus(kp1.public_key_bytes())
    legacy2 = _legacy_form_for_corpus(kp2.public_key_bytes())
    assert legacy1 == legacy2

    # Different forms of the same pubkey → different peer_id strings.
    assert kp1.peer_id != legacy1


# ---------- PIM-5: length-agnostic decoder via test/synthetic key_type ----------

def test_pim5_length_agnostic_decoder_with_synthetic_key_type() -> None:
    """key_type = 0xFE is reserved test/synthetic per §2.1; identity-form
    with a 256-byte synthetic digest MUST round-trip cleanly to verify
    the decoder is length-agnostic for future long-key types."""
    synthetic_digest = bytes(range(256))  # 256 bytes
    data = bytes([KEY_TYPE_TEST_SYNTHETIC, HASH_TYPE_IDENTITY]) + synthetic_digest
    pid = base58.b58encode(data).decode("ascii")

    kt, ht, digest = decode_peer_id(pid)
    assert kt == KEY_TYPE_TEST_SYNTHETIC
    assert ht == HASH_TYPE_IDENTITY
    assert digest == synthetic_digest

    recovered = derive_peer_from_peer_id(pid)
    assert recovered is not None
    pubkey, kt2 = recovered
    assert pubkey == synthetic_digest
    assert kt2 == KEY_TYPE_TEST_SYNTHETIC


# ---------- Auxiliary ----------

def test_default_new_peer_init_is_identity_form() -> None:
    """v7.65 §4 MUST: Ed25519 Keypair construction yields canonical
    identity-multihash form."""
    kp = Keypair.generate()
    kt, ht, _ = decode_peer_id(kp.peer_id)
    assert kt == KEY_TYPE_ED25519
    assert ht == HASH_TYPE_IDENTITY


def test_peer_id_from_public_key_bytes_matches_keypair() -> None:
    kp = Keypair.from_seed(SEED_A)
    derived = peer_id_from_public_key_bytes(kp.public_key_bytes())
    assert derived == kp.peer_id


def test_v7_66_public_mint_api_canonical_only() -> None:
    """V7 v7.66 §3 / LEGACY-MINT-1: the public mint API has no
    ``hash_type`` kwarg. Synthesis of legacy SHA-256-form bytestrings is
    routed through the internal corpus-authoring helper, not a live mint
    API path. ``derive_peer_id(pubkey, hash_type=...)`` MUST TypeError."""
    import pytest
    kp = Keypair.from_seed(SEED_A)

    # Canonical-only output.
    assert derive_peer_id(kp.public_key) == kp.peer_id
    assert peer_id_from_public_key_bytes(kp.public_key_bytes()) == kp.peer_id

    # Public mint API refuses the legacy kwarg.
    with pytest.raises(TypeError):
        derive_peer_id(kp.public_key, hash_type=HASH_TYPE_SHA256)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        peer_id_from_public_key_bytes(  # type: ignore[call-arg]
            kp.public_key_bytes(), hash_type=HASH_TYPE_SHA256,
        )


def test_load_identity_canonicalizes_stale_ed25519_peer_id(tmp_path, capsys) -> None:
    """V7 v7.66 §4.4 / IDENT-FILE-CANON-1: ``load_identity`` MUST re-derive
    the canonical wire peer_id from the public key and MUST NOT trust the
    file's stored ``peer_id``.

    Pre-v7.66 identity files (minted by the cross-impl harness before the
    canonical-form cutover) carry non-canonical SHA-256-form Ed25519
    peer_ids (``hash_type=0x01``). Trusting them propagates staleness onto
    the wire: the remote re-derives the canonical identity-form
    (``hash_type=0x00``), the two diverge, and chain-walk rejects with
    "Root capability not granted by local peer". The loader canonicalizes
    so a stale file still yields a correct peer, and warns per §5 SHOULD.
    """
    import base64
    import json

    from entity_core.crypto.identity_file import PEM_HEADER_ED25519, load_identity

    kp = Keypair.from_seed(SEED_A)
    pub = kp.public_key_bytes()
    canonical = derive_peer_id(kp.public_key)
    stale = _peer_id_from_bytes(pub, key_type=KEY_TYPE_ED25519, hash_type=HASH_TYPE_SHA256)
    assert stale != canonical  # the two forms genuinely differ

    name = "stale-py-fixture"
    (tmp_path / name).write_text(
        f"{PEM_HEADER_ED25519}\n{base64.b64encode(SEED_A).decode()}\n"
        f"-----END ENTITY PRIVATE KEY-----\n"
    )
    (tmp_path / f"{name}.json").write_text(
        json.dumps(
            {
                "key_type": "ed25519",
                "peer_id": stale,  # non-canonical, as the old harness wrote
                "public_key": base64.b64encode(pub).decode(),
            }
        )
    )

    loaded = load_identity(name, base_path=tmp_path)

    # Re-derived canonical form on both surfaces — never the stored stale value.
    assert loaded.keypair.peer_id == canonical
    assert loaded.peer_id_base58 == canonical
    assert decode_peer_id(loaded.keypair.peer_id)[1] == HASH_TYPE_IDENTITY

    # §5 SHOULD: non-canonical acceptance is surfaced.
    assert "non-canonical" in capsys.readouterr().err
