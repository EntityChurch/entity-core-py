"""ECF `emit-canonical` mode.

Implements the §1 contract from the ECF conformance V1 cross-team assignment:

- Loads a corpus (either ``.diag`` text or ``.cbor`` array of vector maps).
- For each ``encode_equal`` vector, runs the input through the per-category
  emitter (Class A: direct ECF; Class B: content_hash / peer_id / signature
  / envelope construction).
- For each ``decode_reject`` vector, runs the strict ECF validator on the
  canonical bytes; records True if rejected, False if accepted.
- Returns / writes the emission map in canonical-ECF form.
"""

from __future__ import annotations

import hashlib
from typing import Any

import base58
import cbor2

from entity_core.conformance.diag import parse_diag
from entity_core.conformance.strict import is_canonical_ecf
from entity_core.crypto.identity import Keypair
from entity_core.utils.ecf import ecf_encode

CORPUS_VERSION = "v1"
SPEC_VERSION = "1.5"
IMPL_NAME = "core-py"


def load_corpus(path: str) -> list[dict]:
    """Load a v1 corpus from either a ``.diag`` or ``.cbor`` file.

    The corpus root must be a CBOR array of vector maps. Vector shape per
    GUIDE-CONFORMANCE.md §2.1.
    """
    with open(path, "rb") as f:
        data = f.read()
    if path.endswith(".diag"):
        parsed = parse_diag(data.decode("utf-8"))
    else:
        parsed = cbor2.loads(data)
    if not isinstance(parsed, list):
        raise ValueError(f"corpus root must be a CBOR array, got {type(parsed).__name__}")
    return parsed


def emit_canonical(corpus: list[dict], impl_version: str) -> dict:
    """Run every vector through the impl's encoder/validator.

    Returns the emission map per §1 of the cross-team assignment.
    """
    encode_results: dict[str, bytes] = {}
    decode_results: dict[str, bool] = {}
    errors: dict[str, str] = {}

    for vector in corpus:
        vid = vector["id"]
        kind = vector["kind"]
        if kind == "encode_equal":
            try:
                encode_results[vid] = _emit_encode_equal(vid, vector["input"])
            except _UnsupportedFeature as e:
                errors[vid] = str(e)
            except Exception as e:  # noqa: BLE001 — record everything else as errors
                errors[vid] = f"{type(e).__name__}: {e}"
        elif kind == "decode_reject":
            try:
                decode_results[vid] = not is_canonical_ecf(vector["canonical"])
            except Exception as e:  # noqa: BLE001
                errors[vid] = f"{type(e).__name__}: {e}"
                decode_results[vid] = False
        else:
            errors[vid] = f"unknown vector kind {kind!r}"

    return {
        "impl": IMPL_NAME,
        "impl_version": impl_version,
        "corpus_version": CORPUS_VERSION,
        "spec_version": SPEC_VERSION,
        "encode_results": encode_results,
        "decode_results": decode_results,
        "errors": errors,
    }


# --- per-category emitters ---------------------------------------------------


class _UnsupportedFeature(Exception):
    """Recorded in ``errors`` (not encode_results) per §4 of the assignment."""


def _emit_encode_equal(vid: str, input_val: Any) -> bytes:
    category = vid.split(".", 1)[0]
    if category == "content_hash":
        return _emit_content_hash(input_val)
    if category == "peer_id":
        return _emit_peer_id(input_val)
    if category == "signature":
        return _emit_signature(input_val)
    if category == "envelope":
        return _emit_envelope(input_val)
    # Class A: float / int / map_keys / length / primitive / nested
    return ecf_encode(input_val)


def _emit_content_hash(input_val: dict) -> bytes:
    """varint(format_code) || SHA256(ECF({type, data}))."""
    fmt = input_val.get("format_code", 0)
    inner = {"type": input_val["type"], "data": input_val["data"]}
    digest = hashlib.sha256(ecf_encode(inner)).digest()
    return _multicodec_varint(fmt) + digest


def _emit_peer_id(input_val: dict) -> bytes:
    """Base58(varint(key_type) || varint(hash_type) || digest), ECF-tstr."""
    key_type = input_val["key_type"]
    hash_type = input_val["hash_type"]
    digest = input_val["digest"]
    raw = _multicodec_varint(key_type) + _multicodec_varint(hash_type) + bytes(digest)
    pid = base58.b58encode(raw).decode("ascii")
    return ecf_encode(pid)


def _emit_signature(input_val: dict) -> bytes:
    """Deterministic Ed25519 ``sign(content_hash(entity))`` under a
    seed-derived key — §7.3, CQ-22, ruled at ``0.8.2.26``.

    The message is the target entity's **full `content_hash`** —
    ``varint(format_code) ‖ SHA256(ECF({type, data}))`` — never the bare
    digest and never the entity's canonical-ECF bytes.

    .. rubric:: ⛔ This signed ``ecf_encode(entity)`` until 0.8.2.26 was
       absorbed, and that made py a SECOND implementation of the losing
       reading

    Arch's `.26` packet states: *"Your peer is already right… **the sole
    implementation of the losing reading is the conformance fixture.**"* True
    of this peer — ``auth.create_signature_entity`` signs the full
    ``target_hash`` and always has, which is why 8 of 8 live peers complete
    the handshake. **False of this emitter.** Had py been used as the second
    independent codec for `S-1`'s cross-bless, it would have **confirmed the
    wrong bytes**, and two independent codecs agreeing is the most convincing
    green there is — the standing *cohort agreement is evidence about the
    reading implementers reach, not about the text* law.

    .. rubric:: ⭐ And the correct input was one function above, unused

    Arch's own finding about the artifact — *"it contains its own correct
    input one category above: ``content_hash.1`` produces the exact value
    §7.3 names as the message, and the ``signature`` category three rows down
    does not use it"* — was true of **this file** in the identical shape:
    :func:`_emit_content_hash` sat directly above and was never called. It is
    called now, so the two categories cannot drift apart again without the
    ``content_hash`` category moving too.
    """
    seed = bytes(input_val["seed"])
    entity = input_val["entity"]
    keypair = Keypair.from_seed(seed)
    msg = _emit_content_hash({
        "type": entity["type"],
        "data": entity["data"],
        **({"format_code": entity["format_code"]}
           if "format_code" in entity else {}),
    })
    return keypair.sign(msg)


def _emit_envelope(input_val: dict) -> bytes:
    """Canonical-ECF encoding of the envelope carrier shape."""
    return ecf_encode(input_val)


# --- helpers -----------------------------------------------------------------


def _multicodec_varint(n: int) -> bytes:
    """Multicodec-style LEB128 varint encoding per V7 §7.3.

    Codes 0–127 encode as a single byte (no continuation bit); codes ≥ 128
    chain with the continuation bit (MSB) set on every non-final byte. This
    is the encoding the spec pins for every format-code field — hash format
    codes (§1.2), peer-ID ``key_type`` and ``hash_type`` (§1.5).

    Not the same as CBOR's argument encoding — CBOR uses major-type-bits +
    fixed-length argument, multicodec chains 7-bit groups.
    """
    if n < 0:
        raise _UnsupportedFeature(f"negative varint not supported: {n}")
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def encode_emission(emission: dict) -> bytes:
    """Encode the §1 emission map to canonical-ECF CBOR bytes."""
    return ecf_encode(emission)
