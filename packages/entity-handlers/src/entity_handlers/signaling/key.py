"""The rendezvous key — **peer-side** derivation.

``EXTENSION-SIGNALING.md`` §3.1 (committed corpus, re-diffed 2026-08-05)::

    payload        = "entity:rdv:v1" ‖ SEP ‖ mode ‖ SEP ‖ canonical(mode_input)
    rendezvous_key = varint(0x00) ‖ SHA-256( ecf_for_hash("system/signaling/rendezvous-key",
                                                          cbor_bstr(payload) ) )

**This binds peers only.** The node is mode-blind — it compares 33 opaque bytes
and derives nothing — so everything here is a client obligation.

Why every free variable is pinned
---------------------------------

Both peers MUST produce byte-identical hash input **and** byte-identical key
bytes. Divergence means the two peers derive different keys and **silently never
meet**: nothing errors, nothing logs, the handshake just never completes. That
failure is invisible to a same-impl test (encoder and decoder agree with
themselves), which is why §2.2.1 supplies *differential* properties instead of
authored expected-key vectors, and why they are ported alongside this code in
``tests/unit/test_signaling_key.py``.

The load-bearing one is the **format code**. A content hash is normally
self-describing and format-carrying, and that is correct everywhere else
*because* content is authored once and its hash travels with it. A rendezvous
key inverts that: it is a **lookup token two independent parties must
reproduce**. So it is pinned to the SHA-256 floor (``0x00``) **regardless of the
deriving peer's home format** — otherwise a SHA-384-home peer and a SHA-256-home
peer derive different keys for the same agreed input and never meet, having
passed every other check.

Concretely, in this impl that means :func:`derive` calls
:func:`~entity_core.utils.ecf.compute_ecf_hash` with an **explicit**
``ALG_ECFV1_SHA256`` and MUST NOT build an :class:`~entity_core.protocol.entity.Entity`
to get a hash: ``Entity.compute_hash`` falls back to
:func:`~entity_core.utils.ecf.get_default_hash_algorithm`, the process-global
set at peer construction (the Rust analog is ``Entity::new`` following
``default_hash_format()``). ``test_signaling_key.py`` flips that global to
SHA-384, asserts the flip is live so the test cannot pass vacuously, and
requires byte-identical keys.
"""

from __future__ import annotations

from entity_core.utils.ecf import ALG_ECFV1_SHA256, Hash, compute_ecf_hash
from entity_handlers.signaling.constants import (
    RENDEZVOUS_KEY_LEN,
    SignalingDecodeError,
)

#: The ``type`` half of the hash input — pinned by §3.1, since the substrate
#: content-hash primitive hashes ECF ``{type, data}`` and has no bare-byte form.
#:
#: **This string is wire-visible and was the flag day.** §13 open item #1
#: (`system/nat/*` vs `system/signaling/*`) resolved to `system/signaling/*` on
#: 2026-08-02, and because the derivation hashes the literal type string, the
#: rename changes every derived key. This client was built against the
#: pre-resolution brief and carried `system/nat/rendezvous-key` until the
#: 2026-08-05 re-diff against the committed corpus — the whole time it agreed
#: with itself, produced the §2.2.1 stage-bisect payload byte-for-byte
#: (the payload does NOT contain the type string), and could not have met a
#: post-flag-day go or rust peer at any key.
RENDEZVOUS_KEY_TYPE = "system/signaling/rendezvous-key"

#: The domain-separation prefix. Versioned so a future derivation change is a
#: new domain rather than a silent reinterpretation of the same bytes.
DOMAIN = "entity:rdv:v1"

#: ``SEP`` = ASCII US. It appears **after the domain string and after the mode
#: tag** — not only before the input.
SEP = 0x1F

#: The exact ASCII mode tags (§2.2). Wire-visible through the derived key, so
#: they are spelled once here and never constructed by formatting.
MODE_PAIR = "pair"
MODE_TAG = "tag"
MODE_SECRET = "secret"
MODE_LOBBY = "lobby"


# ---------------------------------------------------------------------------
# The derivation
# ---------------------------------------------------------------------------


def rendezvous_payload(mode: str, canonical_input: bytes) -> bytes:
    """Build the pre-hash payload.

    Exposed because §2.2.1's stage-bisect names it as the first place two
    disagreeing impls compare bytes: if the payloads match and the keys do not,
    the fault is in the CBOR framing or the digest, not the concatenation.
    """
    return b"".join((
        DOMAIN.encode("utf-8"),
        bytes([SEP]),
        mode.encode("utf-8"),
        bytes([SEP]),
        canonical_input,
    ))


def derive(mode: str, canonical_input: bytes) -> Hash:
    """Derive a key from a mode tag and an already-canonicalized input.

    Prefer the four named constructors below — they own the canonicalization,
    which is where ``pair``'s sort-and-separate rule lives. This is the escape
    hatch for a mode added upstream before this module knows about it.
    """
    payload = rendezvous_payload(mode, canonical_input)
    # ``data`` = the payload as a single CBOR bstr with a minimal-length head
    # (§2.2). Passing Python ``bytes`` through ECF encodes exactly that, and
    # ``compute_ecf_hash`` then embeds it under the "data" key of the hashed
    # ``{data, type}`` map — the same double encoding every entity has.
    #
    # ALG_ECFV1_SHA256 is passed EXPLICITLY: this is the SHA-256 floor pin, so
    # it must not read the process-global default (see the module docstring).
    return compute_ecf_hash(
        {"type": RENDEZVOUS_KEY_TYPE, "data": payload}, ALG_ECFV1_SHA256
    )


# ---------------------------------------------------------------------------
# The four modes (§2.2)
# ---------------------------------------------------------------------------


def pair_key(peer_a: str, peer_b: str) -> Hash:
    """``pair`` — exactly those two peers meet.

    Identity *is* the key, so no secret is needed and none is implied: peer-ids
    are public.

    Canonicalization: the two peer-ids **byte-wise sorted ascending**, joined
    with ``SEP`` between them (``lo ‖ SEP ‖ hi``).

    Both halves are load-bearing. The sort makes ``pair(A,B) == pair(B,A)``, so
    either peer may derive first. The separator disambiguates: bare
    concatenation makes ``sorted("ab","c")`` and ``sorted("a","bc")`` both yield
    ``abc``, so two *different* pairs would share one bucket.
    """
    a, b = peer_a.encode("utf-8"), peer_b.encode("utf-8")
    lo, hi = (a, b) if a <= b else (b, a)
    return derive(MODE_PAIR, lo + bytes([SEP]) + hi)


def tag_key(label: str) -> Hash:
    """``tag`` — anyone who knows the label meets.

    A **public** discovery convenience, explicitly **not** access control: the
    label is guessable by design.

    The label is byte-exact UTF-8: no case-folding and **no Unicode
    normalization**. §2.2.1 names normalization "the likeliest accidental
    import — many string libs do it by default", so this encodes ``str`` to
    UTF-8 and hands the bytes over untouched.
    """
    return derive(MODE_TAG, label.encode("utf-8"))


def secret_key(secret: str) -> Hash:
    """``secret`` — anyone who knows the string meets, so knowing it *is* a
    lightweight admission gate.

    **Only as strong as its entropy** (§2.2). A short, human-memorable phrase is
    enumerable — anyone who guesses it lands in the same bucket — and is really
    a :func:`tag_key` wearing a different name. A ``secret`` used as a gate MUST
    be a generated high-entropy string exchanged verbatim. Even then it
    *introduces*; it never authorizes: the resulting connection still runs the
    ordinary handshake and capability flow.
    """
    return derive(MODE_SECRET, secret.encode("utf-8"))


def lobby_key(lobby_constant: str) -> Hash:
    """``lobby`` — "just connect me to anyone here, right now."

    Pass the pool's constant:
    :data:`~entity_handlers.signaling.constants.LOBBY_DEFAULT` unless the node's
    ``advertise`` published an override, in which case pass that.
    """
    return derive(MODE_LOBBY, lobby_constant.encode("utf-8"))


# ---------------------------------------------------------------------------
# Parsing a key back off the wire
# ---------------------------------------------------------------------------


def key_from_wire(raw: bytes) -> Hash:
    """Accept 33 key bytes from a foreign client, rejecting a wrong width.

    This is the §2.2.1 "fixed format code" check at the edge: an otherwise
    correct SHA-384 implementation produces a 49-byte key and passes every other
    differential property. Refusing it loudly here converts a silent never-meet
    into a visible error at the first request.
    """
    if not isinstance(raw, bytes):
        raise SignalingDecodeError(
            f"rendezvous key must be bytes, got {type(raw).__name__}"
        )
    if len(raw) != RENDEZVOUS_KEY_LEN:
        raise SignalingDecodeError(
            f"rendezvous key must be {RENDEZVOUS_KEY_LEN} bytes, got {len(raw)}"
        )
    return raw
