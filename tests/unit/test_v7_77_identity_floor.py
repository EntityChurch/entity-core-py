"""V7 v7.77 §4.5a item 1a — the ``system/peer`` identity entity is pinned to
the ECFv1-SHA-256 floor unconditionally.

The exception this file guards: §1.2 says a peer's persistent state is
*uniformly* its home format, and §4.5a item 1 says the wire/identity surface
is authored under the connection's *active* format. The identity entity obeys
neither. Its data is wholly recoverable from the public peer-id, so every
consumer **derives** its hash rather than fetching it (``[derive-to-meet]``,
``SPECIFICATION-FORMAT.md`` §8.4.6) — pinning makes the derived form and the
authored form one value on every connection in the network, instead of two
that coincide only while the active format happens to be the floor.

Item 4 names the failure mode precisely: *two* derivation functions. So the
structural half of this file matters as much as the value half — there is one
constructor, and it takes no format parameter to disagree about.
"""

from __future__ import annotations

import contextlib

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import (
    compute_peer_identity_hash,
    create_identity_entity,
    create_peer_entity,
)
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    get_default_hash_algorithm,
    set_default_hash_algorithm,
)


@contextlib.contextmanager
def _home_format(code: int):
    """Boot the process under a non-floor home format and restore after."""
    prev = get_default_hash_algorithm()
    set_default_hash_algorithm(code)
    try:
        yield
    finally:
        set_default_hash_algorithm(prev)


def test_identity_entity_is_floor_under_a_sha384_home():
    """A SHA-384-home peer authors its own ``system/peer`` at 0x00."""
    kp = Keypair.generate()
    with _home_format(ALG_ECFV1_SHA384):
        # Guard: the home format really is non-floor in this block, so a
        # passing assertion below cannot be the floor default sneaking through.
        assert get_default_hash_algorithm() == ALG_ECFV1_SHA384
        h = create_identity_entity(kp).compute_hash()
    assert h[0] == ALG_ECFV1_SHA256
    assert len(h) == 33


def test_identity_hash_is_invariant_across_home_formats():
    """One identity, one hash — the whole point of item 1a. The bytes a
    SHA-384 peer authors are the bytes a SHA-256 peer derives."""
    kp = Keypair.generate()
    with _home_format(ALG_ECFV1_SHA384):
        under_384 = create_identity_entity(kp).compute_hash()
    with _home_format(ALG_ECFV1_SHA256):
        under_256 = create_identity_entity(kp).compute_hash()
    assert under_384 == under_256


def test_peer_entity_from_pubkey_is_floor_pinned():
    """The remote-peer constructor (pubkey in hand, no Keypair) is pinned too —
    this is the reconstruct-a-grantee path in the connect handler."""
    kp = Keypair.generate()
    with _home_format(ALG_ECFV1_SHA384):
        ent = create_peer_entity(kp.public_key_bytes(), kp.key_type)
        assert ent.compute_hash()[0] == ALG_ECFV1_SHA256
    # …and it agrees with the keypair-side constructor, byte for byte.
    assert ent.compute_hash() == create_identity_entity(kp).compute_hash()


def test_derive_to_meet_and_author_are_one_function():
    """§4.5a item 4: *an implementation that derives an identity hash for a
    path segment and compares an authored identity hash is using one function,
    and that is the conformant shape — two functions is the defect.*"""
    kp = Keypair.generate()
    authored = create_identity_entity(kp).compute_hash()
    derived_from_pubkey = compute_peer_identity_hash(
        public_key=kp.public_key_bytes(), key_type=kp.key_type,
    )
    derived_from_peer_id = compute_peer_identity_hash(
        peer_id=kp.peer_id, key_type=kp.key_type,
    )
    assert authored == derived_from_pubkey == derived_from_peer_id
    with _home_format(ALG_ECFV1_SHA384):
        assert compute_peer_identity_hash(peer_id=kp.peer_id) == authored


def test_identity_constructor_takes_no_format_parameter():
    """The parameter was **deleted**, not defaulted. Defaulting it would leave
    every old call site a silent no-op; deleting it made each one a hard
    failure that had to be read and re-decided. This test keeps it deleted —
    a well-meant ``algorithm=`` kwarg re-added here would reopen the two-value
    split without failing anything else."""
    kp = Keypair.generate()
    with pytest.raises(TypeError):
        create_identity_entity(kp, algorithm=ALG_ECFV1_SHA384)  # type: ignore[call-arg]
