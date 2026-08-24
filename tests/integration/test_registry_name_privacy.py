"""`EXTENSION-REGISTRY` §4.1 step 2 + §4.3 — a **name-transmitting** backend
MUST NOT be made eligible for an **unscoped** name, and the rule binds the
**write**, not the load.

`REG-DISPATCH-CONFIG-REFUSED-1` `[v1.17]` plus the load-side surfacing MUST.
The model settled on 2026-08-19 (arch `05faaa5`, REGISTRY v1.17/v1.18) and it
moved this file's subject twice, so both moves are recorded here:

1. **Kind-scoped, not chain-scoped** `[MUST, v1.17]`. A broad rule naming
   `did-web` violates whether or not the chain carries a `did-web` entry. We
   filed the opposite reading (SA-PY-21) and were ruled against, on an argument
   we had not made: the MUST binds a **distribution**, and under chain-scoping
   *"this shipped config is safe"* is not a property of the shipped artifact —
   it is a property of the artifact paired with whatever a downstream operator
   later adds. **You cannot hold a party to a property they cannot evaluate.**
2. **The MUST binds the write** `[MUST, v1.17]`, because at load a
   distribution's seed and an operator's deliberate edit are one entity at one
   path (§6a.9.2 store-first) — indistinguishable by construction. So §11.1's
   *"refused or normalized at load"* is **withdrawn**, and this peer's
   load-time normalizer came out. At load: **surface it, never normalize it,
   never refuse to start** — refusing to boot would delete the operator `MAY`
   granted in the same paragraph.

**Why the old vector could not settle any of this, which is the lesson under
the ruling.** `REG-DISPATCH-CATCHALL-LOCAL-1`'s observable is *the absence of a
request* to a third party — and a kind absent from the chain transmits nothing
under **either** reading, so the question of what the MUST binds was
unmeasurable by the check written for it. §4.3's `set-resolver-config` is the
surface that makes it measurable, and it did not exist: `registry-configure`
named an act the corpus never defined.
"""

from __future__ import annotations

import logging

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.entity import Entity
from entity_handlers.registry import (
    NAME_TRANSMITTING_KINDS,
    _pattern_reaches_unscoped_name,
)

from tests.integration.test_registry import (  # reuse the pinned harness
    _call,
    _emit_resolver_config,
    _emit_signed_binding,
    _peerissued_config,
    _peerissued_fixture,
    _pin_registry,
    _registry_mod,
    peer,  # noqa: F401 — pytest fixture
)


def _chain(*kinds):
    """A chain entry per kind, each accepting its own trust anchor."""
    return [
        {
            "backend_kind": k,
            "priority": i,
            "backend_id": f"b-{k}",
            "accepted_trust_anchors": [k.replace("-", "_"), f"peer_issued:b-{k}"],
        }
        for i, k in enumerate(kinds)
    ]


def _config(chain, dispatch=None):
    """A `resolver-config` entity, as a caller would submit it to §4.3."""
    return Entity(
        type="system/registry/resolver-config",
        data={
            "resolver_chain": chain,
            "pinned_bindings": [],
            "name_format_dispatch": dispatch or [],
        },
    )


async def _set_config(peer, config, *, acknowledge=None):  # noqa: F811
    params = {"config": config.to_dict(include_hash=False)}
    if acknowledge is not None:
        params["acknowledge_name_disclosure"] = acknowledge
    return await _call(peer, "set-resolver-config", params)


async def _get_config(peer):  # noqa: F811
    return await _call(peer, "get-resolver-config", {})


# ===========================================================================
# The classifier — which patterns reach a bare name
# ===========================================================================


class TestUnscopedReach:
    """A pattern is **narrow** only when it pins an authority: an `@` the user
    typed, a `:` scheme prefix, or a dotted **literal** suffix the star cannot
    reach into. Everything else is broad."""

    @pytest.mark.parametrize("pattern,reaches", [
        ("*", True),                    # the catch-all, the usual door
        ("", True),                     # matches only the empty name, still bare
        ("alice", True),                # a literal bare name is still a bare name
        ("a*e", True),                  # stars take the empty run: `ae`
        ("*.eth", False),               # §4.1a row 3: ENS — the rule pins ENS
        ("*@*.*", False),               # §4.1a rows 4-5: the user pins the authority
        ("did:web:*", False),           # §4.1a rows 1-2: scheme prefix
        ("*lab*", True),                # no marker anywhere ⇒ `lab` matches
    ])
    def test_the_rows(self, pattern, reaches):
        assert _pattern_reaches_unscoped_name(pattern) is reaches

    @pytest.mark.parametrize("pattern", ["*.*", "*.e*", "a.b", "alice.eth"])
    def test_the_rows_where_this_peer_moved_and_a_sibling_did_not(self, pattern):
        """**SA-PY-23 — the live cross-impl divergence, pinned as rows so it is
        visible rather than latent.**

        Until 2026-08-19 this peer classified on a different argument, and a
        sound one: under the closed grammar every name a pattern matches
        carries all of the pattern's literal bytes, so a literal `.` anywhere
        means *every* match is dotted — making `*.*` and `a.b` scoped.
        `entity-core-go` calls both **broad**. §4.1a's default list classifies
        identically under both readings, so **the one fixture the spec ships
        cannot tell them apart** — the shape this repo has now met four times.

        We moved to the strictly larger broad-set on §4.1's own asymmetry
        argument: a false positive is a visible edit with a documented override
        (`acknowledge_name_disclosure`), and a false negative sends
        `my.private.handle` and every dotted typo to a third party. `*.*` pins
        no authority at all — its suffix is a star — which is the substantive
        half; `a.b` is the residue, and it is the row we would still argue
        about.
        """
        assert _pattern_reaches_unscoped_name(pattern) is True

    def test_an_unclassifiable_pattern_fails_broad(self):
        """`entity-browser-rust`'s argument, now the cohort's: *"a pattern we
        cannot confidently classify is treated as broad, because calling a
        broad pattern narrow is what leaks."*"""
        for junk in (None, 42, ["*"], {}):
            assert _pattern_reaches_unscoped_name(junk) is True

    def test_peer_issued_is_not_name_transmitting(self):
        """The v1.14 retarget: the discriminator is name **transmission**, not
        remoteness. `peer-issued` is remote and name-blind (§6a.4 walks a
        signed root by content address); putting it here would make §4.1a row 6
        — which recommends it in the catch-all — violate its own list."""
        assert NAME_TRANSMITTING_KINDS == {
            "dns-txt", "well-known-url", "did-web", "consensus-anchored",
        }
        assert "peer-issued" not in NAME_TRANSMITTING_KINDS
        assert "local-name" not in NAME_TRANSMITTING_KINDS


# ===========================================================================
# REG-DISPATCH-CONFIG-REFUSED-1 — the write surface (§4.3), six rows
# ===========================================================================


class TestSetResolverConfigRefusesDisclosure:
    """The check that can settle kind-scoped, because it reads the **stored
    config** rather than the absence of a request."""

    @pytest.mark.asyncio
    async def test_row_a_a_broad_row_naming_the_kind_is_refused(self, peer):  # noqa: F811
        r = await _set_config(
            peer,
            _config(_chain("did-web"), [{"pattern": "*", "backend_kinds": ["did-web"]}]),
        )
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "policy_rejected"

    @pytest.mark.asyncio
    async def test_row_b_the_kind_scoped_discriminator(self, peer):  # noqa: F811
        """**The row that decides the ruling, and the only one that does.**
        A broad rule naming `did-web` with **no `did-web` chain entry**:
        kind-scoped refuses, chain-scoped accepts (nothing would be consulted).
        Every other row in this class scores identically under both readings —
        which is exactly why the old request-absence vector could not settle
        it, and why this peer shipped the losing reading for two days without
        any instrument noticing.
        """
        r = await _set_config(
            peer,
            _config(_chain("local-name"), [{"pattern": "*", "backend_kinds": ["did-web"]}]),
        )
        assert r["status"] == 403, (
            "a broad row naming a kind the chain does not carry was accepted — "
            "that is the chain-scoped reading, ruled against at v1.17"
        )
        assert r["result"]["data"]["code"] == "policy_rejected"

    @pytest.mark.asyncio
    async def test_row_c_no_dispatch_list_with_the_kind_in_the_chain_is_refused(
        self, peer,  # noqa: F811
    ):
        """Door B. An absent/empty `name_format_dispatch` disables the filter
        entirely, so every kind is eligible for every name and there is no row
        to inspect — the door the pre-v1.14 one-row rule could not reach."""
        r = await _set_config(peer, _config(_chain("did-web"), []))
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "policy_rejected"

    @pytest.mark.asyncio
    async def test_row_d_the_control_a_scoped_row_is_accepted(self, peer):  # noqa: F811
        """**Narrowing, not banning.** Without this row every assertion above
        is satisfied by a peer that refuses every config naming a
        name-transmitting kind at all — which would delete the eligibility
        §4.1 step 2 exists to express."""
        cfg = _config(
            _chain("did-web"), [{"pattern": "did:web:*", "backend_kinds": ["did-web"]}],
        )
        r = await _set_config(peer, cfg)
        assert r["status"] == 200
        assert (await _get_config(peer))["result"]["data"] == cfg.data

    @pytest.mark.asyncio
    async def test_row_e_a_refusal_writes_nothing_and_the_prior_bytes_stand(
        self, peer,  # noqa: F811
    ):
        """**No partial application, asserted on the stored bytes.**

        A peer that accepts-then-rewrites and a peer that refuses both return a
        non-success on some path, so the status alone cannot tell them apart —
        only the stored config can. This is also SA-PY-22's answer, which arch
        dissolved into a rule at every configuration surface: **a resolver MUST
        NOT rewrite stored configuration as a side effect of reading it.**
        """
        good = _config(
            _chain("did-web"), [{"pattern": "did:web:*", "backend_kinds": ["did-web"]}],
        )
        assert (await _set_config(peer, good))["status"] == 200
        before = (await _get_config(peer))["result"]["data"]

        bad = _config(_chain("did-web"), [{"pattern": "*", "backend_kinds": ["did-web"]}])
        assert (await _set_config(peer, bad))["status"] == 403

        after = (await _get_config(peer))["result"]["data"]
        assert after == before
        assert (
            Entity(type="system/registry/resolver-config", data=after).compute_hash()
            == good.compute_hash()
        ), "the refused config, or a rewritten one, reached the store"

    @pytest.mark.asyncio
    async def test_row_f_the_override_arm_is_the_operator_may(self, peer):  # noqa: F811
        """**Without this row a peer that refuses unconditionally scores
        identically to a conformant one.** The `MAY` is what the whole
        write-time model exists to keep alive: an operator on their own peer
        may configure exactly this, deliberately, and say so."""
        cfg = _config(_chain("did-web"), [{"pattern": "*", "backend_kinds": ["did-web"]}])
        assert (await _set_config(peer, cfg))["status"] == 403
        r = await _set_config(peer, cfg, acknowledge=True)
        assert r["status"] == 200
        assert (await _get_config(peer))["result"]["data"] == cfg.data

    @pytest.mark.asyncio
    async def test_the_acknowledgement_never_enters_the_stored_bytes(self, peer):  # noqa: F811
        """`[MUST]` — the acknowledgement is a parameter of the operation and
        MUST NOT become a field of the entity. A field would be written by
        whoever writes the bytes, so a distribution could set it and defeat the
        rule that bounds it; and it would move a content-addressed type's hash
        to carry a claim it cannot secure. **Provenance is a property of the
        act**, which is why it rides a capability-gated call and why load-time
        enforcement could never honor the `MAY`.
        """
        cfg = _config(_chain("did-web"), [{"pattern": "*", "backend_kinds": ["did-web"]}])
        assert (await _set_config(peer, cfg, acknowledge=True))["status"] == 200
        stored = (await _get_config(peer))["result"]["data"]
        assert "acknowledge_name_disclosure" not in stored
        assert (
            Entity(type="system/registry/resolver-config", data=stored).compute_hash()
            == cfg.compute_hash()
        ), "the stored config's address moved — the ack rode the bytes"

    @pytest.mark.asyncio
    async def test_the_refusal_carries_every_violation_not_the_first(self, peer):  # noqa: F811
        """§4.3 `[MUST]` — *"every violation, not the first, because an operator
        repairing a chain wants the whole list."* A one-at-a-time refusal turns
        one edit into N round-trips, each of which looks like a new problem."""
        r = await _set_config(peer, _config(
            _chain("did-web", "dns-txt"),
            [
                {"pattern": "*", "backend_kinds": ["did-web", "dns-txt"]},
                {"pattern": "alice*", "backend_kinds": ["well-known-url"]},
            ],
        ))
        assert r["status"] == 403
        violations = r["result"]["data"]["violations"]
        assert len(violations) == 3
        assert {"did-web", "dns-txt", "well-known-url"} == {
            k for k in ("did-web", "dns-txt", "well-known-url")
            if any(k in v for v in violations)
        }

    @pytest.mark.asyncio
    async def test_get_is_404_when_unset_and_never_the_synthesized_default(
        self, peer,  # noqa: F811
    ):
        """**Unset is not empty and is not the default.** `_load_resolver_config`
        synthesizes a local-name-only chain so an unconfigured peer resolves its
        own names (§10) — returning that here would tell an operator their write
        landed when nothing was stored. Same call as `get-issuer-policy`'s."""
        r = await _get_config(peer)
        assert r["status"] == 404
        assert r["result"]["data"]["code"] == "not_found"


# ===========================================================================
# SA-PY-24 — the new operation writes a field §5 gives its own capability
# ===========================================================================


class TestSetResolverConfigAlsoWritesThePins:
    """**A known gap, pinned as behaviour rather than left as prose** —
    SA-PY-24, filed against §4.3 the day it landed.

    §5's capability table gives `pinned_bindings` **its own capability**
    (`system/capability/registry-pin`, *"who may add or remove pins"*), separate
    from `registry-configure`. §4.3's `set-resolver-config` is gated by
    `registry-configure` alone and writes the **whole config**, pins included.
    So the holder of the weaker capability can now mint pins.

    **And pins are the stronger thing by a distance:** §4.1 step 1 returns a
    synthesized pin *before* the step-2 dispatch filter and before any chain
    entry, so a pin bypasses the name-disclosure control this whole file is
    about **and** the §6a.9.1 resolver ceiling. The rows below demonstrate it
    on one peer: under a config whose filter admits nothing, a bare name is
    `chain_exhausted` and the pinned name resolves anyway.

    **The separation was never enforceable, which is the more useful half.**
    Before §4.3 both caps were declared as bare tree-writes against the *same*
    content-addressed entity — and an entity is written whole, so no layer
    could ever have distinguished "edits pins" from "edits config". §4.3 is the
    first surface where the distinction could be made real (an authorization
    check on the `pinned_bindings` delta) or honestly withdrawn. This peer does
    neither on purpose: inventing the check locally would refuse a client
    `entity-core-go` `5655494` accepts, which is a cross-impl divergence
    manufactured out of a spec gap.
    """

    @pytest.mark.asyncio
    async def test_a_configure_holder_can_write_pins_today(self, peer):  # noqa: F811
        target = Keypair.generate().peer_id
        cfg = _config(_chain("local-name"), [{"pattern": "nomatch", "backend_kinds": []}])
        cfg.data["pinned_bindings"] = [{"name": "alice", "target_peer_id": target}]

        assert (await _set_config(peer, cfg))["status"] == 200
        assert (await _get_config(peer))["result"]["data"]["pinned_bindings"] == [
            {"name": "alice", "target_peer_id": target},
        ]

    @pytest.mark.asyncio
    async def test_and_a_pin_short_circuits_every_control_in_this_file(self, peer):  # noqa: F811
        """The teeth: same peer, same config, two names. The filter admits no
        backend for either, so `chain_exhausted` is the honest answer — and the
        pinned name resolves regardless, which is what makes the merged
        capability a privilege escalation rather than a tidiness question."""
        target = Keypair.generate().peer_id
        cfg = _config(_chain("local-name"), [{"pattern": "nomatch", "backend_kinds": []}])
        cfg.data["pinned_bindings"] = [{"name": "alice", "target_peer_id": target}]
        assert (await _set_config(peer, cfg))["status"] == 200

        pinned = (await _call(peer, "resolve", {"name": "alice"}))["result"]["data"]
        other = (await _call(peer, "resolve", {"name": "bob"}))["result"]["data"]
        assert other["status"] == "chain_exhausted"
        assert pinned["status"] == "resolved"
        assert pinned["peer_id"] == target


# ===========================================================================
# The load side — surface, never normalize, never refuse to start
# ===========================================================================


class TestLoadSurfacesAndHonors:
    """`[MUST, v1.17]`. Every row here asserted the **opposite** until
    2026-08-19: this peer narrowed the offending rows in the loaded view, so a
    violating config resolved to `chain_exhausted`. That was §11.1's
    *"normalized at load"*, now withdrawn — the peer was making the operator's
    stored bytes lie."""

    @pytest.mark.asyncio
    async def test_a_seeded_violating_config_is_honored_and_surfaced(
        self, peer, caplog,  # noqa: F811
    ):
        """The out-of-band seed path — a direct tree write, carrying no
        acknowledgement, which is the case that keeps §4.3 from being security
        theatre: the documented path is controlled and the undocumented one is
        **loud** rather than blocked."""
        target = Keypair.generate().peer_id
        _emit_signed_binding(peer, peer.keypair, "alice", target, kind="dns-txt")
        _emit_resolver_config(
            peer, _chain("dns-txt"),
            dispatch=[{"pattern": "*", "backend_kinds": ["dns-txt"]}],
        )

        with caplog.at_level(logging.WARNING, logger="entity_handlers.registry"):
            r = await _call(peer, "resolve", {"name": "alice"})

        assert r["result"]["data"]["status"] == "resolved", (
            "the loaded config was normalized — the operator's bytes say this "
            "backend is eligible and the peer silently disagreed"
        )
        assert any("§4.1 step 2" in m for m in caplog.messages), (
            "a violating config was honored with no diagnostic — surfacing is "
            "the whole obligation at load"
        )

    @pytest.mark.asyncio
    async def test_the_stored_config_is_not_rewritten_by_being_read(self, peer):  # noqa: F811
        """The general rule SA-PY-22 became: **a resolver MUST NOT rewrite
        stored configuration as a side effect of reading it.** Read the config
        back after a resolution has loaded it and compare the address, not the
        fields — a rewrite that preserved every field would still move the
        hash, and that is the failure a field-wise assertion misses."""
        cfg = _config(_chain("did-web"), [{"pattern": "*", "backend_kinds": ["did-web"]}])
        assert (await _set_config(peer, cfg, acknowledge=True))["status"] == 200
        before = peer.entity_tree.get(
            peer.entity_tree.normalize_uri("system/registry/resolver-config"))

        await _call(peer, "resolve", {"name": "alice"})

        after = peer.entity_tree.get(
            peer.entity_tree.normalize_uri("system/registry/resolver-config"))
        assert bytes(after) == bytes(before) == bytes(cfg.compute_hash())

    @pytest.mark.asyncio
    async def test_a_violating_config_does_not_stop_the_peer_answering(self, peer):  # noqa: F811
        """*"Never refuse to start."* A peer that will not run on a config the
        operator deliberately wrote has revoked the override it was granted —
        so the local-name backend keeps answering beside the offending row."""
        target = Keypair.generate().peer_id
        await _call(
            peer, "bind", {"name": "alice", "target_peer_id": target},
            uri="system/registry/local-name",
        )
        _emit_resolver_config(
            peer, _chain("did-web", "local-name"),
            dispatch=[{"pattern": "*", "backend_kinds": ["did-web", "local-name"]}],
        )
        r = await _call(peer, "resolve", {"name": "alice"})
        assert r["result"]["data"]["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_the_control_a_conformant_config_surfaces_nothing(
        self, peer, caplog,  # noqa: F811
    ):
        """The teeth control. Without it every surfacing assertion above is
        satisfied by a peer that logs the diagnostic unconditionally, which is
        a diagnostic carrying no information."""
        target = Keypair.generate().peer_id
        _emit_signed_binding(
            peer, peer.keypair, "alice@example.com", target, kind="dns-txt",
        )
        _emit_resolver_config(
            peer, _chain("dns-txt"),
            dispatch=[{"pattern": "*@*.*", "backend_kinds": ["dns-txt"]}],
        )
        with caplog.at_level(logging.WARNING, logger="entity_handlers.registry"):
            r = await _call(peer, "resolve", {"name": "alice@example.com"})
        assert r["result"]["data"]["status"] == "resolved"
        assert not any("§4.1 step 2" in m for m in caplog.messages)

    @pytest.mark.asyncio
    async def test_the_shipped_default_is_compliant_by_construction(
        self, peer, caplog,  # noqa: F811
    ):
        """An unconfigured peer synthesizes a local-name-only chain with an
        empty dispatch list — door B's exact shape, compliant because
        `local-name` transmits nothing. **The case that must not regress:** a
        rule that fired on the default peer would simply be turned off."""
        target = Keypair.generate().peer_id
        await _call(
            peer, "bind", {"name": "alice", "target_peer_id": target},
            uri="system/registry/local-name",
        )
        with caplog.at_level(logging.WARNING, logger="entity_handlers.registry"):
            r = await _call(peer, "resolve", {"name": "alice"})
        assert r["result"]["data"]["status"] == "resolved"
        assert not any("§4.1 step 2" in m for m in caplog.messages)

    @pytest.mark.asyncio
    async def test_the_control_a_remote_peer_issued_backend_is_never_flagged(
        self, peer, monkeypatch, caplog,  # noqa: F811
    ):
        """**The v1.14 retarget in one row.** Same door B shape — an empty
        dispatch list — and no violation, because a §6a.4 resolution walks a
        signed root **by content address**: remote, unfiltered, name-blind, and
        recommended in §4.1a row 6's own catch-all."""
        registry_kp = Keypair.generate()
        target = Keypair.generate().peer_id
        reader, _ = _peerissued_fixture(registry_kp, "billslab.com", target)
        _pin_registry(peer, registry_kp)
        _peerissued_config(peer, registry_kp)          # writes an EMPTY dispatch list
        monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

        with caplog.at_level(logging.WARNING, logger="entity_handlers.registry"):
            r = await _call(peer, "resolve", {"name": "billslab.com"})
        d = r["result"]["data"]
        assert d["status"] == "resolved"
        assert d["peer_id"] == target
        assert not any("§4.1 step 2" in m for m in caplog.messages)
