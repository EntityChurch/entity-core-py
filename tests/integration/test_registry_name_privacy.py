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
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.entity import Entity
from entity_handlers.registry import (
    ENUMERATED_TYPED_SUFFIXES,
    NAME_TRANSMITTING_KINDS,
    _pattern_reaches_unscoped_name,
)

from tests.integration.test_registry import (  # reuse the pinned harness
    _call,
    _ctx,
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
    """§4.1b's classifier `[MUST, v1.19]` — **NARROW iff** (a) no `*`, (b) a
    literal `@`, (c) the literal head before the first `*` ends in `:`, or (d)
    the pattern ends in an **enumerated** typed suffix (§4.1b.1). Otherwise
    BROAD, i.e. it can match at least one bare name."""

    @pytest.mark.parametrize("pattern,reaches", [
        ("*", True),                    # the catch-all, the usual door
        ("a*e", True),                  # stars take the empty run: `ae`
        ("*lab*", True),                # no marker anywhere ⇒ `lab` matches
        ("*.eth", False),               # (d) §4.1a row 3: ENS, enumerated
        ("*@*.*", False),               # (b) §4.1a rows 4-5: the user names it
        ("*@*", False),                 # (b) §4.1a row 5
        ("did:web:*", False),           # (c) §4.1a rows 1-2: scheme prefix
        ("did:key:*", False),           # (c)
    ])
    def test_the_rows(self, pattern, reaches):
        assert _pattern_reaches_unscoped_name(pattern) is reaches

    @pytest.mark.parametrize("pattern", ["did:web:*", "did:key:*", "*.eth",
                                         "*@*.*", "*@*"])
    def test_every_non_catch_all_row_of_the_shipped_default_is_narrow(self, pattern):
        """**The fixture that has to hold, and the one to run first.** §4.1a is
        a list this spec SHOULD-ships *and* the MUST lives inside it — so a
        classifier that called any of rows 1-5 broad would make the recommended
        default violate its own rule, and one that called row 6 narrow would
        delete the rule. Row 6 is asserted broad in `test_the_rows`."""
        assert _pattern_reaches_unscoped_name(pattern) is False

    @pytest.mark.parametrize("pattern,broad", [
        ("*.*", True),      # `.` is not a typed suffix — `billslab.com` is bare
        ("*.e*", True),     # trailing `*` ⇒ no fixed suffix
        ("*.lab", True),    # `.lab` is NOT enumerated — MOVED, see below
        ("a.b", False),     # (a) exactly one name — MOVED, see below
        ("alice.eth", False),  # (a), and also (d)
        ("alice", False),   # (a) — MOVED, see below
        ("", False),        # (a) — no `*`, so exactly one name (the empty one)
    ])
    def test_the_rows_the_v1_19_ruling_moved(self, pattern, broad):
        """**SA-PY-23 ruled — `EXTENSION-REGISTRY` §4.1b, v1.19.** The predicate
        this file turns on had **no grammar** until then, and the seats reached
        three answers from one sentence. Two of ours moved, in opposite
        directions, and both are worth naming because the direction is the
        interesting part:

        * **`a.b` / `alice` / `""` were BROAD here and are NARROW by (a).** We
          had no rule (a): an exact literal went through the same marker scan as
          a wildcard, so a pattern that can only ever match the single name the
          operator typed out was refused as a disclosure risk. A false positive,
          and the cheap direction to be wrong in — which is exactly why it
          survived.
        * **`*.lab` was NARROW here and is BROAD by (d)**, because `.lab` is not
          in §4.1b.1's enumerated list. This is the security-relevant half. Our
          reading was *"a dotted literal suffix the star cannot reach into pins
          an authority"* — and the ruling argues the opposite at length:
          *"any literal at all"* is **not** the line, because `.` narrows almost
          nothing when `billslab.com` is a legal bare local name (§6a). The line
          is *does the literal identify an authority or a naming system*, which
          is why the suffix list is enumerated, MUST grow only by spec revision,
          and makes an unrecognized suffix broad.

        `*.*` and `*.e*` stay broad and are the rows we got right ahead of the
        grammar — moved on §4.1's asymmetry argument (a false positive is a
        visible edit with a documented override; a false negative is
        `my.private.handle` going to a third party), which the ruling reaches by
        its own route. **Being right about the answer is not being right about
        the rule**, and it is the rule that decides `*.lab`.
        """
        assert _pattern_reaches_unscoped_name(pattern) is broad

    def test_the_enumerated_suffix_list_is_exactly_what_the_spec_enumerates(self):
        """§4.1b.1 `[MUST]` — one row, `.eth`. **Pinned as a row of its own
        because growing this tuple is a privacy decision, not a config
        change**: each entry declares that every name a user types ending in it
        may be handed to a third party. Not implementation-defined, not
        operator-extensible, not inferable. A seat that "helpfully" adds
        `.sol` / `.crypto` fails here, which is the point."""
        assert ENUMERATED_TYPED_SUFFIXES == (".eth",)

    def test_a_scheme_colon_only_counts_in_the_head(self):
        """Rule (c) is *"the literal head **before the first `*`** ends in
        `:`"*, not *"a `:` appears somewhere"* — which is what this peer
        checked before v1.19. The difference is only visible on a pattern
        whose `:` sits behind a star, where the matching name carries no
        guaranteed scheme position at all."""
        assert _pattern_reaches_unscoped_name("*:x") is True
        assert _pattern_reaches_unscoped_name("*.foo:bar") is True
        assert _pattern_reaches_unscoped_name("did:web:*") is False

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
# Row 7 — the §4.1b classifier, driven through the write surface
# ===========================================================================


class TestTheClassifierOnTheWriteSurface:
    """`REG-DISPATCH-CONFIG-REFUSED-1` **row 7** `[v1.19]`, the same five
    patterns `entity-core-go`'s `v15` drives.

    Every row here names `did-web` **with a `did-web` chain entry present**, so
    the chain is constant and the *only* thing deciding accept-versus-refuse is
    §4.1b's classification of the pattern. That is deliberate: the unit rows in
    `TestUnscopedReach` prove the predicate, and these prove the predicate is
    the one the **write path** actually consults. A peer can hold a correct
    classifier and call it from nowhere — this repo's own fourth
    validator-versus-consumer instance — and rows a-f above cannot see it,
    because they all use `*`, which every candidate reading calls broad.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,refused", [
        ("*.*", True),
        ("*.e*", True),
        ("*.lab", True),     # the row that moved: `.lab` is not enumerated
        ("*.eth", False),
        ("a.b", False),      # the row that moved: no `*` ⇒ exactly one name
    ])
    async def test_row_7(self, peer, pattern, refused):  # noqa: F811
        cfg = _config(
            _chain("local-name", "did-web"),
            [{"pattern": pattern, "backend_kinds": ["did-web"]}],
        )
        r = await _set_config(peer, cfg)
        if refused:
            assert r["status"] == 403, (
                f"a BROAD pattern {pattern!r} naming did-web was accepted — it "
                f"discloses every bare name matching it (§4.1b)"
            )
            assert r["result"]["data"]["code"] == "policy_rejected"
        else:
            assert r["status"] == 200, (
                f"a NARROW pattern {pattern!r} was refused — it discloses "
                f"nothing and §4.1b says it MUST be accepted"
            )


# ===========================================================================
# Row 8 — SA-PY-24 ruled: the pin delta needs pin authority
# ===========================================================================


def _cap(*, pin: bool):
    """A caller capability over this handler. `pin=False` is the
    **configure-only** operator: everything §4.3 needs and no pin authority."""
    ops: dict[str, Any] = {"include": ["*"]}
    if not pin:
        ops["exclude"] = ["pin-bindings"]
    return {"grants": [{
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "operations": ops,
    }]}


async def _set_config_as(peer, config, cap, *, acknowledge=None):  # noqa: F811
    """`set-resolver-config` under a specific caller capability — the seam the
    blanket-`*` `_call` harness cannot reach."""
    params: dict[str, Any] = {"config": config.to_dict(include_hash=False)}
    if acknowledge is not None:
        params["acknowledge_name_disclosure"] = acknowledge
    h = peer.handlers.find_handler("system/registry")
    ctx = _ctx(peer, remote="an-operator")
    ctx.caller_capability = cap
    return await h("system/registry", "set-resolver-config", {"data": params}, ctx)


class TestSetResolverConfigPinDeltaRequiresPinCap:
    """**SA-PY-24 — RULED, `EXTENSION-REGISTRY` §4.3 `[MUST, v1.19]`.**

    We filed it the day §4.3 landed: §5 gives `pinned_bindings` its own
    capability (`registry-pin`, *"who may add or remove pins"*), §4.3 gated the
    whole-entity write on `registry-configure` alone, and an entity is written
    whole — so the weaker grant minted pins. **And a pin is the strongest row in
    the file:** §4.1 **step 1** returns it *before* the step-2 disclosure filter
    and *before* the §6a.9.1 resolver ceiling, so it answers a name while
    bypassing both of this extension's controls. A split that lets the less
    specific grant write the more privileged row inverts the model.

    **We shipped no local fix on purpose, and that was the right call.** The
    filing pinned the gap as *behaviour* — one peer, one config, a bare name
    `chain_exhausted` and the pinned name resolving anyway — and inventing the
    delta check locally would have refused a client `entity-core-go` accepted,
    manufacturing a cross-impl divergence out of a spec gap. It is ruled now, so
    the check is conformance rather than invention, and the class flips from
    *"here is the hole"* to *"here is the gate."*

    **What is still unruled is the ENCODING**, and it is why row 8 is here and
    not on the wire. §5 names `registry-pin` descriptively; no rule says how a
    capability *expresses* pin authority. go models it as authority over the
    operation `pin-bindings` and so do we — matching rather than converging,
    because a shared harness minting one seat's encoding would answer `403` to a
    **conformant** peer that checks another, which is a false red on the vector
    rather than a finding. Routed by go as spec-issue `2026-08-20-a`; until it
    rules, this behaviour is teeth-pinned in-tree by these rows.
    """

    @staticmethod
    def _pinned(target, *, pattern="nomatch"):
        cfg = _config(_chain("local-name"), [{"pattern": pattern, "backend_kinds": []}])
        cfg.data["pinned_bindings"] = [{"name": "alice", "target_peer_id": target}]
        return cfg

    @pytest.mark.asyncio
    async def test_a_configure_only_caller_cannot_add_a_pin(self, peer):  # noqa: F811
        target = Keypair.generate().peer_id
        r = await _set_config_as(peer, self._pinned(target), _cap(pin=False))
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "not_entitled"

    @pytest.mark.asyncio
    async def test_and_the_refusal_writes_nothing(self, peer):  # noqa: F811
        """*"Refuse `403 not_entitled` and write nothing"* — the second half of
        the MUST, and the half a check that only reads the status code cannot
        see. A peer that refuses *after* storing has satisfied the code and
        none of the property."""
        target = Keypair.generate().peer_id
        assert (await _get_config(peer))["status"] == 404
        await _set_config_as(peer, self._pinned(target), _cap(pin=False))
        assert (await _get_config(peer))["status"] == 404, (
            "the refused write landed anyway — nothing means nothing"
        )

    @pytest.mark.asyncio
    async def test_a_caller_holding_both_may_write_the_pin(self, peer):  # noqa: F811
        """The teeth control. Without it a peer that refuses *every*
        `set-resolver-config` carrying pins passes the row above, and the
        refusal would be attributable to the pins existing rather than to the
        capability missing."""
        target = Keypair.generate().peer_id
        r = await _set_config_as(peer, self._pinned(target), _cap(pin=True))
        assert r["status"] == 200, r
        assert (await _get_config(peer))["result"]["data"]["pinned_bindings"] == [
            {"name": "alice", "target_peer_id": target},
        ]

    @pytest.mark.asyncio
    async def test_a_byte_identical_pin_list_needs_only_configure(self, peer):  # noqa: F811
        """*"A write that leaves the pin list byte-identical needs only
        `registry-configure`."* The discriminator is the **delta**, not the
        presence of pins — a configure-only operator editing the chain of a
        config that already carries pins must not be locked out of their own
        config."""
        target = Keypair.generate().peer_id
        assert (await _set_config_as(peer, self._pinned(target), _cap(pin=True)))["status"] == 200

        # Same pins, a different dispatch list: configure alone suffices.
        again = self._pinned(target, pattern="also-nomatch")
        r = await _set_config_as(peer, again, _cap(pin=False))
        assert r["status"] == 200, r
        assert (await _get_config(peer))["result"]["data"][
            "name_format_dispatch"
        ] == [{"pattern": "also-nomatch", "backend_kinds": []}]

    @pytest.mark.asyncio
    async def test_removing_a_pin_is_a_change_too(self, peer):  # noqa: F811
        """§5's `registry-pin` is *"who may add **or remove** pins"*. A check
        written as *"are there pins in the submitted config"* passes every row
        above and lets a configure-only caller **delete** the operator's pins —
        which is the direction that reads as harmless and is not: a pin is what
        an operator asserts *against* the resolver chain."""
        target = Keypair.generate().peer_id
        assert (await _set_config_as(peer, self._pinned(target), _cap(pin=True)))["status"] == 200

        bare = _config(_chain("local-name"), [{"pattern": "nomatch", "backend_kinds": []}])
        r = await _set_config_as(peer, bare, _cap(pin=False))
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "not_entitled"
        assert (await _get_config(peer))["result"]["data"]["pinned_bindings"] == [
            {"name": "alice", "target_peer_id": target},
        ]

    @pytest.mark.asyncio
    async def test_the_pin_still_short_circuits_every_control_in_this_file(self, peer):  # noqa: F811
        """**Why the capability split is a privilege question and not a tidiness
        one** — carried over verbatim from the filing, because the ruling did
        not change this and it is the reason the gate exists. Same peer, same
        config, two names: the filter admits no backend for either, so
        `chain_exhausted` is the honest answer — and the pinned name resolves
        regardless."""
        target = Keypair.generate().peer_id
        assert (await _set_config_as(peer, self._pinned(target), _cap(pin=True)))["status"] == 200

        pinned = (await _call(peer, "resolve", {"name": "alice"}))["result"]["data"]
        other = (await _call(peer, "resolve", {"name": "bob"}))["result"]["data"]
        assert other["status"] == "chain_exhausted"
        assert pinned["status"] == "resolved"
        assert pinned["peer_id"] == target

    @pytest.mark.asyncio
    async def test_the_pin_check_runs_before_the_disclosure_check(self, peer):  # noqa: F811
        """**R-27 clause 4 `[MUST]` — the clause arch flagged as the open
        question at this seat**, and we answer it here: authorize, then validate.

        A config that violates **both** — an unauthorized pin delta *and* a broad
        `did-web` row — answers `not_entitled`, never `policy_rejected`. We
        shipped this ordering on our own argument (the two verdicts are different
        kinds: one says *you may not*, the other says *this config may not*, and
        telling an unauthorized caller to set `acknowledge_name_disclosure`
        invites a retry no acknowledgement can authorize).

        **The ruling's second reason is one we did not have, and it is the
        load-bearing one:** §4.3's violation response is deliberately verbose —
        *"every violation, not the first"* — so validating first hands a
        **config-shaped disclosure to a caller who lacks the authority to change
        anything**. The refusal leaks the shape of the stored configuration to
        someone the peer is in the act of refusing. Ordering that was tidiness
        under our argument is an information-disclosure control under theirs.
        """
        target = Keypair.generate().peer_id
        cfg = self._pinned(target)
        cfg.data["name_format_dispatch"] = [{"pattern": "*", "backend_kinds": ["did-web"]}]
        r = await _set_config_as(peer, cfg, _cap(pin=False))
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "not_entitled"

    @pytest.mark.asyncio
    async def test_the_refusal_leaks_no_violation_list_to_an_unauthorized_caller(
        self, peer,  # noqa: F811
    ):
        """The teeth for clause 4's *reason*, which the status code alone does
        not carry. A peer could answer `not_entitled` and still attach the
        violation list it computed — same code, same ordering as far as any
        status assertion can see, and the disclosure happens anyway."""
        target = Keypair.generate().peer_id
        cfg = self._pinned(target)
        cfg.data["name_format_dispatch"] = [{"pattern": "*", "backend_kinds": ["did-web"]}]
        body = (await _set_config_as(peer, cfg, _cap(pin=False)))["result"]["data"]
        assert "violations" not in body, (
            "the authz refusal carried the config-shaped violation list — the "
            "leak clause 4 exists to prevent"
        )
        assert "did-web" not in str(body.get("message", ""))

    @pytest.mark.asyncio
    async def test_pin_bindings_is_not_dispatchable(self, peer):  # noqa: F811
        """**R-27 clause 2 `[MUST]`** — `pin-bindings` is a capability-check
        discriminator and **MUST NOT** be an EXECUTE operation. Nothing routes to
        it and it appears in no operation table.

        Arch pinned this because *"it is the one place a seat could diverge into
        a new wire surface"*: an operation name that is **checkable but not
        callable** is unusual enough that a seat could reasonably wire it up, and
        doing so adds an undeclared operation to the registry handler. We satisfy
        it today by falling through to `404 unknown_operation` — which is
        **correct by accident**, since nothing stops a later refactor from adding
        a route beside the two §4.3 operations it sits next to. That is exactly
        the shape this row exists to catch.
        """
        r = await _call(peer, "pin-bindings", {})
        assert r["status"] == 404
        assert r["result"]["data"]["code"] == "unknown_operation"

    @pytest.mark.asyncio
    async def test_the_delta_survives_an_unmodelled_key_on_a_pin(self, peer):  # noqa: F811
        """**§4.3 says *byte-identical*, not *structurally equal* — and the
        difference is a fail-open on the most privileged row in the file.**

        `entity-core-rust` found this in `entity-core-go` (2026-08-20, fixed at go
        `f44ed4d`): go's compare decoded `pinned_bindings` into a typed struct and
        re-encoded it, which **silently drops any §4.2 forward-compat key a pin
        carries** — so a config that adds or strips one reads as *"no change"* and
        rewrites the pins under `registry-configure` alone.

        **Arch's proposal §5 records that py "decodes to a native mapping and had
        no field-drop". That is a claim about our repo, so it is checked here
        rather than accepted** — a sibling reading our tree from outside can be
        right about the defect and wrong about our shape, and this is the cheap
        direction to verify. Python's decode is into `dict`, so unknown keys
        survive and reach `ecf_encode`; the row proves it against the handler
        instead of arguing it from the language.

        Note what our comparison actually is: **the canonical encoding of the
        decoded pins**, which is the same encoder that fixes the stored entity's
        content hash. So *"equal"* means *"the stored pins' bytes would not
        move"*, which is the property §4.3 is protecting.
        """
        target = Keypair.generate().peer_id
        # Seed a stored pin carrying a key no schema models (§4.2 forward-compat).
        seeded = self._pinned(target)
        seeded.data["pinned_bindings"] = [
            {"name": "alice", "target_peer_id": target, "future_key": "v2-only"},
        ]
        assert (await _set_config_as(peer, seeded, _cap(pin=True)))["status"] == 200

        # Submit the SAME pin with the unmodelled key stripped, configure-only.
        # A field-dropping compare sees "no change" and lets this through.
        stripped = self._pinned(target)
        r = await _set_config_as(peer, stripped, _cap(pin=False))
        assert r["status"] == 403, (
            "stripping an unmodelled key off a pin read as 'no change' — the "
            "decode-round-trip fail-open rust found in go (§4.3 says "
            "byte-identical, not structurally equal)"
        )
        assert r["result"]["data"]["code"] == "not_entitled"
        assert (await _get_config(peer))["result"]["data"]["pinned_bindings"] == [
            {"name": "alice", "target_peer_id": target, "future_key": "v2-only"},
        ], "the unmodelled key did not survive storage, so the row above proves nothing"


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
