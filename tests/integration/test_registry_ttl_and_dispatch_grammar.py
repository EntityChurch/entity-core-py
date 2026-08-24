"""`EXTENSION-REGISTRY` v1.13 — the TTL ceiling on both sides, the renew
cascade, and the closed name-dispatch grammar.

Enforcement points for arch's `ROUTING-2026-08-18-o` §4 / `-q` §3 worklist:

- `REG-DISPATCH-GRAMMAR-1` — §4's registry-local matcher is closed and every
  non-`*` byte is a literal. The `x*z` / `x/y/z` row is the one that fails
  against every path-glob implementation; the `a?c` and `a[bc]d` rows are the
  ones that fail against `fnmatch`, which is what this peer used until v1.13.
- `REG-TTL-CEILING-1` / `REG-TTL-CLAMP-1` — `max_ttl` is REQUIRED on a live
  issuer policy, `default_ttl` may not exceed it, and a request above the
  ceiling is **clamped, not refused**.
- `REG-RENEW-TTL-CASCADE-1` (a/b/c) + `REG-RENEW-TTL-NULLPRED-1` — the
  three-step cascade and its terminal `403`.
- The resolver's own ceiling, which is the half that protects the consumer.

**Why the clamp rows assert on the binding and not on the status.** A peer that
refuses instead of clamping also returns a non-`200`, so the two are
indistinguishable from the response code alone — the spec says this outright
and it is the reason each row reads the issued binding's `ttl` back out of the
content store.
"""

from __future__ import annotations

import time as _time
import unicodedata

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.protocol.entity import Entity
from entity_handlers.registry import name_glob_match

from tests.integration.test_registry import (  # reuse the pinned harness
    _call,
    _emit,
    _emit_issuer_policy,
    _emit_resolver_config,
    _register_data,
    _sign_into_store,
    peer,  # noqa: F401 — pytest fixture
)

_DAY = 86_400_000
_YEAR = 365 * _DAY

#: Fixed so a binding seeded twice content-addresses to the same bytes — the
#: byte-identical-hash gate below is meaningless if the fixture moves.
_FIXED_TARGET = Keypair.generate().peer_id


# ===========================================================================
# REG-DISPATCH-GRAMMAR-1 — §4, the closed name matcher
# ===========================================================================


class TestDispatchGrammar:
    """§4 `[MUST, v1.13]` — `*` is the only metacharacter and `/` is not a
    separator."""

    @pytest.mark.parametrize(
        "pattern,name,expected",
        [
            # The four ruled rows.
            ("a?c", "a?c", True),
            ("a?c", "abc", False),
            ("a[bc]d", "a[bc]d", True),
            ("a[bc]d", "abd", False),
            ("*@*.*", "alice@example.com", True),
            ("x*z", "x/y/z", True),
            # The rest of the grammar, stated rather than inferred.
            ("*", "", True),
            ("*", "anything/at/all", True),
            ("alice", "alice", True),
            ("alice", "alice.lab", False),      # anchored at both ends
            ("*.lab", "billslab.lab", True),
            ("*.lab", "bills.labx", False),
            ("a*", "a", True),                  # `*` matches the empty run
            ("*a*a*a*", "banana", True),        # many stars, no pathological blowup
            ("\\d", "\\d", True),               # backslash is a literal, not an escape
            ("\\d", "d", False),
        ],
    )
    def test_the_grammar_rows(self, pattern, name, expected):
        assert name_glob_match(pattern, name) is expected

    def test_the_row_that_fails_against_every_path_glob(self):
        """`x*z` matches `x/y/z`. Go's `path.Match` and Python's `glob`-style
        segment matchers both stop `*` at `/` and answer False here."""
        assert name_glob_match("x*z", "x/y/z")

    def test_the_rows_that_fail_against_fnmatch(self):
        """The control for the *previous* implementation. `fnmatch` grants `?`
        and `[…]` character-class meaning this grammar does not, so it answers
        True on both of these — which is how the wrong matcher looks from
        inside a suite that never spelled a `?`."""
        import fnmatch

        assert fnmatch.fnmatchcase("abc", "a?c") is True      # what we used to do
        assert name_glob_match("a?c", "abc") is False         # what the ruling says
        assert fnmatch.fnmatchcase("abd", "a[bc]d") is True
        assert name_glob_match("a[bc]d", "abd") is False

    def test_no_pattern_is_invalid(self):
        """§4 `[MUST]` — a registry MUST NOT reject a pattern for containing
        `?`, `[` or `\\`. There is no write-time validator to pair with this
        matcher, which is the deliberate difference from `EXTENSION-REVISION`'s
        four forms. Nothing here raises."""
        for pattern in ("a?c", "a[bc]d", "\\", "[", "]", "**", "*a*b*"):
            assert isinstance(name_glob_match(pattern, "subject"), bool)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pattern,name,matches", [
        ("a?c", "a?c", True),      # `?` matches itself
        ("a?c", "abc", False),     # ...and nothing else — `fnmatch` says True
        ("a[bc]d", "a[bc]d", True),
        ("a[bc]d", "abd", False),  # `fnmatch` says True
        ("*@*.*", "alice@example.com", True),
        ("*@*.*", "plainhandle", False),   # anchored, not a substring form
    ])
    async def test_the_filter_uses_the_matcher_end_to_end(
        self, peer, pattern, name, matches,  # noqa: F811
    ):
        """The matcher reaching `_dispatch_allows` is what matters — a
        conformant helper wired to nothing is not a fix.

        **This test pins the grammar AND the §4.1 step 2 filter reading
        together, and cannot separate them.** `entity-core-go` pulled their
        equivalent *wire* check for exactly this reason: observing "the pattern
        did not match" requires observing an **exclusion**, and whether a
        non-match excludes was the contested filter question (SA-PY-17) — so a
        check that claimed to measure the matcher was measuring the filter, and
        it went green go-on-go while failing a conformant rust.

        **Both halves are now ruled** (REGISTRY 1.14 filter + 1.15 matcher), so
        these rows no longer straddle an open question. The wire vector stays
        pulled until all three seats have landed the filter branch — arch's
        sequencing, `ROUTING-2026-08-19-a` §4 — and the grammar's own
        cross-impl check is `registry_issuer.name_constraints_grammar`, which
        this peer passes 32/32.
        """
        target = Keypair.generate().peer_id
        await _call(
            peer, "bind", {"name": name, "target_peer_id": target},
            uri="system/registry/local-name",
        )
        _emit_resolver_config(
            peer,
            [{"backend_kind": "local-name", "priority": 0}],
            dispatch=[{"pattern": pattern, "backend_kinds": ["local-name"]}],
        )
        r = await _call(peer, "resolve", {"name": name})
        assert r["result"]["data"]["status"] == (
            "resolved" if matches else "chain_exhausted"
        )

    @pytest.mark.asyncio
    async def test_a_kind_named_by_no_entry_is_excluded_when_another_matches(
        self, peer,  # noqa: F811
    ):
        """Edge case **A**, **RULED 2026-08-19** (REGISTRY 1.14) — and
        SA-PY-17's argument for it is what arch adopted as the ruling's
        rationale: a kind named in **no** entry being consulted anyway makes
        §4.1a's privacy MUST *evadable by leaving a row out*. A `dns-txt`
        backend nobody mentioned would see every bare name a user types, which
        is a larger disclosure than the one the rule forbids.

        rust read it the other way and owes the flip; this peer did too until
        2026-08-18. **The v1.14 widening is what closes the door properly** —
        the MUST now binds the whole configuration, not the catch-all row, so
        the omission route is shut at load as well as here (see
        `test_registry_name_privacy.py`).
        """
        target = Keypair.generate().peer_id
        await _call(
            peer, "bind", {"name": "alice", "target_peer_id": target},
            uri="system/registry/local-name",
        )
        _emit_resolver_config(
            peer,
            [{"backend_kind": "local-name", "priority": 0}],
            # `local-name` is named by nothing; the entry that matches names a
            # different kind entirely.
            dispatch=[{"pattern": "*", "backend_kinds": ["did-web"]}],
        )
        r = await _call(peer, "resolve", {"name": "alice"})
        assert r["result"]["data"]["status"] == "chain_exhausted"

    @pytest.mark.asyncio
    async def test_an_empty_dispatch_list_filters_nothing(self, peer):  # noqa: F811
        """The floor both readings agree on, and the control for the two rows
        above: without it they pass against a peer that resolves nothing."""
        target = Keypair.generate().peer_id
        await _call(
            peer, "bind", {"name": "alice", "target_peer_id": target},
            uri="system/registry/local-name",
        )
        _emit_resolver_config(peer, [{"backend_kind": "local-name", "priority": 0}])
        r = await _call(peer, "resolve", {"name": "alice"})
        assert r["result"]["data"]["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_a_slash_bearing_name_and_pattern_are_ordinary_literals(self, peer):  # noqa: F811
        """`x*z` on `x/y/z` — `/` is not a separator. A name with a `/` is
        unbindable (§6.3), so the only thing asserted is that the peer treats
        both `/`s as ordinary bytes and answers cleanly; the crossing itself is
        pinned by the unit rows."""
        _emit_resolver_config(
            peer,
            [{"backend_kind": "local-name", "priority": 0}],
            dispatch=[{"pattern": "x*z", "backend_kinds": ["local-name"]}],
        )
        r = await _call(peer, "resolve", {"name": "x/y/z"})
        assert r["result"]["data"]["status"] == "chain_exhausted"


# ===========================================================================
# REG-NAME-CONSTRAINTS-GRAMMAR-1 — §6a.9.1, the SECOND call site
# ===========================================================================


class TestNameConstraintsGrammar:
    """§6a.9.1 + §4 `[MUST, v1.15]` — `name_constraints` uses §4's matcher,
    because **there is one matcher per registry**.

    **Why these rows exist even though the matcher above is already pinned.**
    The defect this class closes is not a wrong matcher; it is a **call site
    pointed at the wrong function** while the matcher beside it is correct.
    Until 2026-08-19 the only `name_constraints` test in this repo used
    `*.lab` — the spec's own example, which is grammar-identical under every
    candidate reading. Arch says that is *why the divergence survived review*,
    and it is why a control-only fixture at a call site is not coverage: swap
    the call at `registry.py` to `fnmatch` and every pre-existing
    `name_constraints` assertion still passes.

    This is an **admission gate**, so the observable is `403 not_entitled`
    versus a signed, published binding — two registries running the same
    operator policy admitting different names. `entity-core-rust` was measured
    on row 1 the other way on 2026-08-19 (`a?c` admitted `abc`) and owes the
    v1.15 landing; go and py both pass 32/32.

    **Row 3 (`x*z` admits `x/y/z`) is absent by construction, not by
    omission.** §6.3 forbids `/` in a name and `_validate_name_path_safety`
    runs *before* admission, so no register-request can carry one — the
    property is pinned at the matcher in `TestDispatchGrammar`, and go's
    spec-issue `2026-08-19-b` routes the §11.1 row upstream.
    """

    @staticmethod
    async def _register(peer, name, *, nonce):
        kp = Keypair.generate()
        data = _register_data(kp.peer_id, name, nonce=nonce)
        _sign_into_store(peer, kp, "system/registry/register-request", data)
        return await _call(peer, "register-request", data)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("constraint,admitted,refused", [
        # Row 1 — `?` is a literal. Inverted under `path.Match` / `fnmatch`.
        ("a?c", "a?c", "abc"),
        # Row 2 — `[…]` is three literals, not a character class.
        ("a[bc]d", "a[bc]d", "abd"),
        # Control — the spec's own example. Passes under BOTH readings and
        # proves nothing alone; here so a failure of the rows above cannot be
        # misread as `name_constraints` being ignored entirely.
        ("*.lab", "alice.lab", "alice.dev"),
    ])
    async def test_the_admission_rows(
        self, peer, constraint, admitted, refused,  # noqa: F811
    ):
        _emit_issuer_policy(peer, "open", name_constraints=constraint)

        ok = await self._register(peer, admitted, nonce=b"\x31" * 16)
        assert ok["status"] == 200

        no = await self._register(peer, refused, nonce=b"\x32" * 16)
        assert no["status"] == 403
        assert no["result"]["data"]["code"] == "not_entitled"

    @pytest.mark.asyncio
    async def test_row_4_a_malformed_glob_is_a_literal_and_never_a_5xx(self, peer):  # noqa: F811
        """Row 4 — `name_constraints: "a[b"`. **Asserted separately from row 2
        because a shell-glob implementation fails this one by *erroring*, not by
        answering wrongly**, and an error is not a wrong answer that a
        result-asserting check would catch. §4: *no pattern is invalid*, so
        `set-issuer-policy` stores it and the literal name `a[b` is admitted.

        Driven through the **operation** rather than a direct entity write,
        because the accept half is a claim about `set-issuer-policy`.

        **What this row does and does not discriminate — measured, not
        assumed.** It catches a `path.Match`-family implementation, which
        returns `ErrBadPattern` on an unterminated `[` (that is the
        `500 internal_error` arm `entity-core-go` deleted at v1.15), and it
        catches a write-time validator added later on the theory that `a[b` is
        malformed. It does **not** catch Python's `fnmatch`: `fnmatchcase`
        treats an unterminated `[` as a literal and answers exactly as this
        grammar does, so a mutation of the call site to `fnmatch` leaves this
        row green. **Rows 1 and 2 are the ones that go red on that mutation**
        — verified by running it, not predicted. Per `AGENTS.md`: when a
        mutation is caught by a different test than the one whose docstring
        claimed to be sharp, the prediction is the finding, and the docstring
        is what gets corrected.
        """
        set_r = await _call(peer, "set-issuer-policy", {
            "mode": "open", "name_constraints": "a[b",
            "default_ttl": _DAY, "max_ttl": _YEAR,
        })
        assert set_r["status"] == 200
        stored = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
        assert stored["name_constraints"] == "a[b"

        ok = await self._register(peer, "a[b", nonce=b"\x33" * 16)
        assert ok["status"] == 200

        # And the literal is anchored: `a[b`'s only match is itself. A shell
        # glob raises or treats `[b` as an unterminated class; neither answers
        # 200 here and then 403 below.
        no = await self._register(peer, "ab", nonce=b"\x34" * 16)
        assert no["status"] == 403
        assert no["result"]["data"]["code"] == "not_entitled"

    def test_the_admission_gate_calls_the_one_matcher_by_name(self):
        """§4 v1.15's actual sentence — *"there is one matcher per registry"* —
        pinned as **identity at the call site**, which is a different claim from
        the behavioural rows above and is the one this field's history calls
        for.

        Behavioural agreement is the weaker claim: two functions can agree on
        every row a suite spells and diverge on the first one it does not,
        which is exactly how `name_constraints` and
        `name_format_dispatch[].pattern` drifted apart in three
        implementations while every test stayed green. So this reads the
        admission function's own source and asserts the call, not the answer.

        A source assertion is unusual here and is justified by what it caught:
        an earlier version of this test asserted `name_glob_match` and
        `_dispatch_allows` behaviour instead, and a mutation of the admission
        call site to `fnmatch` left it **green** — it never reached the site it
        was named for.

        **And the first draft of the source check failed on its own comment.**
        The call site *explains* that it used to be `fnmatch`, so a bare
        substring search over the source read that prose as a violation — the
        same inflation the presentation-tier gate hit counting `entity://` in
        docstrings (`AGENTS.md`). A gate that cannot tell a sanctioned mention
        from a smuggled call is not a gate, so this strips comments first.
        """
        import inspect

        import entity_handlers.registry as reg

        src = inspect.getsource(reg._handle_register_request)
        code = "\n".join(
            line.split("#", 1)[0] for line in src.splitlines()
        )
        assert "name_glob_match(" in code, (
            "the §6a.9.1 admission gate must call §4's matcher (v1.15)"
        )
        assert "fnmatch" not in code, (
            "a shell-glob at the admission gate is the v1.15 divergence"
        )


# ===========================================================================
# REG-TTL-CEILING-1 — the issuer side
# ===========================================================================


class TestIssuerCeiling:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode,extra", [
        ("open", {}), ("allowlist", {"allowlist": ["p1"]}), ("manual", {}),
    ])
    async def test_a_live_policy_without_max_ttl_is_refused(self, peer, mode, extra):  # noqa: F811
        """`REG-TTL-CEILING-1` — `400`, and the policy is not stored.

        Every mode that can reach *approve* is covered: "live" is the property
        that triggers the rule, and `manual` reaches approve by a slower route.
        `default_ttl` is supplied so the refusal is attributable to `max_ttl`
        and not to D11 one line up.
        """
        good = {"mode": "open", "default_ttl": _DAY, "max_ttl": _YEAR}
        assert (await _call(peer, "set-issuer-policy", good))["status"] == 200

        r = await _call(peer, "set-issuer-policy",
                        {"mode": mode, "default_ttl": _DAY, **extra})
        assert r["status"] == 400
        # ...and the refused write did not overwrite the good policy.
        got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
        assert got["max_ttl"] == _YEAR, "the refused policy was stored anyway"

    @pytest.mark.asyncio
    async def test_default_ttl_above_the_ceiling_is_refused(self, peer):  # noqa: F811
        """`REG-TTL-CEILING-1` row 2 — `default_ttl <= max_ttl` `[MUST]`."""
        r = await _call(peer, "set-issuer-policy", {
            "mode": "open", "default_ttl": _YEAR, "max_ttl": _DAY,
        })
        assert r["status"] == 400
        assert (await _call(peer, "get-issuer-policy", {}))["status"] == 404

    @pytest.mark.asyncio
    async def test_the_control_a_policy_with_both_is_accepted(self, peer):  # noqa: F811
        """The acceptance control. A rejection row without one passes
        trivially against a peer that refuses everything
        (`GUIDE-CONFORMANCE` §2.4a)."""
        r = await _call(peer, "set-issuer-policy", {
            "mode": "open", "default_ttl": _DAY, "max_ttl": _YEAR,
        })
        assert r["status"] == 200
        assert r["result"]["data"]["max_ttl"] == _YEAR
        got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
        assert got["default_ttl"] == _DAY and got["max_ttl"] == _YEAR

    @pytest.mark.asyncio
    async def test_equal_is_permitted(self, peer):  # noqa: F811
        """`MUST NOT exceed` — equality is not an excess."""
        r = await _call(peer, "set-issuer-policy", {
            "mode": "open", "default_ttl": _DAY, "max_ttl": _DAY,
        })
        assert r["status"] == 200


# ===========================================================================
# REG-TTL-CLAMP-1 — clamped, not refused
# ===========================================================================


def _binding(peer, h):  # noqa: F811
    return peer.content_store.get(bytes(h))


class TestClamp:
    @pytest.mark.asyncio
    async def test_a_register_above_the_ceiling_is_clamped(self, peer):  # noqa: F811
        """`REG-TTL-CLAMP-1` — accepted `200`, and the issued binding carries
        **exactly** `max_ttl`.

        Asserted on the binding rather than the status because a peer that
        refuses instead of clamping also returns a non-200 — the two are
        indistinguishable from the response code alone.
        """
        _emit_issuer_policy(peer, "open", default_ttl=_DAY, max_ttl=_DAY)
        kp = Keypair.generate()
        data = _register_data(kp.peer_id, "greedy.lab", requested_ttl=_YEAR)
        _sign_into_store(peer, kp, "system/registry/register-request", data)

        r = await _call(peer, "register-request", data)
        assert r["status"] == 200, "a request above the ceiling was refused, not clamped"
        assert _binding(peer, r["result"]["data"]["binding_hash"]).data["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_a_renew_above_the_ceiling_is_clamped(self, peer):  # noqa: F811
        """`REG-TTL-CLAMP-1`, the second producer. The cascade resolves first,
        the ceiling applies after."""
        _emit_issuer_policy(peer, "open", default_ttl=_DAY, max_ttl=_DAY)
        kp = Keypair.generate()
        data = _register_data(kp.peer_id, "renewer.lab")
        _sign_into_store(peer, kp, "system/registry/register-request", data)
        bh = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]

        renew = {"binding_hash": bh, "ttl": _YEAR,
                 "nonce": b"\x33" * 16, "issued_at": int(_time.time() * 1000)}
        _sign_into_store(peer, kp, "system/registry/renew-request", renew)
        r = await _call(peer, "renew-request", renew)
        assert r["status"] == 200
        assert _binding(peer, r["result"]["data"]["binding_hash"]).data["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_a_request_below_the_ceiling_is_untouched(self, peer):  # noqa: F811
        """The teeth control: a peer that clamped *everything* to `max_ttl`
        would pass both rows above."""
        _emit_issuer_policy(peer, "open", default_ttl=_DAY, max_ttl=_YEAR)
        kp = Keypair.generate()
        data = _register_data(kp.peer_id, "modest.lab", requested_ttl=60_000)
        _sign_into_store(peer, kp, "system/registry/register-request", data)
        r = await _call(peer, "register-request", data)
        assert _binding(peer, r["result"]["data"]["binding_hash"]).data["ttl"] == 60_000

    @pytest.mark.asyncio
    async def test_the_manual_queue_records_the_clamped_terms(self, peer):  # noqa: F811
        """The clamp runs **before** the queue, so the head records the terms
        the operator is being asked to approve. A queue holding the unclamped
        ask would issue above the ceiling on approval, weeks later, with
        nothing in the path re-checking it."""
        _emit_issuer_policy(peer, "manual", default_ttl=_DAY, max_ttl=_DAY)
        kp = Keypair.generate()
        data = _register_data(kp.peer_id, "queued.lab", requested_ttl=_YEAR)
        _sign_into_store(peer, kp, "system/registry/register-request", data)

        r = await _call(peer, "register-request", data)
        assert r["status"] == 202
        ph = bytes(r["result"]["data"]["pending_hash"])
        assert peer.content_store.get(ph).data["requested_ttl"] == _DAY


# ===========================================================================
# REG-RENEW-TTL-CASCADE-1 + REG-RENEW-TTL-NULLPRED-1
# ===========================================================================


def _seed_curated_binding(peer, kp, name, *, ttl):  # noqa: F811
    """Write a peer-issued binding straight to the tree + by-name index.

    This is the out-of-band seeding path §6a.9.2's store-first resolution
    admits and the only way to reach `ttl: null` now that the handler refuses
    to mint one — the same two-stage shape as `REG-ISSUER-DOMAINCTRL-STORED-1`.
    """
    binding = Entity(type="system/registry/binding", data={
        "name": unicodedata.normalize("NFC", name),
        "kind": "peer-issued",
        "target_peer_id": kp.peer_id,
        "transports": [],
        "issued_at": int(_time.time() * 1000),
        "ttl": ttl,
    })
    bh = binding.compute_hash()
    _emit(peer, f"system/registry/binding/{bh.hex()}", binding)
    _emit(peer, f"system/registry/binding/by-name/{name}", binding)
    return bh


async def _renew(peer, kp, bh, *, ttl=None, nonce=b"\x44" * 16):  # noqa: F811
    data = {"binding_hash": bh, "nonce": nonce,
            "issued_at": int(_time.time() * 1000)}
    if ttl is not None:
        data["ttl"] = ttl
    _sign_into_store(peer, kp, "system/registry/renew-request", data)
    return await _call(peer, "renew-request", data)


class TestRenewCascade:
    """§6a.9.1 `[MUST, v1.9-v1.10]` — request `ttl`, then the policy's
    `default_ttl`, then **the superseded binding's** `ttl`."""

    @pytest.mark.asyncio
    async def test_row_a_explicit_ttl_wins(self, peer):  # noqa: F811
        kp = Keypair.generate()
        bh = _seed_curated_binding(peer, kp, "a.lab", ttl=_DAY)
        r = await _renew(peer, kp, bh, ttl=60_000)
        assert r["status"] == 200
        assert _binding(peer, r["result"]["data"]["binding_hash"]).data["ttl"] == 60_000

    @pytest.mark.asyncio
    async def test_row_b_a_curated_registry_inherits_the_predecessor(self, peer):  # noqa: F811
        """The row that fails against **both** a null-minting peer and a
        refusing peer — and the one this repo filed as SA-PY-13.

        No issuer policy at all: a curated registry is conformant per §6a.9.2
        and has no `default_ttl` to fall back on, so before v1.9 this minted a
        successor with `ttl: null` — a binding §6a.3 forbids and §6a.4 will not
        resolve. Step 3 is a *recovery* of the registry's own prior signed act,
        not an invented default, which is why it creates no determinism split.
        """
        kp = Keypair.generate()
        bh = _seed_curated_binding(peer, kp, "inherit.lab", ttl=_DAY)
        r = await _renew(peer, kp, bh)
        assert r["status"] == 200, "a curated renew with no ttl was refused"
        new = _binding(peer, r["result"]["data"]["binding_hash"])
        assert new.data["ttl"] == _DAY, "the successor did not inherit the predecessor"
        # ...and it is a successor, not a fresh mint: §6a.4's `require
        # binding.ttl != null` is what a null here would have failed.
        assert bytes(new.data["supersedes"]) == bytes(bh)

    @pytest.mark.asyncio
    async def test_row_c_the_policy_outranks_the_predecessor(self, peer):  # noqa: F811
        """Current operator intent outranks history: an operator who *lowers*
        `default_ttl` sees renewals pick it up. This is the row that fails
        against a peer that implemented inherit-first."""
        kp = Keypair.generate()
        bh = _seed_curated_binding(peer, kp, "policy.lab", ttl=_DAY)
        _emit_issuer_policy(peer, "open", default_ttl=60_000, max_ttl=_YEAR)
        r = await _renew(peer, kp, bh)
        assert r["status"] == 200
        assert _binding(peer, r["result"]["data"]["binding_hash"]).data["ttl"] == 60_000

    @pytest.mark.asyncio
    async def test_nullpred_all_three_steps_null_refuses(self, peer):  # noqa: F811
        """`REG-RENEW-TTL-NULLPRED-1` `[MUST, v1.10]` — `403 policy_rejected`,
        nothing published.

        v1.9 asserted this branch unreachable *because* §6a.3 guarantees step
        3. That reads an invariant as a fact about stored bytes: a predecessor
        carrying `ttl: null` can be already there, and an implementation that
        merely guards the dereference falls through and mints exactly the shape
        the whole rule set exists to prevent. Enforced, not asserted —
        precisely because nothing conformant reaches it.
        """
        kp = Keypair.generate()
        before = len(list(peer.entity_tree.list_prefix(
            peer.entity_tree.normalize_uri("system/registry/binding/"))))
        bh = _seed_curated_binding(peer, kp, "nullpred.lab", ttl=None)
        after_seed = len(list(peer.entity_tree.list_prefix(
            peer.entity_tree.normalize_uri("system/registry/binding/"))))
        assert after_seed > before

        r = await _renew(peer, kp, bh)
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "policy_rejected"
        # MUST publish nothing — no successor binding landed.
        after = len(list(peer.entity_tree.list_prefix(
            peer.entity_tree.normalize_uri("system/registry/binding/"))))
        assert after == after_seed, "a successor was published by a refused renew"


# ===========================================================================
# The resolver's own ceiling — the half that protects the consumer
# ===========================================================================


class TestResolverCeiling:
    """`REG-TTL-RESOLVER-CEILING-1` `[v1.16]` — the four rows, plus the two
    teeth the wire vector cannot reach.

    §6a.9.1: the effective lifetime is `min(binding.ttl, local_max)` computed
    at resolution from `resolver_chain[].hints.max_ttl`, **never written
    back** — and a binding carrying **no** `ttl` takes `local_max`.

    | row | fixture | expected |
    |---|---|---|
    | (a) | `ttl` above the ceiling | effective lifetime is exactly `max_ttl`, binding hash unchanged |
    | (b) | `ttl` below the ceiling | returned untouched |
    | (c) | `hints.max_ttl: 0` | identical to an absent `hints` — the binding's own `ttl` survives |
    | (d) | sticky binding, no `ttl` | effective lifetime is `max_ttl` |

    **Row (d) is the one this peer failed on a live wire vector** (go
    `v4c_ttl_resolver_ceiling`, 2026-08-19) while 3820 local tests stayed
    green — and the reason is in the fixtures, not the code. Every row above
    was seeded with a `local-name` binding carrying an explicit `ttl`, which
    is a shape the **bind path never mints** (`_handle_bind` writes
    `ttl: None`, sticky until removed). So the whole class exercised the arm
    `min` has an answer for and never the arm production actually produces —
    the two-representations law with the *fixture* on the wrong side of it.
    `test_the_bind_path_mints_the_sticky_shape` pins that the seeded shape and
    the minted shape now agree.
    """

    def _seed(self, peer, *, ttl, ceiling, issued_at=None):  # noqa: F811
        binding = Entity(type="system/registry/binding", data={
            "name": "ceiling.lab", "kind": "local-name",
            "target_peer_id": _FIXED_TARGET, "transports": [],
            "issued_at": issued_at if issued_at is not None else int(_time.time() * 1000),
            "ttl": ttl,
        })
        _emit(peer, "system/registry/binding/local-name/ceiling.lab", binding)
        self._set_ceiling(peer, ceiling)
        return binding

    @staticmethod
    def _set_ceiling(peer, ceiling):  # noqa: F811
        entry = {"backend_kind": "local-name", "priority": 0}
        if ceiling is not None:
            entry["hints"] = {"max_ttl": ceiling}
        _emit_resolver_config(peer, [entry])

    @pytest.mark.asyncio
    async def test_the_surfaced_ttl_is_clamped(self, peer):  # noqa: F811
        self._seed(peer, ttl=_YEAR, ceiling=_DAY)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["status"] == "resolved"
        assert d["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_the_binding_hash_is_byte_identical_clamped_and_unclamped(self, peer):  # noqa: F811
        """The gate that matters, and it is `entity-browser-rust`'s framing:
        assert the *hash*, not the number.

        If a refactor ever wrote the clamped TTL back into the binding, the
        content address moves and every signature over it stops verifying —
        the property that would rot silently. Asserting the clamped value
        catches none of that.
        """
        # One binding, two resolver configs — the binding is never rewritten,
        # so any hash movement is the resolver's doing and nothing else's.
        binding = self._seed(peer, ttl=_YEAR, ceiling=None)
        d1 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        self._set_ceiling(peer, _DAY)
        d2 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]

        stored = peer.content_store.get(bytes(d2["binding"]))
        assert stored.data["ttl"] == _YEAR, "the clamped ttl was written back"
        assert bytes(d2["binding"]) == binding.compute_hash()
        assert bytes(d1["binding"]) == bytes(d2["binding"]), (
            "the resolver wrote its ceiling back into the binding"
        )
        assert d1["ttl"] == _YEAR and d2["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_a_ceiling_below_the_binding_age_expires_it(self, peer):  # noqa: F811
        """The actual security property: the *effective lifetime* is bounded,
        so a binding a hostile byte-server would keep serving past its useful
        life stops resolving here. A resolver that clamped only the surfaced
        number would still honor it."""
        kp = Keypair.generate()  # noqa: F841 — target only
        binding = Entity(type="system/registry/binding", data={
            "name": "stale.lab", "kind": "local-name",
            "target_peer_id": Keypair.generate().peer_id, "transports": [],
            "issued_at": int(_time.time() * 1000) - 10 * _DAY, "ttl": _YEAR,
        })
        _emit(peer, "system/registry/binding/local-name/stale.lab", binding)
        _emit_resolver_config(peer, [
            {"backend_kind": "local-name", "priority": 0, "hints": {"max_ttl": _DAY}},
        ])
        d = (await _call(peer, "resolve", {"name": "stale.lab"}))["result"]["data"]
        assert d["status"] != "resolved", "the resolver honored a binding past its ceiling"

    @pytest.mark.asyncio
    async def test_a_zero_ceiling_is_dropped_not_honored(self, peer):  # noqa: F811
        """Honored literally, `0` expires every binding instantly and the
        operator sees *"no binding for this name"* — indistinguishable from a
        bad signature or a revocation. Ruled upheld for `entity-browser-rust`
        at `6927500`."""
        self._seed(peer, ttl=_YEAR, ceiling=0)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["status"] == "resolved"
        assert d["ttl"] == _YEAR

    @pytest.mark.asyncio
    async def test_row_b_a_ttl_below_the_ceiling_is_returned_untouched(self, peer):  # noqa: F811
        """The ceiling is a bound, not a value: a binding that already asks
        for less keeps its own number. A resolver that returned `max_ttl`
        here would be *extending* lifetimes the issuer deliberately kept
        short, which is the control pointed backwards."""
        self._seed(peer, ttl=_DAY, ceiling=_YEAR)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["status"] == "resolved"
        assert d["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_no_ceiling_ships_by_default(self, peer):  # noqa: F811
        """§6a.3's ceiling is a `MAY` and the corpus writes no number, for the
        reason §4.10 writes none: there is no defensible constant, and choosing
        one makes every unconfigured deployment look configured. Shipping no
        default is conformance, not incompleteness."""
        self._seed(peer, ttl=_YEAR, ceiling=None)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["ttl"] == _YEAR

    @pytest.mark.asyncio
    async def test_the_ceiling_is_read_at_resolution_and_never_latched(self, peer):  # noqa: F811
        """`REG-TTL-CEILING-REREAD-1` `[v1.17]` — durable configuration read
        **at resolution**, not a process-lifetime setting fixed at
        construction.

        rust's argument, which decided this cohort-wide: a ceiling read at
        start-up applies on a cold boot and silently does not on a warm one,
        and *a control present on one boot path and absent on the other is
        worse than absent — it tests green on whichever path the test happens
        to take.* So the discriminating fixture is **one process, three
        configs**: a latched implementation answers the first one three times,
        and no amount of restarting-the-peer testing would show it.

        **This check was specified `[v1.17]` and was not constructible** — the
        state it needs is a running peer whose `resolver-config` has been
        rewritten, and no operation existed to do that. §4.3's
        `set-resolver-config` is its enabling surface, which is why the rows
        below go through the **wire operation** rather than an emit: an
        in-process seed would exercise a path a conformance client cannot
        reach, and the missing operation is exactly what made this check and
        §4.1 step 2's write-time MUST unbuildable *together*.
        """
        self._seed(peer, ttl=_YEAR, ceiling=None)
        r1 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        await self._set_ceiling_over_the_wire(peer, _DAY)
        r2 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        await self._set_ceiling_over_the_wire(peer, 2 * _DAY)
        r3 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert [r1["ttl"], r2["ttl"], r3["ttl"]] == [_YEAR, _DAY, 2 * _DAY], (
            "the ceiling was latched — an operator editing resolver-config on a "
            "running peer is not obeyed"
        )

    @staticmethod
    async def _set_ceiling_over_the_wire(peer, ceiling):  # noqa: F811
        """Rebind the ceiling through §4.3's operation, as a conformance client
        must. `hints` is opaque backend config, so this round-trips a whole
        config rather than patching a field."""
        entry = {"backend_kind": "local-name", "priority": 0, "hints": {"max_ttl": ceiling}}
        cfg = Entity(type="system/registry/resolver-config", data={
            "resolver_chain": [entry],
            "pinned_bindings": [],
            "name_format_dispatch": [],
        })
        r = await _call(peer, "set-resolver-config", {
            "config": cfg.to_dict(include_hash=False),
        })
        assert r["status"] == 200, r
        return r

    # -- row (d): the sticky arm, which is the shape production mints --------

    @pytest.mark.asyncio
    async def test_row_d_a_sticky_binding_takes_the_ceiling_as_its_lifetime(self, peer):  # noqa: F811
        """`min(binding.ttl, local_max)` has **no arm for a null `ttl`**, and
        the sticky kinds (`local-name`, `pinned`) carry none — so a guard
        written `if isinstance(ttl, int)` applies the control only where a
        bound already exists and leaves the unbounded case uncovered. That is
        the inversion §6a.9.1 v1.16 rules out, and it is what this peer did
        until `_effective_lifetime`.
        """
        self._seed(peer, ttl=None, ceiling=_DAY)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["status"] == "resolved"
        assert d["ttl"] == _DAY, (
            "a sticky binding under a ceiling surfaced no lifetime — the guard "
            "that only clamps a present ttl skips exactly the unbounded case"
        )

    @pytest.mark.asyncio
    async def test_row_d_teeth_the_sticky_arm_bounds_honoring_and_not_just_the_number(
        self, peer,  # noqa: F811
    ):
        """**The row the wire vector cannot see.** go's `v4c` reads the
        surfaced `ttl` off a *freshly bound* name, so an implementation that
        stamps `local_max` into the result and never feeds it to the expiry
        check passes the vector and still honors a sticky binding forever.
        The security property is the honoring, so assert on that: a sticky
        binding older than the ceiling MUST stop resolving.
        """
        binding = Entity(type="system/registry/binding", data={
            "name": "stickystale.lab", "kind": "local-name",
            "target_peer_id": _FIXED_TARGET, "transports": [],
            "issued_at": int(_time.time() * 1000) - 10 * _DAY, "ttl": None,
        })
        _emit(peer, "system/registry/binding/local-name/stickystale.lab", binding)

        # Control first: with no ceiling a sticky binding never expires, so the
        # refusal below is attributable to the ceiling and not to the age.
        self._set_ceiling(peer, None)
        d0 = (await _call(peer, "resolve", {"name": "stickystale.lab"}))["result"]["data"]
        assert d0["status"] == "resolved" and d0["ttl"] is None

        self._set_ceiling(peer, _DAY)
        d = (await _call(peer, "resolve", {"name": "stickystale.lab"}))["result"]["data"]
        assert d["status"] != "resolved", (
            "the resolver surfaced a bounded ttl but honored the binding anyway "
            "— the ceiling reached the response and not the expiry verdict"
        )

    @pytest.mark.asyncio
    async def test_row_d_under_c_a_zero_ceiling_leaves_a_sticky_binding_sticky(self, peer):  # noqa: F811
        """Rows (c) and (d) interact, and this is the pair that would make a
        `0` ceiling maximally destructive: undeclared means the sticky arm
        does not fire either, so the binding keeps its null lifetime rather
        than being handed `0` and expiring instantly."""
        self._seed(peer, ttl=None, ceiling=0)
        d = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        assert d["status"] == "resolved"
        assert d["ttl"] is None

    @pytest.mark.asyncio
    async def test_row_d_the_ceiling_is_still_not_written_back(self, peer):  # noqa: F811
        """Row (a)'s hash gate, on the sticky arm — where it is easier to get
        wrong, because `local_max` is a value the binding never carried at all
        and a "fill in the missing ttl" refactor reads as helpful."""
        binding = self._seed(peer, ttl=None, ceiling=None)
        d1 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]
        self._set_ceiling(peer, _DAY)
        d2 = (await _call(peer, "resolve", {"name": "ceiling.lab"}))["result"]["data"]

        stored = peer.content_store.get(bytes(d2["binding"]))
        assert stored.data["ttl"] is None, "the ceiling was written into the binding"
        assert bytes(d2["binding"]) == binding.compute_hash()
        assert bytes(d1["binding"]) == bytes(d2["binding"])
        assert d1["ttl"] is None and d2["ttl"] == _DAY

    @pytest.mark.asyncio
    async def test_the_bind_path_mints_the_sticky_shape(self, peer):  # noqa: F811
        """The fixture-vs-production check this class was missing. Every other
        row seeds a binding by hand; if the seeded shape ever stops matching
        what `bind` actually writes, the class goes back to testing an arm no
        deployment reaches. `local-name` bindings are sticky (§6.3: *"ttl:
        null — local-names are sticky until the user removes them"*), so the
        sticky arm is the **default** path through this code, not an edge."""
        r = await _call(
            peer, "bind", {"name": "minted.lab", "target_peer_id": _FIXED_TARGET},
            uri="system/registry/local-name",
        )
        assert r["status"] == 200
        stored = peer.content_store.get(bytes(r["result"]["data"]["binding_hash"]))
        assert stored.data["kind"] == "local-name"
        assert stored.data["ttl"] is None, (
            "bind now mints a ttl-bearing local-name — the ceiling rows above "
            "seed a shape production no longer produces"
        )
