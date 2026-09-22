"""§6.3's `check_path_permission` handed a PATTERN subject — the H1 cell no
seat swept, because the subject shape is decided by the CALL SITE.

Found auditing `entity-core-go`'s completed H1 sweep
(``ROUTING-2026-09-11-f``). 0.8.2.21's `G-4` gave §5.2's
``check_resource_scope`` a **pattern arm** — ``patterns_overlap`` +
``is_covered_by`` — because a pattern target spanning a grant exclude was
re-spellable past it. go landed it at ``CheckResourceScope``; this repo landed
it at ``check_resource_scope`` (`58bf7b7`). **Neither seat landed it at
``check_path_permission``**, and the reason is the same at both: §6.3's
subject is *"the path this handler is ABOUT TO TOUCH"*, which reads as
concrete, so the arm looks inapplicable by construction.

.. rubric:: It is not, and the corpus is what makes it reachable

`EXTENSION-SUBSCRIPTION` §2.3 (v3.13) requires, verbatim:

    *"when ``include_payload`` is set, the subscribe handler MUST additionally
    verify the caller's capability covers the tree read —
    ``check_path_permission("get", resource_path, caller_capability,
    "system/tree", local_peer_id)`` — and MUST reject the subscribe with 403
    ``payload_unauthorized`` if it does not."*

The subscribe resource **is a pattern** (§3.1: a subscription is taken out on
a pattern). So the corpus itself routes a pattern into the one path-scope
matcher that has no pattern arm. Handed ``/{p}/data/*`` as the *subject*, the
exclude loop evaluates ``matches_pattern("/{p}/data/secret", "/{p}/data/*")``
— a concrete exclude against a pattern **string** — which is an exact-string
comparison that can never be true. The exclusion carves out nothing.

.. rubric:: What that buys the caller, measured

A grant ``resources: {include: ["data/*"], exclude: ["data/secret"]}`` —
i.e. *everything under data except the secret* — subscribes with
``include_payload: true`` on pattern ``data/*`` and is **accepted**. Delivery
performs no second check (`subscription.py` ``_deliver_notification`` resolves
``event.hash`` from the content store and bundles it), so from then on **the
excluded entity's body is pushed to the subscriber on every write to it**.
Subscribe-time is the only gate, by design (§2.3), and it asked the wrong
question.

Worse than the listing leak on two axes: it is a **push** channel, so the
disclosure is continuous rather than one-shot; and it carries the entity
**body**, not a name and a hash.

.. rubric:: Why the cohort's vector cannot see it

`entity-core-go`'s `include_payload_unauthorized`
(``cmd/internal/validate/subscriptions.go``) mints a **subscribe-only** cap
with *no* ``system/tree`` grant at all and asserts 403. That is the *neither*
arm. The *both* arm (a full ``get`` grant → 200) is the other one everyone
writes. The discriminating vector is the one where the two authorities
**disagree** — include covers the pattern, exclude carves a child out of it —
and it belongs to both arms at once, so neither arm's author writes it. This
is the standing compose-discriminator law with `include`/`exclude` as the two
authorities.

.. rubric:: The fix needs no invention — §6.3 is §5.2's arm with
   ``caller_exclude = []``

§5.2's pattern arm reads: *for each grant exclude overlapping the target, the
caller must also exclude it (or a superset), else DENY.* §6.3 has no caller-
exclude channel — there is no ``resource.exclude`` on a handler-level check —
so ``is_covered_by(cge, [])`` is vacuously false and the arm reduces to
**an overlapping grant exclude denies**. That is a transcription, not a new
rule, which is why it is landed here rather than held for a ruling. The
*sentence* is still owed: routed as **SA-PY-56**, because §6.3's pseudocode
has no pattern arm and §2.3 is a normative call site that supplies one.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import check_path_permission
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

PEER = "2KTestPatternSubjectPeerJdaaaaaaaaaaaaaaaaaaaa"


def _cap(include: list[str], exclude: list[str] | None = None) -> dict:
    grant: dict = {
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": include},
    }
    if exclude is not None:
        grant["resources"]["exclude"] = exclude
    return {"grants": [grant]}


class TestThePatternArmAtTheHandlerLevelCheck:
    """`check_path_permission` with a pattern subject — §5.2's `G-4` arm, at
    the site 0.8.2.21's enumeration does not reach."""

    def test_a_pattern_spanning_a_grant_exclude_is_DENIED(self):
        """⭐ The headline. ``data/*`` spans ``data/secret``; the grant
        excludes it; the pattern must not be authorized as a whole."""
        assert check_path_permission(
            _cap(["data/*"], ["data/secret"]), "get", "data/*", PEER,
        ) is False, (
            "a subject pattern spanning a grant exclusion was ALLOWED. The "
            "exclude loop compared a concrete exclude against the pattern "
            "STRING, which no concrete path can equal, so the exclusion "
            "carved out nothing — `F68`'s law with the subject's SHAPE as the "
            "vacuum-inducing input, one site past where 0.8.2.21 fixed it"
        )

    def test_teeth_the_same_pattern_with_no_exclude_is_ALLOWED(self):
        """Without this the row above passes on a peer that denies every
        pattern subject outright."""
        assert check_path_permission(
            _cap(["data/*"]), "get", "data/*", PEER,
        ) is True

    def test_a_NON_overlapping_exclude_does_not_deny(self):
        """The arm is ``patterns_overlap``, not *"any exclude denies"*. A
        grant excluding something outside the requested subtree must leave the
        subject authorized, or the fix is a denial-of-service wearing a
        security fix's clothes."""
        assert check_path_permission(
            _cap(["data/*", "other/*"], ["other/secret"]), "get", "data/*", PEER,
        ) is True

    def test_the_concrete_arm_is_unchanged_in_both_directions(self):
        """The existing behaviour this must not disturb — the concrete subject
        is still decided by ``matches_pattern``, both ways."""
        cap = _cap(["data/*"], ["data/secret"])
        assert check_path_permission(cap, "get", "data/secret", PEER) is False
        assert check_path_permission(cap, "get", "data/public", PEER) is True

    def test_an_exact_grant_exclude_of_the_pattern_ITSELF_still_denies(self):
        """A granter who writes the exclusion in the caller's own spelling is
        not worse off than one who writes a concrete child.

        **Labelled as the NON-DISCRIMINATOR**, measured rather than assumed:
        removing the pattern arm leaves this row GREEN, because
        ``matches_pattern("/{p}/data/*", "/{p}/data/*")`` is true under the
        concrete arm too. Four rows in a class read as four rows of coverage
        unless one of them says otherwise — this is the one that says so, and
        it is exactly the shape a granter is most likely to write, which is
        why it is kept.
        """
        assert check_path_permission(
            _cap(["data/*"], ["data/*"]), "get", "data/*", PEER,
        ) is False


# ---------------------------------------------------------------------------
# The reachable consequence — EXTENSION-SUBSCRIPTION §2.3
# ---------------------------------------------------------------------------

EXCLUDED = "data/secret"
VISIBLE = "data/public"

OPEN = {"grants": [{"handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]}}]}


@pytest.fixture
def peer():
    p = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    for path in (EXCLUDED, VISIBLE):
        p.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    return p


def _ctx(peer, caller: dict) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=caller,
        emit_pathway=peer.emit_pathway,
    )


def _deliver_token(peer) -> bytes:
    """A resolvable delivery token.

    Its *authority* is a separate chain (INBOX §2) and is deliberately not
    what these rows are about — every row holds it constant, so a refusal is
    attributable to the §2.3 read-auth check and to nothing else. It has to be
    in the content store because the handler resolves it; a bare 33 bytes gets
    ``400 missing_deliver_token``, which would make the teeth control fail for
    a reason unrelated to what it controls for.
    """
    return peer.emit_pathway.content_store.put(
        Entity(type="system/capability/token", data={"grants": [{
            "handlers": {"include": ["system/inbox"]},
            "operations": {"include": ["receive"]},
            "resources": {"include": ["system/inbox/*"]},
        }]}),
    )


async def _subscribe(peer, caller: dict, pattern: str) -> dict:
    handler = peer.handlers.find_handler("system/subscription")
    return await handler("system/subscription", "subscribe", {"data": {
        "pattern": pattern,
        "events": ["created", "updated"],
        "deliver_to": {"uri": "system/inbox/probe", "operation": "receive"},
        "deliver_token": _deliver_token(peer),
        "include_payload": True,
    }}, _ctx(peer, caller))


class TestIncludePayloadOnASpanningPattern:
    """§2.3's read-authorization, driven at the arm the cohort vector cannot
    reach: the caller HAS ``get`` on the pattern and the grant excludes a
    child inside it."""

    @pytest.mark.asyncio
    async def test_a_spanning_subscription_is_refused(self, peer):
        """⭐ The reachable half. Accepted, this subscription pushes the body
        of the excluded entity on every write to it, forever, with no second
        check at delivery."""
        caller = {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["data/*"], "exclude": [EXCLUDED]},
        }]}
        r = await _subscribe(peer, caller, "data/*")
        assert r["status"] == 403, (
            f"subscribe(include_payload=True, pattern='data/*') returned "
            f"{r['status']} under a capability that excludes {EXCLUDED!r}. "
            f"Delivery performs no per-event read check, so this is a "
            f"standing push of the excluded entity's body"
        )
        assert r["result"]["data"]["code"] == "payload_unauthorized"

    @pytest.mark.asyncio
    async def test_teeth_an_unexcluded_pattern_passes_the_read_auth_gate(self, peer):
        """The control that keeps the row above attributable — and the one
        that fails a fix which simply refuses every pattern subject.

        **It asserts the gate, not the subscription.** Completing a subscribe
        needs a signed ``deliver_token`` chain reaching the subscriber (SB1,
        §3.1), which is a separate authority and a great deal of fixture; this
        request fails *after* the §2.3 check on exactly that. Asserting *"not
        ``payload_unauthorized``"* is the strongest claim this fixture can
        carry, and it is the whole claim the control needs — said here rather
        than left for a reader to infer from a passing row.
        """
        caller = {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["data/*"]},
        }]}
        r = await _subscribe(peer, caller, "data/*")
        code = r.get("result", {}).get("data", {}).get("code")
        assert code != "payload_unauthorized", (
            "a payload subscription whose grant covers the whole pattern was "
            "refused by the §2.3 read-auth check — the pattern arm is "
            "over-refusing, which is a denial of service wearing a security "
            "fix's clothes"
        )

    @pytest.mark.asyncio
    async def test_the_cohorts_vector_the_neither_arm_still_refuses(self, peer):
        """go's `include_payload_unauthorized` shape: no ``system/tree`` grant
        at all. Kept and **labelled as the non-discriminator** — it passes on a
        peer with the defect, which is the whole point of the entry above.

        It also pins the **ordering**: the §2.3 check answers before the
        deliver-token chain walk, so the spanning row above is attributable.
        """
        caller = {"grants": [{
            "handlers": {"include": ["system/subscription"]},
            "operations": {"include": ["subscribe"]},
            "resources": {"include": ["data/*"]},
        }]}
        r = await _subscribe(peer, caller, "data/*")
        assert r["status"] == 403
        assert r["result"]["data"]["code"] == "payload_unauthorized"
