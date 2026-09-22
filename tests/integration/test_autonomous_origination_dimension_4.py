"""SA-PY-46 — autonomous origination is IN scope (§1.4 D4), and this peer
exempts the whole class by minting itself `peers: ["*"]`.

**These rows assert today's WRONG behaviour and carry their retirement
condition in the assertion message.** They fail when the fix lands. That is
the SA-PY-29 shape, used here for the same reason: a defect held open across
a cohort conversation needs a row that speaks up when it closes, or it closes
silently and nobody re-reads the filing.

.. rubric:: The rule (§1.4, 0.8.2.19 — *authority provenance, not timing*)

    *"A delivery engine running unattended looks like a peer acting as
    itself, and it is not: an engine delivering under a credential the
    recipient minted is a handler spending its grant — Dimensions 1-3 gate on
    that grant, and the recipient-minted credential relaxes Dimension 4 to
    that recipient. **A peer MUST NOT exempt the class on the ground that no
    caller was on the stack.**"*

.. rubric:: Why this is not a missing check

The §1.4 outbound gate landed this session and is fully armed on this path —
`extension_execute` goes through `_dispatch_local_execute`, which runs
`_authorize_outbound_sub_dispatch` on the remote branch like any other
sub-dispatch. **The gate runs, reads the grant, and passes**, because the
grant it is handed is `create_full_access_grant()` with
`peers: {include: ["*"]}`.

So there is no branch to find and nothing reads as skipped. That is the
`peers`-dimension law from `AGENTS.md` in its third shape: *a field the type
system parses is not a field the authorization path checks* — here the field
is checked, and the **value** makes the check vacuous. A carve-out would have
been easier to see.

.. rubric:: What this is not

Not `entity-core-go`'s defect. They mint the `deliver_token` **B-rooted**
against `EXTENSION-SUBSCRIPTION` §1.2's A-rooted `[MUST]`; ours is supplied by
the subscriber and chain-validated against the subscriber's identity, so the
token's rooting looks conformant here. Same wire symptom — Dimension 4
unenforced on autonomous delivery — reached from the opposite end. Three
seats, three mechanisms, one class.

.. rubric:: Why it is still not fixed — RE-POINTED 2026-09-10, and the reason
   changed

The original reason was that *"which grant does a delivery engine spend"* was
unanswered and picking unilaterally manufactures a divergence. **That question
is now ruled** (arch `ROUTING-2026-09-10-b` §3, from 0.8.2.19 §1.4): Dimensions
1-3 on the subscription handler's own grant, Dimension 4 relaxed by the
recipient-minted token. So that reason is retired.

The new reason is **sequencing, and it is measured rather than argued.** The
ruling's two halves are one change: `extension_execute` passes no
`dispatch_capability_entity`, so nothing on this path can supply Dimension 4.
Narrowing the grant without presenting the `deliver_token` refuses every
cross-peer delivery — measured, with `extension_execute` on a peers-omitted
grant the cross-peer subscription suite fails `403 … §5.2 Dimension 4 (peers)`.
**Presenting is arch's Phase 2**, which opens only once all three seats mint
conformantly; py's mint landed at `b3bcff7`.

Arch's per-seat table files py's half under **Phase 1**, headed *"Phase 1 is
independently correct and breaks nothing."* At this seat it is a Phase 2
change, and that is routed as a finding about the table's sequencing — not as
a request for relief. See SA-PY-46's 2026-09-10 update.

**What is not in doubt:** the wildcard is wrong under every candidate answer,
and it is ours.
"""

from __future__ import annotations

import inspect

from entity_core.capability.checking import grant_allows_peer
from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair

RETIREMENT = (
    "SA-PY-46 has been fixed — autonomous origination now spends a real "
    "handler grant instead of a self-minted wildcard. DELETE this file, "
    "close SA-PY-46 in docs/SPEC-AMBIGUITIES.md naming the commit, and move "
    "the coverage to a row that asserts the deliver_token relaxes Dimension 4 "
    "to the RECIPIENT and to no one else."
)


class TestTheClassIsCurrentlyExempt:
    def test_the_extension_pathway_still_mints_itself_a_wildcard_grant(self):
        """The site. `Peer._from_builder`'s `extension_execute` is what every
        autonomous origination dispatches through, and the authority it hands
        the gate is a peer-level full-access grant rather than the grant of
        the handler whose work is being delivered.
        """
        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer._from_builder)
        assert "create_full_access_grant()" in src, RETIREMENT
        assert "async def extension_execute" in src, (
            "the extension execute pathway moved; re-point this row at its "
            "new home before concluding anything about SA-PY-46"
        )

    def test_and_that_grant_authorizes_dimension_4_at_every_foreign_peer(self):
        """The consequence, measured at the predicate rather than argued.

        Both entries of the grant carry `peers: {include: ["*"]}`, so the
        §1.4 gate — which does run on this path — reads a grant that covers
        every peer that will ever exist. `grant.py`'s own docstring quotes the
        spec calling this shape *"specifically wrong … the one direction that
        must not be widened"*; the delivery pathway kept it.
        """
        foreign = Keypair.generate().peer_id
        local = Keypair.generate().peer_id

        entries = [g.to_dict() for g in create_full_access_grant()]
        assert entries, "the full-access grant is empty; this row measures nothing"
        assert all(
            grant_allows_peer(entry, foreign, local) for entry in entries
        ), RETIREMENT

    def test_the_gate_itself_is_armed_which_is_what_makes_this_a_VALUE_defect(
        self,
    ):
        """The control that keeps the two claims apart, and it is the reason
        this file is not a duplicate of the PD-2 one.

        *"The check is missing"* and *"the check passes on a wildcard"* are
        different defects with different fixes, and only the second is ours.
        This row asserts the enforcement point is present and reached on the
        remote branch — so a reader cannot conclude from the rows above that
        py has no outbound authorization, which is the misreading that would
        get relayed.
        """
        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer._dispatch_local_execute)
        check = src.index("self._authorize_outbound_sub_dispatch(")
        remote = src.index("return await self._remote_execute(")
        assert check < remote, (
            "the outbound gate no longer precedes the transport — that is a "
            "PD-2 regression, not SA-PY-46"
        )
