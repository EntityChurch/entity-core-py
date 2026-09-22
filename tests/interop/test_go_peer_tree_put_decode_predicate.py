"""SA-PY-41 driven, not read — `EXTENSION-TREE` Appendix A `put` against a go peer.

.. rubric:: SA-PY-41 is RULED (0.8.2.11 / EXTENSION-TREE v4.5), and this file is the acceptance test

Both filed rows went go's way, and the ruling refused the dichotomy the filing
posed: ``put`` is a **receipt** path at the peer *and* an **authoring** one at
the SDK (`SDK-OPERATIONS` §3.2), so the two layers compose and neither seat's
answer was the whole rule. Every seat was non-conformant somewhere.

The two divergent rows therefore **flip rather than retire**, and one of them
inverts outright:

* the absent-hash refusal stays a refusal and its *code* moves —
  ``hash_mismatch`` → ``invalid_request`` (go's refusal was right and go's code
  was wrong: an absent required field is step 1, not step 2);
* **our own SDK now `put`s to a go peer**, which is the cross-seat acceptance
  drive core-go asked for and the one no single-tree suite can perform. It is
  the same row, asserted in the opposite direction, and that inversion is the
  proof our SDK's construction step landed.


`AGENTS.md`: *a source reading gives you the site; only a trace gives you the
extent.* SA-PY-41's headline claim — **a py or rust SDK cannot `put` to a go
peer, because go refuses an entity submitted without a `content_hash`** — was
derived by reading `core/tree/handler.go` → `entity.Validate` → `hash.Validate`,
and a claim about a sibling's behaviour routed on a source read is exactly what
that law forbids. This file drives it.

Run against a live go peer:

    cd ../entity-core-go && go run ./cmd/entity-peer -addr 127.0.0.1:19805 -open-access
    ENTITY_GO_PEER=127.0.0.1:19805 .venv/bin/python -m pytest \\
        tests/interop/test_go_peer_tree_put_decode_predicate.py -v

**Opt-in by an explicit address, with NO default**, for the reason
`test_go_peer_compute_v324.py` states at length: these rows assert a *sibling's*
behaviour, and arming them by default puts our gate on core-go's release
schedule. The obligation therefore moves to the calendar — run it on every
cohort catch-up and before replying to any routed tree item, and record the
result with the go commit attached (`docs/status/ROUTING-2026-09-06-a-…`).

.. rubric:: What the rows are, and which way each one points

Three rows of the decode predicate, plus two controls. **Every row is driven
against py as well**, in `tests/integration/test_tree_put_error_rows_appendix_a.py`
— a divergence report with only the sibling's leg measured is *"our reading of
the spec disagrees with your code."*

* **The controls** — a well-formed put with a correct `content_hash` lands, and a
  non-decoding entity is refused. Without them a refusal on the rows below is
  attributable to an unreachable handler or a closed grant rather than to the
  input, and go's own probe carries the same precaution.
* **`content_hash` absent** — the row with a caller-visible consequence today.
  We expect go to refuse it. If this row ever passes, go has grown rust's arm
  and SA-PY-41's §4.1 is closed.
* **`type` is `""`** — go refuses (`entity.Validate`: *type is empty*), rust
  accepts. We hold rust's answer.

.. rubric:: The rows assert go's CURRENT behaviour, which is a deliberate choice

Each divergent row asserts what go does **today** and carries its retirement
condition in the assertion message. That is the opposite of an `xfail`, and for
the standing reason: an `xfail` here flips to XPASS the day go changes, and gets
read as *the claim confirming* rather than as *the divergence closing*. A row
that states today's answer fails loudly when the answer moves, which is the
notification we actually want.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_core.utils.ecf import compute_ecf_hash, get_default_hash_algorithm

#: `host:port` of a live `entity-core-go` peer. Unset ⇒ every row skips.
GO_PEER_ADDR = os.environ.get("ENTITY_GO_PEER", "")

BASE = "interop/sapy41"


async def _handshake(keypair: Keypair) -> Connection | None:
    """Connect AND complete the handshake, or None.

    Testing for a listening socket is not testing for a peer — the 2026-08-19
    Selenium-on-9000 lesson, inherited verbatim.
    """
    if not GO_PEER_ADDR:
        return None
    host, _, port = GO_PEER_ADDR.partition(":")
    try:
        conn = await asyncio.wait_for(
            Connection.connect(host, int(port), keypair, wait_for_capability=True),
            timeout=5.0,
        )
    except Exception:
        return None
    if conn.session.remote_peer_id is None:
        conn.close()
        await conn.wait_closed()
        return None
    return conn


@pytest.fixture
async def go_conn():
    conn = await _handshake(Keypair.generate())
    if conn is None:
        pytest.skip(
            "set ENTITY_GO_PEER=host:port to a live entity-core-go peer that "
            f"completes a handshake; current value: {GO_PEER_ADDR!r}"
        )
    try:
        yield conn
    finally:
        conn.close()
        await conn.wait_closed()


async def _put(conn: Connection, path: str, entity: Any) -> tuple[int, str]:
    result = await conn.execute(
        f"entity://{conn.session.remote_peer_id}/system/tree",
        "put",
        {"type": "system/tree/put-request", "data": {"path": path, "entity": entity}},
        resource={"targets": [path]},
    )
    body = (result.result or {}).get("data") or {}
    return int(result.status), body.get("code", "")


def _hashed(entity_type: str, data: Any) -> dict[str, Any]:
    """The shape a go/rust constructor mints: `{type, data, content_hash}`."""
    return {
        "type": entity_type,
        "data": data,
        "content_hash": compute_ecf_hash(
            {"type": entity_type, "data": data}, get_default_hash_algorithm()
        ),
    }


class TestControls:
    """Without these, no refusal below is attributable to its input."""

    @pytest.mark.asyncio
    async def test_a_hashed_put_lands(self, go_conn) -> None:
        status, code = await _put(
            go_conn, f"{BASE}/control", _hashed("app/probe", {"v": "ok"})
        )
        assert status == 200, (
            f"control put answered {status}/{code!r} — the rows below are "
            f"unattributable until a well-formed put lands"
        )

    @pytest.mark.asyncio
    async def test_a_non_decoding_entity_is_refused(self, go_conn) -> None:
        """Row 1 as go's own probe drives it — the agreed half of the predicate."""
        status, code = await _put(go_conn, f"{BASE}/undecodable", 42)
        assert (status, code) == (400, "invalid_request"), (
            "go's own row-1 vector, driven from this seat"
        )


class TestTheRuledRows:
    """SA-PY-41 §4 after 0.8.2.11 — the two seats agree, measured rather than assumed."""

    @pytest.mark.asyncio
    async def test_an_absent_content_hash_is_400_invalid_request_at_go(
        self, go_conn
    ) -> None:
        """The row that was the live cohort break, now the row that closes it.

        The payload is the one `EntityClient._put` used to emit:
        ``{"type": …, "data": …}``, no hash. py and rust authored one; go
        decoded the absent field to the zero ``Hash``, recomputed under format
        ``0x00`` and reported ``ErrHashMismatch``.

        **Both halves of that were wrong** and the ruling says which: refusing
        is right (``put`` is a receipt path — a peer MUST NOT author a
        submitted entity's hash) and ``hash_mismatch`` is not, because an absent
        required field is step 1 of §6.3's ladder and never reaches step 2. This
        row is now the ruled pair on both sides, so a *code* regression at
        either seat fails here — which the old row, asserting only ``!= 200``
        plus go's then-current pair, could not do for a fix that had not landed.

        No probe in the cohort could reach this arm before it was written: every
        one builds its entity through a constructor that computes a hash.
        """
        status, code = await _put(
            go_conn, f"{BASE}/nohash", {"type": "app/probe", "data": {"v": 1}}
        )
        assert (status, code) == (400, "invalid_request"), (
            f"0.8.2.11 §6.3 step 1 / EXTENSION-TREE v4.5 row 1 — an absent "
            f"content_hash is a required field's absence. Got {status}/{code!r}: "
            f"`hash_mismatch` means go is on the pre-`bed12bb` code, `200` means "
            f"the authoring arm is back."
        )

    @pytest.mark.asyncio
    async def test_our_own_sdk_can_now_put_to_a_go_peer(self, go_conn) -> None:
        """**The cross-seat acceptance drive**, and the row this whole arc is for.

        SA-PY-41 §4.1's headline claim was *a py SDK cannot `put` to a go peer*.
        It was true, it was our defect rather than go's, and this row is the same
        assertion inverted: `EntityClient.put` constructs the entity and computes
        its hash (`SDK-OPERATIONS` §3.2), so a strict go peer accepts it.

        **No single-tree suite can run this.** Our SDK against our own peer
        passes on both sides of the defect — that is what a compensating pair
        is — so the boundary is the only place the construction step is
        observable at all. It is also the reason the arc took six weeks to
        surface: nothing was wrong from inside either tree.

        The returned hash is asserted against the one we authored, because a
        `200` alone would still be satisfied by a peer that ignored our hash and
        minted its own.
        """
        from entity_core.protocol.entity import Entity
        from entity_core.sdk import ConnectionDispatcher
        from entity_sdk.client import EntityClient

        client = EntityClient(
            ConnectionDispatcher(go_conn), go_conn.session.remote_peer_id
        )
        returned = await client.put(f"{BASE}/viasdk", "app/probe", {"v": 1})
        assert returned == Entity(type="app/probe", data={"v": 1}).compute_hash(), (
            "the go peer must bind the hash WE authored — `put` is a receipt "
            "path, so the hash it echoes is the one it was given"
        )

    @pytest.mark.asyncio
    async def test_an_empty_type_is_400_invalid_request_at_go(self, go_conn) -> None:
        """SA-PY-41 §4 row 7 → ruled at 0.8.2.11 §6.3, in go's shape.

        The filing was right that an empty string decodes into ``type: string``
        perfectly well and that no sentence *then* required a non-empty type.
        §6.3 now says **non-empty**, derived from §2.7 (*"the name is the interop
        contract"*) and 0.8.2.4's present-but-empty ``protocols`` precedent.

        Kept as a driven row rather than deleted: it was a real divergence, and
        this is where a seat drifting back off the ruling is noticed.
        """
        status, code = await _put(
            go_conn, f"{BASE}/emptytype", _hashed("", {"v": 1})
        )
        assert (status, code) == (400, "invalid_request"), (
            "0.8.2.11 §6.3 step 1 — an empty interop contract is not a contract"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "content_hash"),
        [
            # Allocated (ECFv1-SHA-512), not in either peer's supported set,
            # carried at exactly the length that code names — so the value is a
            # well-formed `system/hash` and the only thing wrong with it is that
            # neither peer can verify it. Row 4, not row 1.
            ("allocated_but_unsupported_sha512", b"\x02" + b"\xab" * 64),
            # Unallocated. §4.7 row 5's own note: the code is "reachable on any
            # frame carrying an unallocated format code".
            ("unallocated_format_byte", b"\x7f" + b"\xab" * 32),
        ],
    )
    async def test_an_unsupported_content_hash_format_is_row_4_at_go(
        self, go_conn, label: str, content_hash: bytes
    ) -> None:
        """v4.5's NEW row — and a measured divergence, routed rather than absorbed.

        **Measured at go `b353351`: `400 invalid_request` for both vectors.**
        Traced rather than read off the code: `core/tree/handler.go:464-467`
        branches on `errors.Is(err, hash.ErrHashMismatch)` and sends *everything
        else* from `entity.Validate()` to `invalid_request` — and
        `hash.Validate` → `ComputeFormat` → `OfBytes`'s `default:` arm returns
        `ErrUnsupportedContentHashFormat` for any code outside `{0x00, 0x01}`.
        So the code go already mints is reached and then flattened one frame
        later by a catch-all.

        **This is not a defect go was told about.** Their `bed12bb` implements
        the absent/mis-sized arm their worklist named; row 4 landed with v4.5
        *after* it, restated onto Appendix A from §4.7 row 5 *"because `put` is
        one of its ingest surfaces"*. It is the standing *walk every row when a
        sibling reports N* shape from the other side: the row nobody was
        assigned is where a seat stays non-conformant after the cross-drive goes
        green.

        The row asserts **the ruled pair**, not go's current answer, because
        this is not an unruled divergence — v4.5 says outright *"Not the
        `invalid_request` row"*. It therefore fails until go lands it, which is
        the notification we want; the finding goes back in the routing reply.
        """
        status, code = await _put(
            go_conn, f"{BASE}/unsupportedfmt/{label}",
            {"type": "app/probe", "data": {"v": 1}, "content_hash": content_hash},
        )
        assert (status, code) == (400, "unsupported_content_hash_format"), (
            f"{label}: EXTENSION-TREE v4.5 row 4 / §4.7 row 5 — got "
            f"{status}/{code!r}. Do NOT change our own answer to match: v4.5 "
            f"postdates go's `bed12bb` and their worklist did not name this row. "
            f"Routed 2026-09-06; retire when go lands it."
        )

    @pytest.mark.asyncio
    async def test_a_null_data_is_accepted_by_go(self, go_conn) -> None:
        """The control that keeps our guard from over-reaching.

        ``data: null`` is present-but-empty, and all three seats accept it. It is
        here so that a seat "tightening" `validate_entity_structure` from
        *absent* to *falsy* is caught against the sibling rather than against our
        own opinion.
        """
        status, code = await _put(
            go_conn, f"{BASE}/nulldata", _hashed("app/probe", None)
        )
        assert status == 200, (
            f"expected go to accept `data: null` (present, not absent); got "
            f"{status}/{code!r} — if this is a refusal, our guard's `data` arm "
            f"is looser than the cohort's and SA-PY-41 gains a row"
        )
