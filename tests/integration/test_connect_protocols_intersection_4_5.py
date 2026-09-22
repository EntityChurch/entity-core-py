"""V7 §4.5 `protocols` intersection and §4.7 row 1 — and the constant it turns on.

**The gap and the partition are two findings, and only the first was routed.**
`entity-core-go` landed §4.7 row 1 (a responder MUST refuse a hello whose
`protocols` set is disjoint from its own) and relayed *"both siblings owe the
`handleHello` intersection check."* True. What the relay could not contain is
what the check makes visible: **this peer advertised `entity-core/7.0` while go,
rust and the spec's own §8.4 say `entity-core/1.0`.** Measured against a live go
peer at `7262f17`, a py initiator gets

    Connect hello failed (status 400 incompatible_protocol):
      no common protocol version: initiator=[entity-core/7.0] responder=[entity-core/1.0]

so implementing the row as relayed — without the constant — would have converted
a dormant disagreement into a **mutual refusal**: they reject us today, we would
have started rejecting them.

**Why nobody saw it for the life of the project.** §4.5 pins `protocols` as
*"Intersection, must be non-empty"* and **no seat implemented it**, so the field
was carried on every hello in the cohort and read by nothing. A dead field
cannot diverge observably — the divergence is created by the first
implementation, not revealed by it. That is the *validator-vs-consumer* law
(a field with a producer and no consumer) with the missing consumer in **every**
implementation at once, which is why no cross-impl run could catch it: the
cohort agreed on the behaviour (ignore it) and disagreed on the value.

**These rows are the responder half.** The initiator half is only observable
against a peer that checks, and lives in
`tests/interop/test_go_peer_connect_negotiation.py` — deliberately not here,
because a row asserting our conformance must not need a sibling's peer to run.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import re
from pathlib import Path
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import (
    ADVERTISED_PROTOCOLS,
    PROTOCOL_VERSION,
    ConnectError,
    ConnectState,
    handle_connect_hello,
)
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute
from entity_core.utils.ecf import (
    DEFAULT_ADVERTISED_KEY_TYPES,
    default_advertised_hash_formats,
)

PORT = 19093
CONNECT_URI_PATH = "system/protocol/connect"


@pytest.fixture
async def server_peer():
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_default_handlers().debug_mode(True).build()
    )
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


def _hello_execute(peer_id: str, protocols: Any) -> Execute:
    """A hello whose `protocols` is whatever the row needs — including absent.

    ``protocols=...`` (Ellipsis) omits the key entirely, which is a different
    input from ``[]`` and the two are separate rows below: §4.5 marks the field
    Required, so *"omitted"* and *"present but empty"* are not obviously one
    case and an implementation that folds them has made a second silent ruling.
    """
    data: dict[str, Any] = {
        "peer_id": peer_id,
        "nonce": b"\x07" * 32,
        "hash_formats": default_advertised_hash_formats(),
        "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
    }
    if protocols is not ...:
        data["protocols"] = protocols
    return Execute.create(
        uri=f"entity://{peer_id}/{CONNECT_URI_PATH}",
        operation="hello",
        params=Entity(type="system/protocol/connect/hello", data=data).to_dict(),
    )


async def _hello_over_the_wire(protocols: Any) -> tuple[int, str]:
    """Drive one hello and return the responder's `(status, code)`.

    Over a real socket rather than by calling `handle_connect_hello`, because
    §4.7 is a table of `(failure, code, status)` **triples** and the status half
    is applied at the wire boundary in `peer.py`. A row driven in-process can
    only ever assert the code, which is how a peer ships two thirds of a row
    (FM-1, and again at G-28).
    """
    keypair = Keypair.generate()
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        await send_envelope(
            writer,
            Envelope(root=_hello_execute(keypair.peer_id, protocols).to_entity()),
        )
        response = await asyncio.wait_for(recv_envelope(reader), timeout=5.0)
        body = response.root["data"]
        result = body.get("result") or {}
        code = (result.get("data") or {}).get("code", "")
        return int(body["status"]), code
    finally:
        writer.close()


class TestRow1TheIntersectionIsChecked:
    """§4.5 *"Intersection, must be non-empty"* → §4.7 row 1, on the wire."""

    async def test_a_disjoint_non_empty_set_is_400_incompatible_protocol(
        self, server_peer
    ) -> None:
        """The headline row, asserted as a PAIR.

        Both halves are checked separately on purpose: a peer can answer
        `400 bad_request` (the code half missing — what this peer did until
        today) or `500 incompatible_protocol` (the status half wrong) and
        satisfy a row that only looks at one. G-28 measured four §4.7 rows here
        that were each half-right in exactly that way.
        """
        status, code = await _hello_over_the_wire(["entity-core/99.0"])
        assert (status, code) == (400, "incompatible_protocol"), (
            f"§4.7 row 1 pins (400, 'incompatible_protocol'); got ({status}, {code!r})"
        )

    async def test_the_matching_set_still_completes(self, server_peer) -> None:
        """The control, and it is what makes the row above attributable.

        Without it a peer that refuses *every* hello — a broken harness, a bad
        nonce, a peer that is down — scores the row above green.
        """
        status, code = await _hello_over_the_wire(list(ADVERTISED_PROTOCOLS))
        assert status == 200, f"a conformant hello was refused: ({status}, {code!r})"

    async def test_an_overlapping_superset_completes(self, server_peer) -> None:
        """Intersection, not equality.

        A peer offering a version we speak **and** one we do not has a non-empty
        intersection and MUST be accepted. An implementation that compares the
        sets for equality, or takes the initiator's first entry, passes both
        rows above and fails this one — and it is the shape a future second
        protocol version arrives in.
        """
        status, _ = await _hello_over_the_wire(
            ["entity-core/99.0", PROTOCOL_VERSION]
        )
        assert status == 200


class TestTheAbsentArmIsARuling:
    """The arm `min`-style code writes as a null check — RULED, and the other way.

    **The retirement condition fired.** These rows were written to accept
    (reading 1, matching `entity-core-go`) with the condition stated in the
    docstring: *they flip to a refusal iff FM-2 or a successor rules the absent
    case, for the cohort at once.* 0.8.2.4 ruled it — §4.5 in normative text, and
    §4.7's row 1 narrowed to a **non-empty** disjoint set in the same fold — so
    the rows flip and keep pinning the arm. That is what a test written as a
    decision rather than as an outcome is for.

    **What the flip cost, and it is the reusable half:** our filing's *argument*
    carried the ruling and our *fallback* was wrong. We reasoned "two ground-up
    seats both accept, so refusing manufactures a partition" — but the cohort is
    not the ground-up seats: keystone's generated `csharp` and `typescript`
    peers already **required** the field and passed conformance, so reading 1
    would have made 46 peers non-conformant. **A cohort-consistency argument is
    only as good as the census behind it**, and ours had counted two of three
    families. Same shape as this repo's standing *"the conjunction of two
    readings bounds the disagreement, not the error"* entry: the seats we polled
    agreed, and the rows nobody re-examines are exactly the ones they agree on.

    Absent and empty are one input by ruling ("no `protocols` field, or an empty
    list"), so the `or []` fold that used to be a silent second ruling is now the
    ruled shape — the two rows stay separate anyway, because a fold that happens
    to be correct is still a fold, and the next arm to move needs somewhere
    visible to move.
    """

    async def test_an_omitted_protocols_list_is_400_invalid_request(
        self, server_peer
    ) -> None:
        """§4.5: Required with no default, so there is no floor to fall back to."""
        status, code = await _hello_over_the_wire(...)
        assert (status, code) == (400, "invalid_request"), (
            "§4.5 (0.8.2.4) pins an absent `protocols` as a malformed hello — "
            f"(400, 'invalid_request'); got ({status}, {code!r})"
        )

    async def test_an_empty_protocols_list_is_400_invalid_request(
        self, server_peer
    ) -> None:
        """Present-but-empty, kept as its own row."""
        status, code = await _hello_over_the_wire([])
        assert (status, code) == (400, "invalid_request"), (
            "§4.5 (0.8.2.4) names the empty list alongside the absent field; got "
            f"({status}, {code!r})"
        )

    async def test_it_is_not_incompatible_protocol(self, server_peer) -> None:
        """The discriminating row: the ruling is about WHICH code, not whether.

        **Mutation-verified, and the prediction was wrong in the useful
        direction.** Deleting the guard was predicted to restore reading 1 and
        leave this row green; it turned the peer into **reading 3** instead and
        this row went red — because narrowing the guard leaves the intersection
        comparison *unguarded*, and an empty set trivially fails it. Reading 1
        needs a second edit (re-guarding the comparison with `initiator_protocols
        and`), and that mutation fails the two rows above and NOT this one. So
        the two wrong readings are caught by different rows, and reading 3 —
        the one an author reaches for by deleting a line — is the one only this
        row can see.


        Reading 3 — an empty set intersects to empty, so answer row 1 — is the
        tidy implementation and the one an author reaches for when narrowing the
        `or []`. It refuses the same hello with the same status, so a row
        asserting only `status == 400` scores it green. The whole content of the
        ruling is that a caller who named no version cannot be told the
        comparison failed: the remedy is *send the field*, not *change the
        version*, and §4.7 exists so the code selects the remedy.
        """
        _, absent_code = await _hello_over_the_wire(...)
        _, empty_code = await _hello_over_the_wire([])
        assert "incompatible_protocol" not in (absent_code, empty_code), (
            "row 1 is reserved for a NON-EMPTY set that does not intersect "
            "(§4.7, narrowed at 0.8.2.4)"
        )


class TestTheVersionStringItself:
    """The constant is wire contract, and it had four homes.

    A matcher inside a hash-determining function is wire contract; so is a
    **string a peer compares byte for byte to decide whether to talk to you**.
    These rows are the enforcement point for the finding, because the
    behavioural rows above pass against *any* string as long as both sides of
    the test use the same one — which is precisely the configuration that hid
    this for the life of the project.
    """

    def test_the_advertised_version_is_the_one_8_4_pins(self) -> None:
        """Pinned against the spec, not against what we happen to emit.

        `AGENTS.md` on `PINNED_ROOT_HASH`: updating a pin to whatever the code
        currently emits is how a pin stops meaning anything. So this row names
        the literal §8.4 declares — the check that would have failed on day one.
        """
        assert PROTOCOL_VERSION == "entity-core/1.0", (
            "V7 §8.4 *Protocol Version* is `entity-core/1.0`. This peer shipped "
            "`entity-core/7.0` — the specification's title version — until "
            "2026-09-01, and §4.5's intersection had no implementer to notice."
        )
        assert ADVERTISED_PROTOCOLS == [PROTOCOL_VERSION]

    def test_no_second_literal_of_the_version_string_exists_in_the_packages(
        self,
    ) -> None:
        """A ratchet at ZERO: the value has one home.

        It diverged because it had four — both hello builders, the
        `system/peer/info` advertisement, and a renderer docstring — and four
        literals of one wire value is the two-representations bug waiting for
        someone to edit three of them. An absent ledger entry is a hard zero
        (the presentation-purity gate's rule), so a new literal here is a
        deliberate act to be argued for, not an oversight to be tolerated.

        **It counts string literals in CODE, via the AST, not lines matching a
        regex** — and the difference is not pedantry: the first draft of this
        row read lines, and its first run flagged `display.py`'s docstring,
        which renders an example of the field for a human. That is the standing
        *"a gate that cannot tell a sanctioned mention from a smuggled call is
        not a gate"* shape, which has now inflated a count in this repo three
        times (`entity://` in docstrings, the `fnmatch` call-site comment, and
        here). Comments and docstrings are prose about the value; an
        `ast.Constant` in an expression is a second source of truth.

        The definition site is exempt by the name it is assigned to, so moving
        the constant to another module does not widen the exemption.
        """
        root = Path(__file__).resolve().parents[2] / "packages"
        offenders: list[str] = []

        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text())

            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(
                    node,
                    (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
                ):
                    body = getattr(node, "body", None)
                    if (
                        body
                        and isinstance(body[0], ast.Expr)
                        and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str)
                    ):
                        docstrings.add(id(body[0].value))

            sanctioned = {
                id(target.value)
                for target in ast.walk(tree)
                if isinstance(target, ast.Assign)
                and isinstance(target.value, ast.Constant)
                and any(
                    isinstance(t, ast.Name) and t.id == "PROTOCOL_VERSION"
                    for t in target.targets
                )
            }

            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                if not re.fullmatch(r"entity-core/[0-9].*", node.value):
                    continue
                if id(node) in docstrings or id(node) in sanctioned:
                    continue
                offenders.append(
                    f"{path.relative_to(root)}:{node.lineno}: {node.value!r}"
                )

        assert offenders == [], (
            "a second literal of the protocol version string appeared:\n  "
            + "\n  ".join(offenders)
            + "\nUse `ADVERTISED_PROTOCOLS` / `PROTOCOL_VERSION`."
        )

    async def test_the_peer_info_advertisement_matches_what_hello_negotiates(
        self, server_peer
    ) -> None:
        """The two surfaces a peer states its version on, compared.

        `system/peer/info` is what a *client* reads; the hello set is what the
        handshake *negotiates*. They were separate literals, so a peer could
        advertise one version and refuse connections on another — and no test
        in either surface's suite could see it, because each asserted its own
        literal. This is the row that compares them.
        """
        conn = await Connection.connect(
            "127.0.0.1", PORT, Keypair.generate(), wait_for_capability=True
        )
        try:
            response = await conn.execute(
                uri=f"entity://{server_peer.keypair.peer_id}/system/peer/info",
                operation="get",
            )
            advertised = response.result["data"]["protocols"]
        finally:
            conn.close()

        assert advertised == list(ADVERTISED_PROTOCOLS), (
            f"system/peer/info advertises {advertised}, hello negotiates "
            f"{list(ADVERTISED_PROTOCOLS)}"
        )


class TestTheDialerSurfacesAHelloRefusal:
    """The seam that made row 1 nearly unmeasurable from our own seat.

    `connect_refusal` is the dialer-side extractor and its docstring says *"both
    transports route their refusals through here."* That was true of the
    **authenticate** response and false of the **hello** response in both
    transports: the hello leg read `peer_id`/`nonce` straight out of the result
    and raised *"Missing peer_id or nonce in hello response"* — a correct
    statement about the response's shape that says nothing about the refusal,
    and drops the remote's `(status, code)` on the floor.

    Four §4.7 rows refuse at hello (1, 2, 4, and 10's re-hello), so this seam
    was eating the code for **all** of them. It surfaced only when we dialed a
    go peer that refuses at hello — i.e. it needed a sibling to have implemented
    a row we had not, which is why no amount of green here would have found it.
    """

    async def test_a_hello_refusal_arrives_with_its_status_and_code(
        self, server_peer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from entity_core.handlers import connect as connect_handlers
        from entity_core.peer import connection as connection_mod

        original = connect_handlers.create_connect_hello_execute

        def _disjoint(keypair: Keypair):  # type: ignore[no-untyped-def]
            execute, nonce = original(keypair)
            execute.params["data"]["protocols"] = ["entity-core/99.0"]
            return execute, nonce

        # Patched in the CALLER's namespace: `connection.py` from-imports the
        # builder, so rebinding it on `handlers.connect` changes an attribute
        # nothing reads and the row passes having driven the normal hello.
        monkeypatch.setattr(
            connection_mod, "create_connect_hello_execute", _disjoint
        )

        with pytest.raises(ConnectError) as caught:
            await Connection.connect(
                "127.0.0.1", PORT, Keypair.generate(), wait_for_capability=True
            )

        assert caught.value.code == "incompatible_protocol", (
            f"the dialer reported code={caught.value.code!r}; the responder sent "
            "`incompatible_protocol`"
        )
        assert caught.value.status == 400
        assert "Missing peer_id or nonce" not in str(caught.value), (
            "the structural complaint is back — the status check has been "
            "removed or moved below the peer_id/nonce read"
        )


class TestTheHelloSideKeyTypeGate:
    """§4.5's *canonical earliest reject point*, which we were not honoring.

    §4.5: *"Hello negotiation is the canonical earliest reject point for an
    unsupported `key_type` … hello-time reject is the canonical guidance for new
    implementations (matches Rust's choice)."* This peer rejected only at
    `authenticate` (§4.6 step 0), which **AGILITY-UNKNOWN-1 tolerates** — the
    vector is satisfied *"at any handshake surface"* — so a real gap against
    §4.5's named guidance sat behind a green conformance row.

    **It was the protocols check that exposed it**, and only because go's probe
    frame is malformed in two dimensions at once: its hello encodes key_type
    `0xFD` *and* advertises `entity-core/v7`. Refuse on the version and the
    key-type vector never reaches a surface. The lesson is the standing one —
    *adding a check that should always have run is a behaviour change; budget
    for the second finding it exposes* — and the fix is what §4.5 already asked
    for, not a reordering chosen to make a probe pass.
    """

    async def test_an_unallocated_key_type_is_refused_at_hello(
        self, server_peer
    ) -> None:
        import base58

        from entity_core.crypto.identity import HASH_TYPE_SHA256

        keypair = Keypair.generate()
        digest = hashlib.sha256(keypair.public_key_bytes()).digest()
        bad_peer_id = base58.b58encode(
            bytes([0xFD, HASH_TYPE_SHA256]) + digest
        ).decode()

        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        try:
            execute = Execute.create(
                uri=f"entity://{bad_peer_id}/{CONNECT_URI_PATH}",
                operation="hello",
                params=Entity(
                    type="system/protocol/connect/hello",
                    data={
                        "peer_id": bad_peer_id,
                        "nonce": b"\x00" * 32,
                        # Conformant, so the refusal is attributable to the
                        # key_type and not to the version — which is exactly
                        # what go's probe does NOT do, and why it broke.
                        "protocols": list(ADVERTISED_PROTOCOLS),
                    },
                ).to_dict(),
            )
            await send_envelope(writer, Envelope(root=execute.to_entity()))
            response = await asyncio.wait_for(recv_envelope(reader), timeout=5.0)
            body = response.root["data"]
            code = ((body.get("result") or {}).get("data") or {}).get("code", "")
        finally:
            writer.close()

        assert (int(body["status"]), code) == (400, "unsupported_key_type"), (
            f"§4.5 pins hello as the canonical reject point; got "
            f"({body['status']}, {code!r})"
        )

    async def test_a_bad_key_type_with_a_bad_version_still_reports_the_key_type(
        self, server_peer
    ) -> None:
        """go's actual probe frame, reproduced.

        This is the row that would have caught the regression before the
        validator did. It is deliberately the *malformed-in-two-dimensions*
        frame rather than a tidy one, because the tidy frame is the one our own
        fixtures would have written and it cannot discriminate the ordering.
        """
        import base58

        from entity_core.crypto.identity import HASH_TYPE_SHA256

        keypair = Keypair.generate()
        digest = hashlib.sha256(keypair.public_key_bytes()).digest()
        bad_peer_id = base58.b58encode(
            bytes([0xFD, HASH_TYPE_SHA256]) + digest
        ).decode()

        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        try:
            execute = Execute.create(
                uri=f"entity://{bad_peer_id}/{CONNECT_URI_PATH}",
                operation="hello",
                params=Entity(
                    type="system/protocol/connect/hello",
                    data={
                        "peer_id": bad_peer_id,
                        "nonce": b"\x00" * 32,
                        "protocols": ["entity-core/v7"],  # go's harness spelling
                    },
                ).to_dict(),
            )
            await send_envelope(writer, Envelope(root=execute.to_entity()))
            response = await asyncio.wait_for(recv_envelope(reader), timeout=5.0)
            body = response.root["data"]
            code = ((body.get("result") or {}).get("data") or {}).get("code", "")
        finally:
            writer.close()

        assert code == "unsupported_key_type", (
            f"got {code!r} — the key-type gate must precede the protocols "
            "intersection, or AGILITY-UNKNOWN-1 loses its surface"
        )


class TestTheCheckRunsBeforeTheOtherNegotiations:
    """Ordering, asserted because it is not observable from a single row.

    §4.5 lists `protocols` first and it is the coarsest of the three: a peer
    speaking no common *version* has nothing to say about hash formats or key
    types, and answering `incompatible_hash_format` to it points the client at
    the wrong remedy — the same argument arch used to split §4.7 row 10.
    """

    def test_a_hello_disjoint_on_both_reports_the_protocol(self) -> None:
        state = ConnectState()
        keypair = Keypair.generate()
        params = Entity(
            type="system/protocol/connect/hello",
            data={
                "peer_id": keypair.peer_id,
                "nonce": b"\x07" * 32,
                "protocols": ["entity-core/99.0"],
                # Also disjoint: if the protocols check moved below this one,
                # the row reports `incompatible_hash_format` instead.
                "hash_formats": ["ecfv1-sha999"],
                "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
            },
        ).to_dict()

        with pytest.raises(ConnectError) as caught:
            handle_connect_hello(state, params, keypair)

        assert caught.value.code == "incompatible_protocol", (
            f"got {caught.value.code!r} — the protocols check must precede the "
            "hash-format negotiation"
        )
