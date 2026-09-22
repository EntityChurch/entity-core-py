"""§3.3's generic 400 code, and the synonym this peer minted for it.

**Found by walking the code SET after a sibling walked the row set.** core-go
relayed FM-2e (§4.5's absent/empty `protocols` → `400 invalid_request`) and was
right about it. Landing it meant reading §4.7 again, and the paragraph one line
under the table — *"`invalid_request` — the generic malformed-request code
(normative, 0.8.2.4) … Extension specifications use this code for the same class
and MUST NOT mint a synonym"* — names something the relay was not about:

    `ExecuteResponse.bad_request(..., code: str = "bad_request")`
    `ConnectError(msg, *, code: str = "bad_request")`

**`bad_request` is in no spec code set.** §3.3's 400 row declares *"Default
`code` = `invalid_request`"*, with the more-specific set enumerated as
`invalid_path`, `invalid_params`, `unexpected_params`, `chain_depth_exceeded`,
`signature_path_conflict`. `bad_request` appears in the corpus once, at §5.1's
M3 rule, as the thing you must **not** surface. It has been our generic 400
since before §3.3 named one (`invalid_request` landed at the 0.8.2.2 PD-1 fold),
so every codeless 400 this kernel emitted was a synonym.

.. rubric:: Why nothing caught it, which is the part that generalizes

1. **It lived in a default argument.** The same peer answers the correct
   `invalid_params` from ~80 handler-tier sites and answered the synonym from 12
   kernel sites — and the difference is not care, it is that the handler sites
   *state* their code and the kernel sites inherit one. **A default argument is
   a wire decision with no call site to review it**, so it is invisible to
   exactly the review that reads call sites.
2. **Our own tests spelled it our way on both sides.** Six test files mention
   `bad_request`; not one asserted our emission of it. Same shape as the
   `entity-core/7.0` finding one week earlier — *a constant we chose, on a wire
   surface, that no local test can see because both sides of the assertion use
   our constant.* The remedy is the same: pin against **what the spec declares**,
   not against what we emit.
3. **The defect was written down and not read as one.** The §4.7 table file's
   own docstring says *"`ConnectError` defaults `code` to `bad_request` at the
   §4.7 400 class"* — accurately, one session earlier, while fixing the rows a
   probe named. A probe family names rows; nobody was assigned the default.

.. rubric:: What is asserted

The pair, on the wire, for a codeless refusal; the two constructors' defaults;
and a **ratchet at zero** on the literal, via the AST, so the synonym cannot
return through a new call site.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import ADVERTISED_PROTOCOLS, ConnectError
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import recv_envelope, send_envelope
from entity_core.protocol.messages import Execute, ExecuteResponse
from entity_core.utils.ecf import (
    DEFAULT_ADVERTISED_KEY_TYPES,
    default_advertised_hash_formats,
)

PORT = 19097

#: §3.3's 400 row, transcribed. The default plus the enumerated more-specific
#: set — a code outside this (and outside §4.7's connect-error codes) is one we
#: minted.
SECTION_3_3_GENERIC_400 = "invalid_request"
SECTION_3_3_SPECIFIC_400 = frozenset(
    {
        "invalid_path",
        "invalid_params",
        "unexpected_params",
        "chain_depth_exceeded",
        "signature_path_conflict",
    }
)


@pytest.fixture
async def server_peer():
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_default_handlers().debug_mode(True).build()
    )
    await peer.start("127.0.0.1", PORT)
    yield peer
    await peer.stop()


async def _hello_over_the_wire(data: dict[str, Any]) -> tuple[int, str]:
    """Drive one hello carrying `data` and return the responder's `(status, code)`."""
    reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
    try:
        execute = Execute.create(
            uri=f"entity://{data['peer_id']}/system/protocol/connect",
            operation="hello",
            params=Entity(
                type="system/protocol/connect/hello", data=data
            ).to_dict(),
        )
        await send_envelope(writer, Envelope(root=execute.to_entity()))
        response = await asyncio.wait_for(recv_envelope(reader), timeout=5.0)
        body = response.root["data"]
        result = body.get("result") or {}
        return int(body["status"]), (result.get("data") or {}).get("code", "")
    finally:
        writer.close()


class TestTheCodelessRefusalOnTheWire:
    """The behavioural half: a refusal that states no code still states §3.3's."""

    async def test_a_hello_missing_its_nonce_is_400_invalid_request(
        self, server_peer
    ) -> None:
        """The codeless `ConnectError` path, driven end to end.

        `raise ConnectError("Missing nonce in hello")` — no `code=`, so this row
        measures the **default**, which is the thing that was wrong. It is also
        squarely inside 0.8.2.4's own description of the class: *"a well-formed
        frame whose content the responder cannot act on as a request."*
        """
        keypair = Keypair.generate()
        status, code = await _hello_over_the_wire(
            {
                "peer_id": keypair.peer_id,
                "protocols": list(ADVERTISED_PROTOCOLS),
                "hash_formats": default_advertised_hash_formats(),
                "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
            }
        )
        assert (status, code) == (400, SECTION_3_3_GENERIC_400), (
            "a codeless connect refusal must carry §3.3's declared generic 400 "
            f"code; got ({status}, {code!r})"
        )

    async def test_the_code_is_never_the_synonym(self, server_peer) -> None:
        """The discriminating row, and it needs saying why it is separate.

        The row above is satisfied by a peer that special-cases *this one raise*
        — which is precisely the shape of fix a probe naming one row produces,
        and precisely what happened here one session earlier. This row asserts
        the property instead: across a spread of malformed hellos, **no** refusal
        carries the synonym.
        """
        keypair = Keypair.generate()
        base = {
            "peer_id": keypair.peer_id,
            "nonce": b"\x07" * 32,
            "protocols": list(ADVERTISED_PROTOCOLS),
            "hash_formats": default_advertised_hash_formats(),
            "key_types": list(DEFAULT_ADVERTISED_KEY_TYPES),
        }
        inputs = {
            "no nonce": {k: v for k, v in base.items() if k != "nonce"},
            "no peer_id": {**base, "peer_id": ""},
            "empty protocols": {**base, "protocols": []},
        }
        seen: dict[str, tuple[int, str]] = {}
        for label, data in inputs.items():
            data.setdefault("peer_id", keypair.peer_id)
            seen[label] = await _hello_over_the_wire(data)

        offenders = {k: v for k, v in seen.items() if v[1] == "bad_request"}
        assert not offenders, (
            f"`bad_request` is in no spec code set (§3.3, §4.7 0.8.2.4): {offenders}"
        )
        assert all(
            code == SECTION_3_3_GENERIC_400 or code in SECTION_3_3_SPECIFIC_400
            for _, code in seen.values()
        ), f"a 400 code outside §3.3's set: {seen}"


class TestTheConstructorDefaults:
    """The unit half — pinned against §3.3's text, not against what we emit."""

    def test_execute_response_bad_request_defaults_to_the_declared_generic(
        self,
    ) -> None:
        """The method keeps its Python name; only the wire code moved.

        `ExecuteResponse.bad_request` is named for HTTP's 400, which is fine —
        it is an identifier. The `code` it *puts on the wire* is a spec value
        and was the same string, which is how one reads as a justification for
        the other.
        """
        response = ExecuteResponse.bad_request(request_id="r", message="m")
        assert int(response.status) == 400
        assert isinstance(response.result, dict)
        assert response.result["code"] == SECTION_3_3_GENERIC_400

    def test_connect_error_defaults_to_the_declared_generic(self) -> None:
        assert ConnectError("m").code == SECTION_3_3_GENERIC_400

    def test_the_dialer_extractor_does_not_fabricate_a_code(self) -> None:
        """The one place the value must NOT become `invalid_request`.

        `connect_refusal` reports what the **remote** said. Filling an absent
        `code` with the generic would have this peer manufacture a claim about a
        peer that made none — and a non-conformant peer answering a coded status
        with no code is the case worth being able to see. It carried
        `"bad_request"`, which read as a wire code and was not one; it now
        carries the empty string, which cannot be mistaken for an answer.
        """
        from entity_core.handlers.connect import connect_refusal

        refusal = connect_refusal(
            "hello failed",
            ExecuteResponse(request_id="r", status=400, result={"message": "no code"}),
        )
        assert refusal.code == "", (
            "an absent remote code must stay absent, not become a plausible one"
        )


class TestTheSynonymIsRatchetedAtZero:
    """No `"bad_request"` string literal in the packages, counted via the AST."""

    def test_no_bad_request_literal_remains_in_the_packages(self) -> None:
        """A hard zero, and the AST is what makes it one.

        Read as lines, this gate would count the four comments and docstrings
        that *explain* the retired synonym — the standing "a gate that cannot
        tell a sanctioned mention from a smuggled call is not a gate" shape,
        which has inflated a count in this repo four times now (`entity://` in
        docstrings, the `fnmatch` call-site comment, the version string, here).
        An `ast.Constant` equal to the literal is a second source of truth; a
        docstring is one Constant holding a paragraph and never equals it.

        The identifier `ExecuteResponse.bad_request` is untouched by this gate,
        which is the intended line: the Python name is ours, the wire code is
        the spec's.

        **The gate corrected its author on its first run**, which is what a gate
        is for: it found `peer.py`'s `getattr(e, "code", "bad_request")` — a
        fallback on an exception that always carries a code, so it was invisible
        to the read that fixed the constructor default — and the signaling
        exemption, which was not a miss but a corpus conflict.

        **The exemption is gone and this is a hard zero across every package**
        (2026-09-02). SIGNALING v1.2 ruled SA-PY-33 in the shape the row below
        wrote down as its first branch: §4.7's MUST NOT is scoped to the wrapped
        EXECUTE surface, §4.3 named `bad_request` there and was the thing that
        was wrong, and §9.2's unwrapped enum is unchanged. Our node serves the
        wrapped surface only — there is no §9 listener in this tree — so the
        directory-wide hole closes to nothing rather than narrowing.
        """
        root = Path(__file__).resolve().parents[2] / "packages"
        offenders: list[str] = []

        for path in root.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if isinstance(node, ast.Constant) and node.value == "bad_request":
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}")

        assert not offenders, (
            "`bad_request` is not a code in any spec code set — §3.3 declares "
            "`invalid_request` as the generic 400 and 0.8.2.4 forbids minting a "
            f"synonym. New literals: {offenders}"
        )

    def test_the_signaling_exemption_retired_on_the_condition_it_wrote_down(
        self,
    ) -> None:
        """SA-PY-33, closed — and the row is re-pointed rather than deleted.

        This row used to hold the ratchet's one exemption open. `EXTENSION-
        SIGNALING` §9.2 pinned a **closed** enum containing `bad_request` for
        the same class core §4.7 (0.8.2.4) says must be `invalid_request` and
        MUST NOT be given a synonym; both sentences were landed and normative,
        so it was **filed, not fixed** — changing it unilaterally would have
        broken a pinned enum and manufactured a cross-impl divergence out of a
        spec conflict, which is the error this repo exists to find in other
        stacks. `entity-core-go` carried the identical string at the matching
        site, which is what made it a corpus conflict rather than one seat being
        sloppy.

        **The written retirement condition was:** *"upstream rules which
        sentence wins. If §4.7's MUST NOT is scoped to the EXECUTE surface,
        signaling's enum moves and this exemption goes with it."* SIGNALING
        **v1.2** ruled exactly that. The defect was one line and it was not in
        §9.2 at all: **§4.3** — which sits in §4 *Handler and Operations*, the
        wrapped section — listed `bad_request` as an EXECUTE error, so both
        seats implemented the spec correctly and the spec was wrong. §4.3 now
        reads `invalid_request`; §9.2 is untouched and still says `bad_request`
        for the `error: tstr` values of the §9 non-entity protocol, which §4.7
        does not reach.

        So this row now asserts the **wrapped** side, which is the only side
        this tree serves: signaling emits the core code and holds no copy of the
        unwrapped enum. A reader who found the class simply deleted would have
        no way to learn that the two surfaces legitimately spell one class two
        ways — and the next person to build the §9 listener needs to know the
        exemption is re-arguable *for that file only*, not that it was a mistake.

        Third recorded instance of a deferral's forward half executing as
        written (after the §8.2 arg-order skip and the §4.5 absent-arm row).
        """
        root = Path(__file__).resolve().parents[2] / "packages"
        signaling = [p for p in root.rglob("*.py") if p.match("*/signaling/*")]
        assert signaling, "the signaling package moved; this row is measuring nothing"

        residue = sorted(
            f"{path.relative_to(root)}:{node.lineno}"
            for path in signaling
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Constant) and node.value == "bad_request"
        )
        assert residue == [], (
            "SIGNALING v1.2 moved §4.3 to `invalid_request` and this node serves "
            "the wrapped surface only, so the exemption is retired. A `bad_request` "
            "here again is either the §9 unwrapped listener arriving — in which "
            f"case re-open the exemption for that file deliberately — or a relapse: {residue}"
        )

        from entity_handlers.signaling.node import CODE_INVALID_REQUEST

        assert CODE_INVALID_REQUEST == "invalid_request", (
            "§4.3 (v1.2) is the wrapped surface's code list and it names the "
            "core's generic 400"
        )
