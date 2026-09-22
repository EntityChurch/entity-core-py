"""GUIDE-CONFORMANCE §7a — the two ``system/validate/*`` test handlers.

These handlers are conformance *scaffolding*, not core protocol and not an
extension. They expose two existing core capabilities at well-known patterns
so a black-box validator can probe them:

- ``system/validate/echo`` exercises V7 §6.13(a) handler dispatch
  (resolve a URI → run a handler), with a verbatim-echo contract.
- ``system/validate/dispatch-outbound`` exercises V7 §6.13(b) — a handler
  originating one outbound EXECUTE during its own dispatch — routed through
  the §6.11 reentry seam back to the caller over the same inbound connection.

In a core-only peer (no compute, no continuation, no subscription, no inbox)
neither capability has any other wire-reachable trigger; that is the whole
reason this module exists (resolves A-011 + A-013 per GUIDE-CONFORMANCE §7a).

Both handlers are OFF by default. The wire host opts in via
``PeerBuilder.with_conformance_handlers()`` (typically driven from a
host-level ``--validate`` flag). A peer without the opt-in 404s the two
patterns and the validator SKIPs honestly per §7a.4.

**Do not enable in production.** ``dispatch-outbound`` originates outbound
EXECUTEs from caller-supplied params — exactly the surface you do not want
exposed unless the validator is the only thing wired to it.

Cap-passing convention (§7a.2a, RATIFIED shape (a)): the reentry-authority
entities travel **in-band, nested in params** (``reentry_capability`` /
``reentry_granters`` / ``reentry_cap_signatures``), NOT via the envelope
``included`` set. The two carriers are **PLURAL** as of 0.8.2.19 — see
:data:`DISPATCH_OUTBOUND_HANDLER_PATTERN`'s handler below.
"""

from __future__ import annotations

from typing import Any

from entity_core.capability.grant import Grant
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ALG_ECFV1_SHA256

from entity_handlers.manifest import build_handler_manifest

# Spec patterns (GUIDE-CONFORMANCE §7a.1).
ECHO_HANDLER_PATTERN = "system/validate/echo"
DISPATCH_OUTBOUND_HANDLER_PATTERN = "system/validate/dispatch-outbound"


def dispatch_outbound_narrow_grant() -> list[Grant]:
    """The ⛔ NARROW grant `system/validate/dispatch-outbound` runs under.

    GUIDE-CONFORMANCE §7a.1's ⛔ block makes this a **scaffold-contract
    requirement, not a hardening choice**: the handler's own grant — the
    ceiling §1.4's outbound gate enforces on Dimensions 1-3 — MUST be scoped
    to a fixed, declared operation set, **not** the peer's wide default
    self-grant.

    .. rubric:: Why a wide grant makes the whole check set blind

    §1.4's outbound gate admits two authority contributions: the executing
    handler's grant (Dimensions 1-3, always) and a target-minted credential
    (Dimension 4 only). A check set MUST discriminate a **compose** from a
    **bypass**, and the discriminating vector is *a valid credential presented
    to a handler whose own grant does not cover the request → MUST refuse*.

    **Against a wide grant that vector is unconstructible** — if the grant
    already covers every operation, the composed reading and the bypassed
    reading return the same answer for every input a probe can send, so the
    probe sits exactly where the two readings agree. That is how the F67
    confused-deputy bypass passed two green wire rows at all three reference
    seats and across 46 generated peers. This grant is what makes go's
    ``dispatch_outbound_narrow_grant_refuses_out_of_scope`` (F63) observable
    **on the wire** at this seat rather than only in-process.

    .. rubric:: Why the reentry contract still passes under it

    The declared minimum is `echo` on ``system/validate/echo`` — the only
    operation §7a.2a's reentry contract needs. In-scope (``op=echo``):
    Dimensions 1-2 covered here, Dimension 3 skipped (echo names no resource
    target), Dimension 4 relaxed by the caller-minted reentry credential.
    An out-of-scope operation fails **Dimension 1** unless the credential is
    wrongly treated as a standalone authorizer — which is the bug.

    ``peers`` is OMITTED, per §6.2's default and for the same reason: the
    reentry direction's Dimension 4 comes from the caller-minted credential,
    never from this grant. A ``peers`` scope here would re-open on Dimension 4
    exactly what the narrow handler/operation scope closes on 1-2.

    Cohort: byte-parallel with `entity-core-go`'s
    ``DispatchOutboundHandler.Manifest().InternalScope`` (`c46eebd`) — same
    three scopes, same omission. Stated as convergence on a **ruled**
    scaffold contract (§7a.1), not on a sibling's shape.
    """
    return [
        Grant.create(
            handlers=[ECHO_HANDLER_PATTERN],
            operations=["echo"],
            resources=[f"/*/{ECHO_HANDLER_PATTERN}"],
        )
    ]


def _error(status: int, code: str, message: str) -> dict[str, Any]:
    """Build a handler error return mapping to a standard status + code."""
    return {"status": status, "result": {"code": code, "message": message}}


class EchoHandler:
    """``system/validate/echo`` — proves §6.13(a) resolve→dispatch.

    Operation ``echo`` returns the params entity verbatim. The §7a.1
    contract is byte-exact: ``result.data`` byte-equals ``params.data`` for
    any ECF value the caller passes. The contract is satisfied by returning
    the params entity *itself* with no decode/re-encode roundtrip.
    """

    @property
    def name(self) -> str:
        return "validate/echo"

    def manifest(self) -> Entity:
        return build_handler_manifest(
            name="validate/echo",
            pattern=ECHO_HANDLER_PATTERN,
            operations={
                "echo": {
                    "input_type": "primitive/any",
                    "output_type": "primitive/any",
                },
            },
        )

    async def __call__(
        self,
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        if operation != "echo":
            return _error(
                501, "unsupported_operation",
                f"system/validate/echo: operation {operation!r} not supported",
            )
        # Verbatim echo: the result entity IS the params entity. Returning
        # it unmodified keeps result.data byte-identical to params.data
        # (§7a.1) — no ECF decode/re-encode that could perturb map-key
        # ordering or tag canonicalization.
        return {"status": 200, "result": params}


class DispatchOutboundHandler:
    """``system/validate/dispatch-outbound`` — proves §6.13(b)/§6.11.

    On ``dispatch``: decode the in-band reentry-authority entities (§7a.2a),
    re-canonicalize each, then originate exactly ONE outbound EXECUTE via the
    §6.13(b) seam (``ctx.execute_with_capability``) to ``operation`` @
    ``target`` — which the validator sets to itself, so the EXECUTE travels
    back over the same inbound connection (the §6.11 reentry surface).
    Returns ``{status, result}`` from the downstream response.

    .. rubric:: The carriers are PLURAL (§7a.1, 0.8.2.19)

    ``reentry_granters`` and ``reentry_cap_signatures`` are **arrays**; the
    single-granter case is an array of one. They were singular, **and that
    made one normative rule ungateable**: §1.4's multi-signature root rule
    needs a K-of-2 root to drive it, which takes *two* granter identities and
    *two* signatures. A singular carrier cannot express the input, so every
    seat drove that rule in-process only — where a mutation proves your own
    gate and says nothing about the cohort's.

    The set is **all-or-none**: supplying the capability plus at least one of
    each carrier selects the *presented* arm; omitting all three selects the
    *ambient* arm; **a partial set is `400 invalid_params`** — a partial
    credential is malformed, not a decision to dispatch ambiently.

    This handler runs under a NARROW grant (see
    :func:`dispatch_outbound_narrow_grant`), which is what makes the presented
    arm's compose-vs-bypass discriminator constructible at all.
    """

    @property
    def name(self) -> str:
        return "validate/dispatch-outbound"

    def manifest(self) -> Entity:
        return build_handler_manifest(
            name="validate/dispatch-outbound",
            pattern=DISPATCH_OUTBOUND_HANDLER_PATTERN,
            operations={
                "dispatch": {
                    "input_type": "primitive/any",
                    "output_type": "primitive/any",
                },
            },
        )

    async def __call__(
        self,
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        if operation != "dispatch":
            return _error(
                501, "unsupported_operation",
                "system/validate/dispatch-outbound: operation "
                f"{operation!r} not supported",
            )
        # The §6.13(b) seam must be wired for any reentry to be possible.
        if getattr(ctx, "_execute_dispatcher", None) is None:
            # §3.3's 500 row default (0.8.2.6). `internal` was a bare
            # abbreviation in no spec code set; the row names `internal_error`
            # and this site carries no more-specific *defined* code, so the
            # default is mandatory. This is py's only bare-`internal` site —
            # the ~16 specific 500 spellings elsewhere are **held** pending
            # arch's per-extension error-code tables (OP-3), not swept.
            return _error(
                500, "internal_error",
                "dispatcher did not wire the outbound seam (§6.13(b))",
            )

        # Params is entity-shaped on the wire (§3.4); the payload is in .data.
        data = params.get("data", params) if isinstance(params, dict) else params
        if not isinstance(data, dict):
            return _error(
                400, "invalid_params",
                "dispatch-outbound params must be a primitive/any object",
            )

        target = data.get("target")
        op = data.get("operation")
        value = data.get("value")
        cap_raw = data.get("reentry_capability")
        granters_raw = data.get("reentry_granters")
        sigs_raw = data.get("reentry_cap_signatures")

        if not target or not op:
            return _error(
                400, "invalid_params",
                "dispatch-outbound requires target and operation",
            )

        # §7a.1's plural carriers, as an all-or-none SET. `present` is
        # deliberately a disjunction and the malformed check a conjunction:
        # anything supplied at all selects the presented arm, and the arm then
        # requires the complete triple. Reading `present` off the capability
        # alone would silently drop a caller's granters, which is the shape
        # that turns a partial credential into an ambient dispatch.
        n_granters = len(granters_raw) if isinstance(granters_raw, list) else 0
        n_sigs = len(sigs_raw) if isinstance(sigs_raw, list) else 0
        has_cap = cap_raw is not None
        present = has_cap or n_granters > 0 or n_sigs > 0
        if not present:
            # §1.4 PD-2's **ambient** arm, and the reason this is reachable at
            # all: the negative arm of 0.8.2.17's conformance row is *"drive
            # `system/validate/dispatch-outbound` at a foreign peer presenting
            # no capability → MUST refuse"*, and a handler that refuses the
            # request at param validation answers it for the wrong reason. A
            # probe would see a refusal and could not attribute it to
            # Dimension 4 — the same shape as a peer that refuses everything
            # passing a refusal-only check.
            #
            # So the three in-band authority fields are optional **as a set**.
            # Supplying them is unchanged (§7a.2a, ruled shape (a)); omitting
            # all three originates on the handler's own grant, which is what
            # the ambient arm is. Supplying some and not others stays a 400:
            # a partial credential is a malformed request, not a decision to
            # dispatch ambiently.
            #
            # This widens what the test handler accepts and nothing else — an
            # ambient outbound dispatch is now *attempted* and the outbound
            # check is what refuses it. Routed to the cohort so all three
            # seats drive the same input rather than three different ones.
            outbound_params = Entity(type="primitive/any", data=value).to_dict()
            result = await ctx.execute(target, op, outbound_params)
            refused = _relay_outbound_refusal(result, "ambient")
            if refused is not None:
                return refused
            inner = {"status": result.status, "result": result.result}
            return {
                "status": 200,
                "result": Entity(type="primitive/any", data=inner).to_dict(),
            }
        if not has_cap or n_granters == 0 or n_sigs == 0:
            return _error(
                400, "invalid_params",
                "dispatch-outbound requires reentry_capability + at least one "
                "reentry_granters + at least one reentry_cap_signatures "
                "together (§7a.1, plural since 0.8.2.19), or all three "
                "omitted (§7a.2a; omitting all three originates on the "
                "handler's own grant — §1.4 PD-2's ambient arm). A partial "
                "credential is malformed, not ambient.",
            )

        # Re-canonicalize the in-band authority entities: recompute each
        # content_hash from {type, data} only — the same rule applied
        # everywhere. The fields rode as nested CBOR maps, so they arrive as
        # decoded dicts; rebuilding through Entity recomputes the hash.
        try:
            cap = _recanonicalize(cap_raw)
            chain = [_recanonicalize(g) for g in granters_raw]
            chain += [_recanonicalize(s) for s in sigs_raw]
        except Exception as e:  # noqa: BLE001
            return _error(
                400, "invalid_params",
                f"decode reentry authority entities: {e}",
            )

        # Wrap the opaque value as a primitive/any entity for the §3.4
        # "params is an entity" requirement at the wire.
        outbound_params = Entity(type="primitive/any", data=value).to_dict()

        # Originate exactly one outbound EXECUTE through the §6.13(b) seam.
        # The cap authorizes the EXECUTE (its grantee is this peer); the
        # chain — every granter identity followed by every signature — rides
        # in the envelope `included` so the caller's verifier finds it. A
        # K-of-N root needs all N granters and all N signatures present, which
        # is the whole reason the carriers went plural. For the cross-peer
        # (caller) target the dispatcher routes through §6.11 reentry —
        # reusing the inbound connection, no fresh dial.
        result = await ctx.execute_with_capability(
            target,
            op,
            outbound_params,
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        refused = _relay_outbound_refusal(result, "reentry")
        if refused is not None:
            return refused

        # Pack the downstream EXECUTE_RESPONSE into the §7a.1 result shape,
        # wrapped as a primitive/any result entity.
        inner = {"status": result.status, "result": result.result}
        return {
            "status": 200,
            "result": Entity(type="primitive/any", data=inner).to_dict(),
        }


def _relay_outbound_refusal(result: Any, arm: str) -> dict[str, Any] | None:
    """Relay an outbound sub-dispatch refusal, or ``None`` if it succeeded.

    .. rubric:: `GUIDE-CONFORMANCE` §7a.1a — the code is pinned, the shape is not

    A scaffold handler is where a §1.4 outbound refusal is **caught and
    re-emitted**, and a handler that wraps every unsuccessful sub-dispatch in
    one generic failure **launders an authorization verdict into a transport
    fault**. §3.3's authorization-path discipline forbids the generic catch-all
    and normalizes the code *regardless of which pipeline layer detected the
    rejection*, so a caller cannot read a peer's internals off its error codes.
    A §1.4 outbound refusal is an authorization DENY whichever dimension raised
    it → **`capability_denied`**.

    .. rubric:: Why this is one function and not a branch in each arm

    It was two arms disagreeing about what one gate decided: the ambient arm
    carried the `403` relay *and the argument for it*, and the
    credential-presented arm forty lines below returned a blanket `502` with no
    `403` branch. Arch found it by reading this file — the seat had written the
    refutation of its own defect in the arm above. One function, both arms, so
    the two cannot drift again; the ``arm`` label keeps the message
    attributable without giving either arm its own rule.

    .. rubric:: The neighbouring arm is PINNED, not settled

    Only `403` is relayed. A §1.4 outbound refusal that surfaces as a **`400`**
    — which this peer can produce, since `PD-1h` moved the foreign-namespace
    refusal from §5.2 authorization to §1.4 canonicalization — is still wrapped
    as `502` below, i.e. laundered in exactly the way §7a.1a forbids, one
    status over. That is filed as **SA-PY-48** rather than fixed here: widening
    the relay would have this scaffold decide which downstream statuses are
    verdicts and which are transport, and inventing that classification is the
    thing this repo exists to catch other people doing. Retirement condition:
    arch rules whether §7a.1a's normalization binds the whole 4xx class or only
    the authorization status.
    """
    if result.status == 403:
        # Relayed, not wrapped. A blanket 502 here would make the negative arm
        # unattributable a second time — one status for "Dimension 4 refused
        # this" and for "there was no route", which are the two outcomes the
        # arm exists to tell apart.
        return _error(
            403, "capability_denied",
            f"{arm} outbound sub-dispatch refused before leaving the peer "
            f"(§1.4 PD-2): {result.error or ''}".strip(),
        )
    if not result.ok:
        return _error(
            502, "reentry_dispatch_failed",
            f"originate {arm} EXECUTE: "
            f"status={result.status} {result.error or ''}".strip(),
        )
    return None


def _recanonicalize(entity_dict: Any) -> dict[str, Any]:
    """Rebuild an entity dict so content_hash is recomputed from {type,data}.

    .. rubric:: ``system/peer`` is floor-pinned here, and it is not cosmetic

    V7 §4.5a **item 1a** pins the identity entity to ECFv1-SHA-256 (0x00)
    **unconditionally** — whatever this peer's home format. Rebuilding a
    granter identity under the process-global authoring default is therefore a
    latent defect on a peer running a non-floor format (e.g. ``sha384``): it
    manufactures a *second* content_hash for the one identity item 1a exists
    to collapse, on the exact surface where §5.2's granter/grantee equality is
    evaluated. It would never fail a check on a same-format peer, because both
    sides of every downstream comparison are wrong the same way — our own
    constant against our own constant.

    Found by `entity-core-go` at their matching site (`c46eebd`); confirmed
    live here rather than accepted from their report. **Keyed on the entity
    TYPE, not on the carrier position** — go pins the ``reentry_granters``
    array positionally, which is right for every well-formed input but reads
    the rule off where a value happened to travel. Item 1a is a statement
    about ``system/peer`` entities; an identity arriving in any position gets
    the floor, and a non-identity in the granters array does not get a pin the
    spec never gave it. Routed as a note, not a divergence: the two agree on
    every input either seat can construct.
    """
    if not isinstance(entity_dict, dict):
        raise ValueError("authority entity is not an object")
    etype = entity_dict["type"]
    return Entity(
        type=etype,
        data=entity_dict["data"],
        hash_algorithm=ALG_ECFV1_SHA256 if etype == "system/peer" else None,
    ).to_dict()
