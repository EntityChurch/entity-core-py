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

Cap-passing convention (§7a.2a, Go ruling): the three
reentry-authority entities travel **in-band, nested in params**
(``reentry_capability`` / ``reentry_granter`` / ``reentry_cap_signature``),
NOT via the envelope ``included`` set. See the V7.74-A013 Go cap-passing
ruling.
"""

from __future__ import annotations

from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity

from entity_handlers.manifest import build_handler_manifest

# Spec patterns (GUIDE-CONFORMANCE §7a.1).
ECHO_HANDLER_PATTERN = "system/validate/echo"
DISPATCH_OUTBOUND_HANDLER_PATTERN = "system/validate/dispatch-outbound"


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

    On ``dispatch``: decode the three in-band reentry-authority entities
    (§7a.2a), re-canonicalize each, then originate exactly ONE outbound
    EXECUTE via the §6.13(b) seam (``ctx.execute_with_capability``) to
    ``operation`` @ ``target`` — which the validator sets to itself, so the
    EXECUTE travels back over the same inbound connection (the §6.11 reentry
    surface). Returns ``{status, result}`` from the downstream response.
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
            return _error(
                500, "internal",
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
        granter_raw = data.get("reentry_granter")
        sig_raw = data.get("reentry_cap_signature")

        if not target or not op:
            return _error(
                400, "invalid_params",
                "dispatch-outbound requires target and operation",
            )
        if cap_raw is None or granter_raw is None or sig_raw is None:
            return _error(
                400, "invalid_params",
                "dispatch-outbound requires reentry_capability + "
                "reentry_granter + reentry_cap_signature in-band per §7a.2a",
            )

        # Re-canonicalize the three in-band authority entities: recompute each
        # content_hash from {type, data} only — the same rule applied
        # everywhere. The fields rode as nested CBOR maps, so they arrive as
        # decoded dicts; rebuilding through Entity recomputes the hash.
        try:
            cap = _recanonicalize(cap_raw)
            granter = _recanonicalize(granter_raw)
            sig = _recanonicalize(sig_raw)
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
        # chain [granter, signature] rides in the envelope `included` so the
        # caller's verifier finds it. For the cross-peer (caller) target the
        # dispatcher routes through §6.11 reentry — reusing the inbound
        # connection, no fresh dial.
        result = await ctx.execute_with_capability(
            target,
            op,
            outbound_params,
            dispatch_capability_entity=cap,
            dispatch_capability_chain=[granter, sig],
        )
        if not result.ok:
            return _error(
                502, "reentry_dispatch_failed",
                "originate reentry EXECUTE: "
                f"status={result.status} {result.error or ''}".strip(),
            )

        # Pack the downstream EXECUTE_RESPONSE into the §7a.1 result shape,
        # wrapped as a primitive/any result entity.
        inner = {"status": result.status, "result": result.result}
        return {
            "status": 200,
            "result": Entity(type="primitive/any", data=inner).to_dict(),
        }


def _recanonicalize(entity_dict: Any) -> dict[str, Any]:
    """Rebuild an entity dict so content_hash is recomputed from {type,data}.

    Mirrors Go's ``entity.NewEntity(e.Type, e.Data)`` re-canonicalization in
    the dispatch-outbound handler.
    """
    if not isinstance(entity_dict, dict):
        raise ValueError("authority entity is not an object")
    return Entity(
        type=entity_dict["type"],
        data=entity_dict["data"],
    ).to_dict()
