"""Core Protocol message types.

Protocol Messages (only two wire message types):
- EXECUTE: Universal operation request
- EXECUTE_RESPONSE: Operation result

Connect hello/authenticate are carried as EXECUTE operations, not separate types.

Architecture:
- Refless architecture: author and capability are in data, not refs
- Signature found via target-matching in envelope's included map
- author, capability, and token are bytes (Hash), not strings
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from entity_core.primitives import Uint, TreePath
from entity_core.protocol.bounds import Bounds
from entity_core.utils.ecf import (
    Hash,
    compute_ecf_hash,
    get_default_hash_algorithm,
)

# Forward declaration for type hints
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entity_core.protocol.delivery import DeliverySpec
    from entity_core.protocol.durability import DurabilityRequest, DurabilityResult


@dataclass
class ResourceTarget:
    """system/protocol/resource-target.

    Enables dispatch-level resource authorization by specifying which
    resources the request intends to access.

    Attributes:
        targets: List of resource path patterns the request targets.
        exclude: Optional list of patterns to exclude from targets.
    """

    TYPE_NAME = "system/protocol/resource-target"

    targets: list[TreePath]
    exclude: list[TreePath] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to wire format."""
        result: dict[str, Any] = {"targets": self.targets}
        if self.exclude:
            result["exclude"] = self.exclude
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceTarget:
        """Parse from wire format."""
        return cls(
            targets=data.get("targets", []),
            exclude=data.get("exclude"),
        )


def compute_content_hash(
    type_str: str, data: Any, algorithm: int | None = None,
) -> Hash:
    """Compute content hash for an entity.

    Args:
        type_str: Entity type.
        data: Entity data (dict, or any CBOR-encodable value for
            primitive-typed entities).
        algorithm: V7 v7.69 §4.5a content_hash_format to author under.
            ``None`` uses the process-global default (connection-bound
            callers thread the negotiated active format).

    Returns:
        Hash as bytes (algorithm byte + digest).
    """
    if algorithm is None:
        algorithm = get_default_hash_algorithm()
    hashable = {"type": type_str, "data": data}
    return compute_ecf_hash(hashable, algorithm)


def _as_entity(value: Any) -> dict[str, Any]:
    """Normalize a value to entity shape ``{type, data, content_hash}``.

    Per ENTITY-CORE-PROTOCOL-V7 §3.4, the ``params`` field of EXECUTE and
    the ``result`` field of EXECUTE_RESPONSE are typed as ``entity`` —
    they MUST appear on the wire as materialized entities, not raw data
    values. Internal handler code commonly passes raw dicts or produces
    partial entity shapes (``{type, data}`` without ``content_hash``);
    this helper normalizes both into a spec-compliant envelope.

    Rules:
    - dict with ``type`` + ``data`` keys -> keep the shape; fill in
      ``content_hash`` if missing.
    - anything else -> wrap as ``primitive/any`` with the original value
      as ``data``.

    This is the send-side shim. Receivers that see legacy raw-dict
    params on the wire still work because every handler has a
    ``params.get("data", params)`` fallback.
    """
    if isinstance(value, dict) and "type" in value and "data" in value:
        entity_type = value["type"]
        entity_data = value["data"]
        return {
            "type": entity_type,
            "data": entity_data,
            "content_hash": value.get("content_hash")
            or compute_content_hash(entity_type, entity_data),
        }
    return {
        "type": "primitive/any",
        "data": value,
        "content_hash": compute_content_hash("primitive/any", value),
    }


def unwrap_entity(value: Any) -> Any:
    """Inverse of :func:`_as_entity` for use on the receive side.

    If ``value`` is an entity envelope ``{type, data, content_hash}``,
    returns the inner ``data``. Otherwise returns ``value`` unchanged —
    tolerates legacy raw-dict senders during the transition.

    Keeping internal code (handlers, protocol consumers) working against
    raw dicts simplifies the change: the wire contract is fixed in one
    place without rippling through every handler.
    """
    if (
        isinstance(value, dict)
        and "type" in value
        and "data" in value
        and "content_hash" in value
    ):
        return value["data"]
    return value


@dataclass
class Execute:
    """Operation request message.

    The universal operation message. Uses path-based routing to dispatch
    to appropriate handlers.

    Required fields: request_id, uri, operation, params
    Optional fields: stream, author, capability, resource, deliver_to, deliver_token

    - author and capability are bytes (Hash) in data, not refs
    - Signature found via target-matching, not in refs
    - resource field enables dispatch-level resource authorization
    - deliver_to/deliver_token enable async result delivery (v7.8 inbox)
    """

    request_id: str
    uri: TreePath
    operation: str
    params: Any  # Any JSON value (required per spec 2.4)
    stream: bool | None = None  # Whether to stream the response
    bounds: Bounds | None = None  # Resource bounds

    # Authentication fields (in data per refless architecture)
    author: Hash | None = None  # Hash of author identity
    capability: Hash | None = None  # Hash of capability token

    # Resource authorization
    resource: ResourceTarget | None = None  # Resource targets for dispatch-level auth

    # V7.8 Inbox Extension: Async delivery
    deliver_to: "DeliverySpec | None" = None  # Where to deliver async results
    deliver_token: Hash | None = None  # Capability authorizing inbox delivery

    # EXTENSION-DURABILITY §2: optional request-side durability marker.
    # Additive and independent of deliver_to — durability-unaware callers
    # never set it and are unaffected. The extension is exploratory and
    # optional; peers that don't install it are unaffected by this field.
    durability_request: "DurabilityRequest | None" = None

    TYPE = "system/protocol/execute"

    @classmethod
    def create(
        cls,
        uri: str,
        operation: str,
        params: dict[str, Any] | None = None,
        stream: bool | None = None,
        bounds: Bounds | None = None,
        resource: ResourceTarget | None = None,
        deliver_to: "DeliverySpec | None" = None,
        deliver_token: Hash | None = None,
        durability_request: "DurabilityRequest | None" = None,
    ) -> Execute:
        """Create an EXECUTE with fresh request_id.

        Args:
            uri: Target entity URI.
            operation: Operation to perform (read, write, list, etc.).
            params: Operation-specific parameters.
            stream: Whether to stream the response.
            bounds: Resource bounds.
            resource: Resource targets for dispatch-level auth.
            deliver_to: Async delivery destination (v7.8 inbox).
            deliver_token: Capability authorizing inbox delivery.

        Returns:
            An Execute message ready to send.
        """
        return cls(
            request_id=str(uuid.uuid4()),
            uri=uri,
            operation=operation,
            params=params if params is not None else {},
            stream=stream,
            bounds=bounds,
            resource=resource,
            deliver_to=deliver_to,
            deliver_token=deliver_token,
            durability_request=durability_request,
        )

    def to_entity(self, algorithm: int | None = None) -> dict[str, Any]:
        """Convert to entity dictionary for wire transmission.

        Per §3.4, ``params`` is entity-typed on the wire: emit as
        ``{type, data, content_hash}`` even when handlers passed a raw
        dict internally.

        ``algorithm`` (V7 v7.69 §4.5a) is the connection's active
        content_hash_format; ``None`` uses the process-global default.
        The execute root hash is what the request signature targets, so a
        connection-bound caller MUST pass the negotiated active format.
        """
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "uri": self.uri,
            "operation": self.operation,
            "params": _as_entity(self.params),
        }
        if self.stream is not None:
            data["stream"] = self.stream
        if self.bounds is not None:
            bounds_dict = self.bounds.to_dict()
            if bounds_dict:  # Only include if non-empty
                data["bounds"] = bounds_dict
        if self.author:
            data["author"] = self.author
        if self.capability:
            data["capability"] = self.capability
        if self.resource is not None:
            data["resource"] = self.resource.to_dict()
        if self.deliver_to is not None:
            data["deliver_to"] = self.deliver_to.to_dict()
        if self.deliver_token is not None:
            data["deliver_token"] = self.deliver_token
        if self.durability_request is not None:
            data["durability_request"] = self.durability_request.to_dict()
        h = compute_content_hash(self.TYPE, data, algorithm)
        return {
            "type": self.TYPE,
            "data": data,
            "content_hash": h,
        }

    @classmethod
    def from_entity(cls, entity: dict[str, Any]) -> Execute:
        """Parse from entity dictionary.

        Per §3.4 ``params`` is entity-shaped on the wire. We keep it
        entity-shaped here — connect authenticate needs the envelope's
        ``content_hash`` for signature target-matching, and handlers
        that want just the payload use ``params.get("data", params)``.
        """
        from entity_core.protocol.delivery import DeliverySpec
        from entity_core.protocol.durability import DurabilityRequest

        data = entity["data"]
        bounds_data = data.get("bounds")
        resource_data = data.get("resource")
        deliver_to_data = data.get("deliver_to")
        durability_data = data.get("durability_request")
        return cls(
            request_id=data["request_id"],
            uri=data["uri"],
            operation=data["operation"],
            params=data.get("params", {}),
            stream=data.get("stream"),
            bounds=Bounds.from_dict(bounds_data) if bounds_data else None,
            author=data.get("author"),
            capability=data.get("capability"),
            resource=ResourceTarget.from_dict(resource_data) if resource_data else None,
            deliver_to=DeliverySpec.from_dict(deliver_to_data) if deliver_to_data else None,
            deliver_token=data.get("deliver_token"),
            durability_request=(
                DurabilityRequest.from_dict(durability_data)
                if durability_data
                else None
            ),
        )


@dataclass
class ExecuteResponse:
    """Operation result message.

    Contains the result of an EXECUTE request.
    Status codes follow HTTP conventions (200=success, 403=forbidden, etc.).

    EXECUTE_RESPONSE has exactly 3 fields: request_id, status, result.
    For connect authenticate, the token is in result.data.token (not at this level).
    """

    request_id: str
    status: Uint  # HTTP-style: 200, 403, 404, 500 (always positive)
    result: Any  # Entity (with type, data, content_hash) or error details

    # EXTENSION-DURABILITY §5: the pinned durability field. Optional
    # and additive — present only when a durability/deliver_to request
    # was reconciled; durability-unaware consumers ignore it.
    durability: "DurabilityResult | None" = None

    # v3.6 F4-cycle wire-shape: the outer wire envelope's `included`
    # map, surfaced on the response object so wire-level consumers
    # (Connection.execute callers) can read the bundle that handlers
    # delivered via the envelope_included hoist. Populated by
    # Connection.execute from response_env.included; None for
    # responses that didn't carry an outer envelope bundle. This is
    # not part of the wire entity itself (which has exactly 3 fields
    # per V4 §3.3) — it's an out-of-band carry-along for receiver
    # convenience, mirroring ExecuteResult.envelope_included on the
    # in-process side.
    envelope_included: dict[bytes, dict[str, Any]] | None = None

    TYPE = "system/protocol/execute/response"

    @classmethod
    def success(cls, request_id: str, result: Any) -> ExecuteResponse:
        """Create a successful response."""
        return cls(request_id=request_id, status=Uint(200), result=result)

    @classmethod
    def not_found(cls, request_id: str, message: str = "Not found") -> ExecuteResponse:
        """Create a 404 not found response."""
        return cls(request_id=request_id, status=Uint(404), result={"code": "not_found", "message": message})

    @classmethod
    def forbidden(cls, request_id: str, message: str = "Forbidden") -> ExecuteResponse:
        """Create a 403 forbidden response.

        V7 §3.3 line 736 canonical example for 403 `code` is
        `capability_denied`. Used as both the wire response body code and
        the EXTENSION-CONTINUATION v1.20 §3.10.3 `{reason}` for the
        rejected-variant chain-error marker (the `{reason}` IS the body
        `code` per §3.10.5 single-rule). Three-way concur cross-impl as of
        v1.19 ratification — Python migrated from the prior HTTP-family
        `forbidden` to the V7-canonical identifier in the same PR as
        WB-27 receiver-side rejected-marker bind.
        """
        return cls(
            request_id=request_id, status=Uint(403),
            result={"code": "capability_denied", "message": message},
        )

    @classmethod
    def bad_request(
        cls, request_id: str, message: str = "Bad request",
        *, code: str = "bad_request",
    ) -> ExecuteResponse:
        """Create a 400 response.

        ``code`` defaults to the generic ``"bad_request"`` but callers
        emitting a V7 §4.7 connection-error subcode (e.g.
        ``"unsupported_key_type"`` for v7.66 §4.4 surface 6,
        ``"unsupported_content_hash_format"`` for v7.66 §5.2) pass the
        spec-canonical identifier so cross-impl conformance vectors see
        the right wire surface.
        """
        return cls(request_id=request_id, status=Uint(400), result={"code": code, "message": message})

    @classmethod
    def unauthorized(cls, request_id: str, message: str = "Unauthorized") -> ExecuteResponse:
        """Create a 401 unauthorized response."""
        return cls(request_id=request_id, status=Uint(401), result={"code": "unauthorized", "message": message})

    @classmethod
    def conflict(cls, request_id: str, message: str = "Conflict") -> ExecuteResponse:
        """Create a 409 conflict response."""
        return cls(request_id=request_id, status=Uint(409), result={"code": "conflict", "message": message})

    @classmethod
    def error(cls, request_id: str, message: str) -> ExecuteResponse:
        """Create a 500 internal error response."""
        return cls(request_id=request_id, status=Uint(500), result={"code": "internal_error", "message": message})

    @classmethod
    def accepted(
        cls,
        request_id: str,
        result: Any = None,
        durability: "DurabilityResult | None" = None,
    ) -> ExecuteResponse:
        """Create a 202 Accepted response (EXTENSION-INBOX §7.1; reused
        by EXTENSION-DURABILITY §5 for the async-completion verdict).

        Accepted; completion is asynchronous and observed elsewhere. When
        a durability request committed to an async pathway, ``durability``
        carries the committed strength (its ``committed`` field) and the
        ``handle`` naming where the committed entry will land."""
        return cls(
            request_id=request_id,
            status=Uint(202),
            result=result,
            durability=durability,
        )

    @classmethod
    def precondition_failed(
        cls,
        request_id: str,
        durability: "DurabilityResult | None" = None,
        message: str = "Required durability precondition unmet",
    ) -> ExecuteResponse:
        """Create a 412 Precondition Failed response (EXTENSION-DURABILITY §5).

        A required durability precondition could not be met; the operation
        was NOT performed (refused at acceptance) — safe to retry, no
        double-execution. ``durability`` carries ``max_available``.
        412 is reserved by EXTENSION-DURABILITY within its own surface;
        V7 v7.46 does not reserve it at the core level.

        Per V7 §3.3 ("Error responses use ``system/protocol/error`` as the
        result entity type"), ``result`` is emitted as that typed entity
        so a durability-unaware consumer branching on the result entity
        type still sees a refusal — not an operation result.
        """
        return cls(
            request_id=request_id,
            status=Uint(412),
            result={
                "type": "system/protocol/error",
                "data": {
                    "code": "durability_required_unmet",
                    "message": message,
                },
            },
            durability=durability,
        )

    def to_entity(self) -> dict[str, Any]:
        """Convert to entity dictionary for wire transmission.

        V4 §3.3: EXECUTE_RESPONSE has exactly 3 fields.
        Per §3.4, ``result`` is entity-typed on the wire.

        V7 §3.3: error responses MUST use ``system/protocol/error`` as the
        result entity type. The error helpers (``bad_request``/``forbidden``/
        etc.) keep a bare ``{code, message}`` dict in memory so in-process
        readers and mutators stay simple; here — the single send-side
        serialization point — any error result (status >= 400, still a bare
        untyped dict) is materialized as ``system/protocol/error`` rather than
        falling through ``_as_entity`` to the generic ``primitive/any`` wrapper.
        That generic wrapper is what made strict cross-impl decoders read
        ``code=""`` (forcing the v7.75 Go probe permissiveness fallback). The
        unwrapped ``data`` payload is byte-identical either way, so receivers
        that ``unwrap_entity`` the result are unaffected — only the wire
        ``type`` string changes. Results already entity-shaped (e.g.
        ``precondition_failed``'s explicit ``system/protocol/error``, or a
        handler's typed error like ``compute/error``) are left untouched.
        """
        result = self.result
        if (
            int(self.status) >= 400
            and isinstance(result, dict)
            and "type" not in result
            and "data" not in result
        ):
            result = {"type": "system/protocol/error", "data": result}
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "status": self.status,
            "result": _as_entity(result),
        }
        if self.durability is not None:
            data["durability"] = self.durability.to_dict()
        h = compute_content_hash(self.TYPE, data)
        return {
            "type": self.TYPE,
            "data": data,
            "content_hash": h,
        }

    @property
    def result_data(self) -> Any:
        """Payload of ``result``, unwrapping the entity envelope if present.

        Per §3.4 ``result`` is entity-shaped on the wire
        (``{type, data, content_hash}``). This property returns the
        ``data`` payload for callers that don't care about the envelope.
        Handlers that need the type or content_hash should read
        ``result`` directly.
        """
        return unwrap_entity(self.result)

    @classmethod
    def from_entity(cls, entity: dict[str, Any]) -> ExecuteResponse:
        """Parse from entity dictionary. Per §3.4 ``result`` is
        entity-shaped on the wire; we keep it that way so consumers
        that need ``type`` or ``content_hash`` have access. Use
        :attr:`result_data` for the unwrapped payload."""
        from entity_core.protocol.durability import DurabilityResult

        data = entity["data"]
        durability_data = data.get("durability")
        return cls(
            request_id=data["request_id"],
            status=Uint(data["status"]),
            result=data.get("result"),
            durability=(
                DurabilityResult.from_dict(durability_data)
                if durability_data
                else None
            ),
        )
