"""EXTENSION-CONTENT v3.5 — content extension implementation.

Modules:

* :mod:`entity_handlers.content.fastcdc` — gear table + boundary
  algorithm per §3.6 (pure functions).
* :mod:`entity_handlers.content.chunking` — fixed-size + FastCDC blob /
  chunk entity construction, verification, reassembly.
* :mod:`entity_handlers.content.descriptor` — descriptor integrity
  check + §5.3 invariant-path lookup.
* :mod:`entity_handlers.content.handler` — async ``system/content``
  handler (``get`` + ``ingest``) with the §6.2 / §6.3 ``path_required``
  discipline.
"""

from __future__ import annotations

from entity_handlers.content.fastcdc import (
    GEAR_TABLE,
    chunk_offsets,
    chunks_of,
    derive_params,
    find_boundary,
)
from entity_handlers.content.handler import (
    CONTENT_HANDLER_PATTERN,
    content_handler,
)
from entity_handlers.content.sdk import (
    DEFAULT_NAMESPACE,
    ClosureError,
    at_peer,
    ensure_closure,
)
from entity_handlers.content.chunking import (
    BlobBuildResult,
    CHUNKING_FASTCDC_NC2,
    CHUNKING_FIXED_SIZE,
    ContentReassemblyError,
    ContentVerificationError,
    DEFAULT_CHUNK_SIZE,
    GET_BATCH_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    build_blob,
    build_fastcdc,
    build_fixed_size,
    persist,
    reassemble_content,
    verify_content,
)

__all__ = [
    # handler
    "CONTENT_HANDLER_PATTERN",
    "content_handler",
    # SDK closure-completion surface (SDK-EXTENSION-OPERATIONS v0.8 §11)
    "ensure_closure",
    "at_peer",
    "ClosureError",
    "DEFAULT_NAMESPACE",
    # fastcdc
    "GEAR_TABLE",
    "chunk_offsets",
    "chunks_of",
    "derive_params",
    "find_boundary",
    # chunking — algorithms
    "BlobBuildResult",
    "build_blob",
    "build_fastcdc",
    "build_fixed_size",
    "persist",
    # chunking — verify / reassemble
    "verify_content",
    "reassemble_content",
    "ContentVerificationError",
    "ContentReassemblyError",
    # chunking — constants
    "CHUNKING_FIXED_SIZE",
    "CHUNKING_FASTCDC_NC2",
    "DEFAULT_CHUNK_SIZE",
    "MIN_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "GET_BATCH_SIZE",
]
