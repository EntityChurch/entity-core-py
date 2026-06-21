"""Wire-conformance harness for ECF v1 corpus.

Implements the `emit-canonical` contract from the ECF conformance V1
cross-team assignment §1 + the operational loop from `GUIDE-CONFORMANCE.md`.

Three pieces:

- `parse_diag(src)` — RFC 8949 §8 CBOR diagnostic-notation parser (subset
  used by the v1 corpus).
- `is_canonical_ecf(data)` — strict validator used for `decode_reject`
  vectors (rejects tags, indefinite lengths, non-minimal ints, non-minimal
  floats, unsorted map keys).
- `emit_canonical(corpus, impl_version)` — runs every vector through the
  Python encoder/validator and produces the §1 emission map (one entry per
  vector_id → canonical bytes / rejected bool).
"""

from entity_core.conformance.diag import parse_diag, strip_diag_comments
from entity_core.conformance.emit import emit_canonical, load_corpus
from entity_core.conformance.strict import is_canonical_ecf

__all__ = [
    "emit_canonical",
    "is_canonical_ecf",
    "load_corpus",
    "parse_diag",
    "strip_diag_comments",
]
