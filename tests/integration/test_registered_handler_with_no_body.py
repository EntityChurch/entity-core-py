"""F60 / N-4 — what this peer answers for *"registered handler, no body"*.

`entity-core-go` asked the cohort, as ruling input: when a handler **is**
registered, its operation **is** in the manifest, but **no body is bound to
run**, what `code` does each seat emit? go spells it `no_handler_body`; the
specification defines none; and the open question is whether an implementation
may mint a code at all.

**This file exists so our answer is a measurement rather than a source read,
and the first draft is why.** Reading the site, I predicted `404
handler_not_found`: `_handler_for_tree_entity` returns `None` when it can bind
no implementation, and the request falls through to handler resolution. The
measured answer is **`501 unsupported_operation`**. The prediction was wrong
and the reply to a cohort poll would have been wrong with it — and a poll is
ruling input, so a wrong answer here does not fail a test, it moves a
specification.

.. rubric:: The state, and why it is reachable rather than exotic

A `system/handler` entity is bound in the tree whose `data` carries a manifest
but neither an `expression_path` (§3.7 entity-native) nor any compiled binding
in this process. That is the ordinary shape after a peer restarts holding a
tree another process wrote, and it is what `register` produces for a pattern
whose implementation lives in a package this peer does not load.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity

PATTERN = "app/bodyless"


def _bind_bodyless(peer):
    """Bind a `system/handler` entity carrying a manifest and no body: no
    `expression_path` (§3.7 entity-native) and nothing in this process's
    registry for the pattern."""
    tree = peer.entity_tree
    handler = Entity(type="system/handler", data={
        "name": "bodyless", "pattern": PATTERN,
        "operations": {"ping": {
            "input_type": "primitive/any", "output_type": "primitive/any",
        }},
    })
    peer.content_store.put(handler)
    tree.set(tree.normalize_uri(PATTERN), handler.compute_hash())
    tree.set(
        tree.normalize_uri(f"system/handler/{PATTERN}"), handler.compute_hash(),
    )
    return peer


async def _dispatch(peer):
    return await peer._dispatch_local_execute(
        PATTERN, "ping", {"data": {}},
        {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["/*/*"]},
        }]},
        None, None,
    )


@pytest.fixture
def peer_with_a_bodyless_handler():
    return _bind_bodyless(
        PeerBuilder().with_keypair(Keypair.generate())
        .with_all_handlers().build()
    )


def _code(result) -> str:
    if isinstance(result.result, dict):
        return (result.result.get("data") or {}).get("code", "")
    return ""


@pytest.mark.asyncio
async def test_what_this_peer_answers(peer_with_a_bodyless_handler):
    """The measurement. Asserted, so the reply to arch is reproducible and so
    a later change to it is a visible one.

    **py answers `501 unsupported_operation`, and does not mint a code.**

    The part that matters for the poll is *where that answer comes from*: it
    is not a decision about the bodyless handler at all. The tree-walk
    resolver declines to bind, resolution falls through to the wildcard `*`
    handler this peer registers by default (`entity_handlers.storage`), and
    that handler answers `501 unsupported_operation` because `ping` is not an
    operation **it** implements. The status is a coincidence of the fallback's
    own vocabulary.

    So py's answer is not evidence of a considered position, and it should not
    be read as one when three spellings are being compared. Two things follow
    that arch can rule on, both arguments from the spec rather than from
    convenience:

    - A peer with **no** `*` fallback registered answers something else
      entirely for the identical input, so the code is a property of the
      peer's handler table rather than of the request. That alone makes it
      unsuitable as a conformance row until it is pinned.
    - `501 unsupported_operation` is a claim that **this peer does not
      implement that operation**, and the manifest in the tree says it does.
      §6.6 makes the tree the resolution surface, so a caller who reads the
      manifest and then dispatches gets two answers that contradict each
      other. That is the argument for a distinct code; it is the same
      argument as go's, reached from a different defect.
    """
    result = await _dispatch(peer_with_a_bodyless_handler)

    assert (result.status, _code(result)) == (501, "unsupported_operation"), (
        "py's answer to F60 moved. It is cohort ruling input, so update the "
        f"routed measurement before changing it: got {result.status} "
        f"{_code(result)!r} / {result.error!r}"
    )


@pytest.mark.asyncio
async def test_the_answer_comes_from_the_wildcard_fallback_not_from_a_decision():
    """The finding, driven: **without** the `*` fallback the identical input
    gets a different answer.

    This is what makes py's `501` unsuitable as evidence about what a peer
    *should* say, and it is the half worth routing. A conformance row keyed on
    this code would be measuring which handlers a deployment happens to
    register — two conformant peers would disagree with no rule broken.

    Built with `with_capability_handler()` only, so nothing is bound at `*`.
    """
    peer = (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_capability_handler().build()
    )
    assert "*" not in [h.pattern for h in peer.handlers.list_handlers()], (
        "this peer has a wildcard fallback after all — the row below would "
        "then be measuring the same thing as the row above"
    )
    _bind_bodyless(peer)

    result = await _dispatch(peer)

    assert (result.status, _code(result)) != (501, "unsupported_operation"), (
        "the answer is the same with and without the `*` fallback, which "
        "would mean py has a considered position on F60 after all — "
        "re-measure and update the routed reply"
    )
    assert result.status == 404, (
        f"unexpected answer without the fallback: {result.status} "
        f"{_code(result)!r} {result.error!r}"
    )
