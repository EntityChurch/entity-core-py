"""Path resolution — `SDK-OPERATIONS` v0.8 §2.5.

**Every path in the entity system is absolute, rooted at a peer identity.**
`/{peer_id}/knowledge/intro` is how data actually lives in the tree; there is no
path outside a peer namespace. A path *without* a leading `/` is peer-relative
notation — caller shorthand that the SDK resolves against the local peer before
any operation. It is not a second addressing mode.

The distinction this module exists to keep straight: dispatch needs the two
halves **apart**. The peer id selects the namespace and rides in the
`entity://{peer}/...` URI; the remainder is what the tree handler resolves and
what the capability check is applied to. Every caller that has hand-split a
path with `str.split("/")` has eventually got the `/{them}/…` case wrong, which
is the exact failure browser-rust routed to this repo as
`ROUTING-2026-08-17-b` §1: *"Every layer that takes a path … none may assume
the local peer's id."* :class:`ResolvedPath` makes assuming it impossible —
there is no way to build one without saying whose namespace it is.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ResolvedPath", "resolve"]


@dataclass(frozen=True, slots=True)
class ResolvedPath:
    """A path with its owning peer made explicit.

    ``relative`` never has a leading slash and keeps any trailing slash, because
    a trailing slash is *semantic* to the tree handler: `path/` (or empty) means
    "listing", `path` means "the entity". Normalizing it away silently converts
    a list into a get.
    """

    peer_id: str
    relative: str

    @property
    def absolute(self) -> str:
        """The universal-namespace form: ``/{peer_id}/{relative}``."""
        return f"/{self.peer_id}/{self.relative}"

    @property
    def is_listing(self) -> bool:
        """True when this addresses a listing rather than a single entity."""
        return self.relative == "" or self.relative.endswith("/")

    def uri(self, pattern: str) -> str:
        """The dispatch URI for ``pattern`` in this path's namespace.

        The *pattern* is the handler being addressed (``system/tree``), not the
        path being operated on — the path travels in ``resource.targets`` so the
        dispatch layer's capability check covers it (V7 §3.2).
        """
        return f"entity://{self.peer_id}/{pattern}"

    def child(self, name: str) -> ResolvedPath:
        """The path of a direct child ``name`` under this (listing) path."""
        base = self.relative if self.relative.endswith("/") or not self.relative else self.relative + "/"
        return ResolvedPath(self.peer_id, base + name)


def resolve(path: str, local_peer_id: str) -> ResolvedPath:
    """Resolve ``path`` to an explicit ``(peer_id, relative)`` pair.

    Accepts all three forms §2.5 names:

    * ``knowledge/intro`` — peer-relative; resolves to the local peer.
    * ``/{peer_id}/knowledge/intro`` — absolute; may name any peer.
    * ``entity://{peer_id}/knowledge/intro`` — the wire URI form, accepted so a
      caller can round-trip something read off the wire without re-parsing it.

    Raises:
        ValueError: if an absolute path names no peer (a bare ``/``, or ``//x``).
            This is deliberately not silently resolved to the local peer — a
            bare ``/`` most often means the caller *believes* paths are rooted
            globally, and quietly rooting it locally hides that misunderstanding
            until it reaches a remote namespace.
    """
    if not local_peer_id:
        raise ValueError("local_peer_id is required to resolve a path")

    remainder = path
    if remainder.startswith("entity://"):
        remainder = "/" + remainder[len("entity://") :]

    if not remainder.startswith("/"):
        # Peer-relative shorthand — §2.5. Resolves to the local namespace.
        return ResolvedPath(local_peer_id, remainder)

    peer_id, _, relative = remainder[1:].partition("/")
    if not peer_id:
        raise ValueError(
            f"absolute path {path!r} names no peer. Absolute paths are "
            f"/{{peer_id}}/... (§2.5); for the local namespace either drop the "
            f"leading slash or write /{local_peer_id}/..."
        )
    return ResolvedPath(peer_id, relative)
