"""Peer module for Entity Core.

This module provides the Peer implementation and related utilities.

Construction:
    Use PeerBuilder to construct peers:
        from entity_core.peer import PeerBuilder
        peer = PeerBuilder().with_keypair(kp).with_default_handlers().build()

    With remote peers:
        peer = (PeerBuilder()
            .with_keypair(kp)
            .with_all_handlers()
            .with_remote_peer("12D3...", "192.168.1.100:9000")
            .build())
"""

from entity_core.peer.builder import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.peer.peer import Peer
from entity_core.peer.remote import RemoteConnectionPool

__all__ = [
    "Connection",
    "Extension",
    "ExtensionContext",
    "Peer",
    "PeerBuilder",
    "RemoteConnectionPool",
]
