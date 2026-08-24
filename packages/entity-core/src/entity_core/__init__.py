"""Entity Core Protocol - Python Implementation.

A Python implementation of the Entity Core Protocol for interoperability
testing with the Rust implementation.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Read from installed package metadata rather than restating the number here.
# This used to be a hand-maintained literal and it had drifted to "0.1.0" while
# `pyproject.toml` said "0.8.0" — nothing caught it, because nothing consumed it.
# One source of truth, and it is `packages/entity-core/pyproject.toml`.
#
# NOTE: this is the *package* version, not the protocol version. See the
# "What the version numbers here mean" section of CHANGELOG.md — per [ADR-0002]
# the spec level an implementation targets is carried out-of-band, never in the
# release number. A conformance emission pins `impl_version` to the git sha
# (`entity_cli.main`), which is the number to cite in a measurement.
try:
    __version__ = _pkg_version("entity-core")
except PackageNotFoundError:  # running from a source tree with nothing installed
    __version__ = "0+unknown"
