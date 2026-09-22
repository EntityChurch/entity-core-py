# Declared conformance exclusions

Vectors that this implementation satisfies **in-process** rather than at the wire,
each with the reason the wire form is not constructible here and the **mutation**
the in-process test was verified against.

Per `GUIDE-CONFORMANCE` §5.2b the point is that a gap is **stated rather than
absent**: an in-process result reported as a cross-impl vector pass is a false
conformance claim. Nothing in this file is covered by any cross-impl report —
if a run of `validate-peer` against this peer looks green on a category listed
below, that category is green *around* the row, not through it.

A row leaves this file when the state it needs becomes constructible at the wire
(for the current entries, that means deploying a RELAY / store-and-forward seam),
not when the implementation is confident about it.

---

## `NET-LIVENESS-NO-ESCALATION-WITHOUT-EPISODE-1`

| | |
|---|---|
| **Spec** | `EXTENSION-NETWORK` §5.4a `[MUST]` — the negative half of the escalation pair |
| **Rule** | A §10.2 dispatch-fallback or RELAY terminal-hop eviction of a `connected` peer MUST NOT produce a `disconnected` write. |
| **Satisfied** | in-process |
| **Test** | `tests/integration/test_peer_status_liveness.py::TestNoEscalationWithoutEpisode` |
| **Mutation** | remove the `status != suspect` guard in `RemoteConnectionPool._escalate_after_grace` (`packages/entity-core/src/entity_core/peer/remote.py`) |
| **Since** | 2026-08-12 |

**Why not at the wire.** The state the vector requires — *unbound yet still
`connected`* — is reachable only from the two paths §A1's seam scope deliberately
excludes from demoting: the §10.2 dispatch fallback and the RELAY terminal-hop
forward. Both need a store-and-forward deployment, and this peer installs neither,
so a conformance client has no way to construct the state. §5.4a states this
satisfaction mode at the point of the MUST rather than leaving it to be discovered.

**Why the obvious proxy is refused.** Substituting a live idle counterpart makes
the case *reachable* — but a live counterpart stays **bound**, so the proxy
exercises a timer-driven escalation and never the scope-pin defect the vector
exists to catch. It would read as coverage while missing the case, which is worse
than this entry.

**The mutation is executed, not merely named.**
`test_mutation_removing_the_suspect_guard_fails_this` neutralizes the guard's
discriminating value and asserts the `disconnected` write then *does* appear —
so the negative assertion is known not to pass by construction. This is a direct
consequence of the §5.5a probe last cycle, where both a control row and a mutation
test ran against a malformed probe and neither could have failed: an unexecuted
mutation claim is not a control.

**What it guards.** Escalating on any *unbound* peer rather than on any *`suspect`*
peer satisfies the positive vector (`NET-LIVENESS-ESCALATE-AFTER-EVICTION-1`) while
breaking the §A1 seam scope. That is why the pair is required and why the negative
half is not optional.
