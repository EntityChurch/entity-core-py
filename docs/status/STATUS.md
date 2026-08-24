# entity-core-py — status

_Updated: 2026-08-20 · public: v0.8.0 (master)_

## Where it is

Python reference implementation of the Entity Core Protocol (`entity-core/7.0`).
It is built clean-room — directly from the specification, with no shared code with the
other implementations — so its real job is to prove the spec is clear and complete
enough to build a compatible peer from scratch, and to act as an interoperability peer
for the Rust and Go implementations.

The codebase is a `uv` workspace of three packages with a strict
`entity-cli → entity-handlers → entity-core` dependency direction:

- **entity-core** — the minimal, stable protocol library: `crypto/` (Ed25519/Ed448
  identity, signing, hashing), `protocol/` (Entity, Envelope, messages, framing),
  `capability/` (tokens, checking, delegation), `storage/` (ContentStore, EntityTree,
  EmitPathway), `types/` (definitions + registry), `utils/` (ECF encoding), `peer/`
  (Peer, PeerBuilder, Connection), and `handlers/` (**registry + context + bootstrap
  only**), plus `conformance/`, `diagnostic/`, and `sdk/`.
- **entity-handlers** — the standard, optional handlers: tree, system, storage, query,
  manifest, capability, role/role-policy, identity, attestation, quorum, subscription,
  inbox, continuation, history, revision, auto-version, compute, route, relay, discovery
  (incl. mDNS), registry (incl. peer-issued), type (handler/constraint/narrowing/
  analysis), and the `content/`, `encryption/`, `local_files/`, and `substitute/`
  sub-packages.
- **entity-cli** — the user-facing CLI (`entity-core start` / `connect` /
  `list-identities`).

Maturity: reasonably mature for a research preview. A broad suite — roughly 2,600+ test
functions across ~130 files (unit, integration, interop, and conformance directories) —
backs it, and `v0.8.0` ("Genesis") is cut as the initial public research-preview release,
with package versions aligned to `0.8.0` alongside the parallel Rust/Go cores. This is
**not a 1.0 API commitment.** The canonical build/test path needs only `make` + `podman`
on the host (a pinned `Dockerfile` carries the exact Python + `uv`); local dev uses
Python 3.11–3.13 and `uv`.

## Where we left off

**REGISTRY v1.19 is landed, and the conjunction we took was still an under-refusal (2026-08-20).**
Arch ruled both of our routed registry items at **v1.19** (arch `9cffb14`/`b254845`), and
`COHORT-OPEN-ITEMS` §0a makes them two of the five rows that close the **registry v1 release line**.
Landed at `1d0f20c`: **R-15** — §4.1b's broad classifier rewritten to the ruled four-rule form
(NARROW iff no `*` · a literal `@` · the literal head before the first `*` ends in `:` · it ends in
an **enumerated** typed suffix, §4.1b.1 = exactly `.eth`); and **R-16** — `set-resolver-config` now
diffs `pinned_bindings` and requires `system/capability/registry-pin` on a change, `403
not_entitled` and nothing written otherwise, checked **before** the disclosure filter because an
authorization verdict and a policy verdict are different kinds. R-11 row 7's five classifier
patterns are driven on the write surface here; **row 8 stays off the wire**, concurring with go's
spec-issue `2026-08-20-a` — §5 names `registry-pin` descriptively and fixes no *encoding*, so a
shared harness minting one seat's cap would answer `403` to a **conformant** peer, a false red
manufactured by the vector. We match go's `pin-bindings` operation-axis encoding, which is
**matching, not converging**.

**SA-PY-23 closes, and closes against us — the part worth reading.** We filed it claiming *"this one
has no bug in it"*: two sound classifiers, enumerate the rows they disagree on, take the
**conjunction**, file the ambiguity. Every step was right and **the conclusion was still an
under-refusal**, because both seats shared a clause the ruling refuses — *"any literal at all" is
not the line*, so `*.lab` handed every dotted bare name a user typed to a third party while reading
as scoped. *A conjunction bounds the disagreement, not the error; the rows the readings agree on are
exactly the rows nobody re-examines.* **SA-PY-24 closes in our shape** (option 1, verbatim) — the
filing's no-local-fix call held for one day and was right, and its escalation row survives into the
gate class unchanged. Four mutations, all caught. Full detail:
`ROUTING-2026-08-20-registry-v1-19-is-landed-…`.

**No citable conformance number this session, and that is a measurement, not an omission.** Another
session on this host held a concurrent `validate-complete.sh` run (fixed ports), so a run started
against it would collide and neither result would be citable. Local: `3931 passed · 31 skipped ·
1 F`, the one failure being `tests/interop/test_connect_to_rust_peer` dialing a fixed
`127.0.0.1:9000` held by unrelated Selenium containers — the fixed-port anti-pattern's fourth
occurrence, not this diff. The previous number (`@ core-go 5655494`) **predates go's `v15` row 7**
and therefore says nothing about R-15 either way; a fresh armed run from `1d0f20c` is owed.

**§4.3 is built, the load-time normalizer is gone, and the new operation absorbed a capability
nobody meant it to (2026-08-19 c).** Arch ruled SA-PY-21 Q1/Q2 and SA-PY-22 as one model (REGISTRY
**v1.17/v1.18**): the §4.1 step 2 privacy MUST is **kind-scoped** and binds the **write**, not the
load. Landed at `7488ee3` — `set-resolver-config` / `get-resolver-config` with whole-config
validation, no partial application, and `acknowledge_name_disclosure` as a **parameter of the
operation** (a field would be writable by whoever writes the bytes); the load-time normalizer
**deleted**, replaced by a diagnostic that never normalizes and never refuses to start. Q1 went
against our implementation and our filed argument was recorded as *not* the justification — both
worth reading in `SPEC-AMBIGUITIES`. Three new SAs: **SA-PY-23** (the "unscoped name" classifier is
undefined and we and go already differ on `*.*`; we took the conservative conjunction),
**SA-PY-24** (§4.3 writes `pinned_bindings`, which §5 gives its own capability — and a pin
short-circuits §4.1 step 1 ahead of both the disclosure filter *and* the ceiling), and the type-ref
divergence in the gate below. Full detail: `ROUTING-2026-08-19-c-…`.

**The citable number is `1601 · 1586 P · 14 W · 1 F · 0 S @ core-go `5655494`` (2026-08-19 c)**,
armed `validate-complete.sh python` from the committed tree at `7488ee3`: pass 1b (`--profile
core`) `747 · 632 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `32/32`, substitute `8/8`, and
**`registry 18/18`** — go's two new checks (`v15_dispatch_config_refused`,
`v16_ttl_ceiling_reread`) both PASS on the first run, so the §4.3 wire shape agreed across two
independent implementations without either adjusting. **The one FAIL is a type-ref divergence we
believe is go's:** `set-resolver-config-request.config` is `system/registry/resolver-config` here
(§4.3's own table) and `core/entity` there (a reflection artifact of `entity.Entity`) — the
identical question was ruled *precise* for `EXTENSION-SUBSTITUTE` §2.3's `entry`, where go had
loosened the same way. Routed, not worked around; one line to withdraw if arch rules otherwise.
Local suite `3903 passed`, `tests/interop` excluded — a foreign container on this host holds the
fixed port 9000 and the handshake now **hangs** rather than failing.

**The resolver ceiling's sticky arm is closed, and the privacy MUST turns out to have one
implementer (2026-08-19 b).** `REG-TTL-RESOLVER-CEILING-1` row (d) — a sticky binding takes the
ceiling as its lifetime — failed against a **3820-test-green** tree when core-go ran the armed gate
(`v4c_ttl_resolver_ceiling`). `min(binding.ttl, local_max)` has no arm for a null `ttl`, and the
guard that makes `min` type-safe applied the control **only where a bound already existed**, which
is the control inverted. Fixed at `bf9e43d` as `_effective_lifetime` — three arms, one function,
both call sites (the expiry verdict and the surfaced `ttl`) — with all four vector rows plus two the
wire vector cannot reach: the sticky arm's *teeth* (a sticky binding aged past the ceiling stops
resolving; go's probe reads the response, not the verdict) and read-at-resolution (one process,
three configs). **SA-PY-15 closes** — ruled v1.16 at our site, verbatim. Filed **SA-PY-22**: an
exhaustive named search finds **no production implementation of §4.1 step 2's privacy MUST in go
`ca53e2a` or rust `e6fb500`**, and no `REG-DISPATCH-CATCHALL-LOCAL-1` in the harness — so the seat
that filed SA-PY-21 is the only seat its answer binds. Full detail, including the argument *against*
our own Q1 reading: `ROUTING-2026-08-19-b-…`.

**The citable number is `1597 · 1582 P · 15 W · 0 F · 0 S @ core-go `ca53e2a`` (2026-08-19 b)** —
the full armed `validate-complete.sh python`, **exit 0**, measured from the committed tree at
`bf9e43d`: pass 1b (`--profile core`) `745 · 630 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3
`32/32`, substitute `8/8`, `registry 16/16/0/0`. Local suite `3899 · 1 F`, the one failure being
`tests/interop/test_connect_to_rust_peer` dialing a fixed `127.0.0.1:9000` held by an unrelated
container on this host — the third instance of the fixed-port anti-pattern, now in `AGENTS.md`.

**Both registry rulings are landed and the widened MUST is built (2026-08-19).** REGISTRY
**1.14** (§4.1 step 2's filter) and **1.15** (one name matcher per registry) closed
`SA-PY-17` and `SA-PY-14` — *neither owed a behaviour change here*, because `c74f95e` and
`c65bfe2` had already landed both before arch read us. What **was** owed: v1.14's privacy MUST,
restated at the width of the configuration rather than the catch-all row, is now normalized at
load (`1cb7c01`) — two doors, exact classification, mutation-checked. And the coverage the
ruling exposed: `name_constraints` was correct and **untested**, because its only fixture used
the spec's own `*.lab` example, which discriminates nothing (`2890f47`). Filed `SA-PY-21` (the
widened MUST's scope, and an operator `MAY` no field can express) and corrected arch on
`SA-PY-15`, which `ROUTING-2026-08-19-c` §3's *"the board is closed"* passed over — it was
dropped in handling, not decided. Full detail:
`ROUTING-2026-08-19-the-two-registry-rulings-are-landed-…`.

**The citable number is `1595 · 1581 P · 14 W · 0 F · 0 S @ core-go `7671f06`` (2026-08-19)** —
the real `validate-complete.sh python`, all six passes exit 0, measured from a clean committed
tree; pass 2 `55/55`, pass 3 `registry_issuer` **32/32** (reproducing core-go's own measurement
of this peer on the *new* tree, so `name_constraints_grammar` is green after these commits) and
`registry` `14/14`. The 14 W are the known py baseline, none new.

**`SDK-OPERATIONS` §16.1's MUST list is complete (2026-08-18 f).** The last row, §11.6
`register_handler`, is built (`447a8e0`): the four §11.6.1 paired writes in order, the
collision check on both sides, §11.6.2's handle (idempotent close, `async with`, no finalizer),
§11.6.4 compensation with types exempt, and §12.5's four code strings as constants. Six
mutations run against it. §11.6.9 service-owning handlers is deliberately unbuilt — §16.1 does
not name it and publishing its type definitions with no producer would manufacture a
type-census divergence. Three SAs came out of building it (SA-PY-18/-19/-20), all found by
building rather than reading; SA-PY-20 changed the code, because §11.6.1 step 3's conditional
grant produces a handler V7 §6.2 will not dispatch to.

**And we corrected our own §4.1 filing the same day (`c74f95e`).** SA-PY-17 was filed as a
two-way split; §4.1 step 2 has **two edge cases** and `-f` argued only the first. Case A (a
kind named in no entry, when another matches) was a real privacy hole — §4.1a's catch-all MUST
is evadable by omitting a row otherwise. Case B (a kind named by an entry, when nothing
matches) flipped in the same commit on that argument and was never argued for; it is now
excluded too. We exclude in **both**, which is the conjunction of go's and rust's exclusions
rather than either seat's position. core-go has since **pulled** the oracle that started this
(`8d2f5ad`) because it discriminated on the unruled filter question rather than the ruled
grammar — and the lesson we ratcheted is the mirror image of theirs: **a failing oracle is
evidence that something is wrong, never evidence about what is right.** Full detail:
`ROUTING-2026-08-18-g-…`.

**The consolidated core-peer worklist is closed (2026-08-18 e).** `ROUTING-2026-08-18-o` §4 as
amended by `-q` §3 — six rows, all landed and mutation-checked: REGISTRY **v1.13** direct (the
renew cascade + terminal `403`, `max_ttl` REQUIRED on a live policy, register/renew clamp, and
the resolver-side ceiling that is the half protecting the consumer) at `c65bfe2`;
`REG-DISPATCH-GRAMMAR-1`'s closed name matcher at `c65bfe2`; **TYPE §4.6** onto core §5.4 at
`1b8224a`; **REVISION**'s four-key specificity total order + §4.4.18 **V7** at `7e56047`;
**HISTORY §6.2** key 3 at `af50d55`; and §4.1a rows 2/6, a no-op because we ship no default
dispatch list. Both SAs filed yesterday came back **ruled in our favour** (SA-PY-12 at arch
`86d6b20`, SA-PY-13 as the whole renew-cascade arc).

*(Superseded 2026-08-19 — see the number above.)* **`1595 · 1580 P · 15 W · 0 F · 0 S @ core-go
`6ae71c4``** — one check fewer because core-go withdrew `v15_dispatch_grammar`, and one warning
more because
`concurrency.t1_1_concurrent_demux` is a timing-sensitive informational check that flaps.
Superseding `1596 · 1582 P · 14 W · 0 F · 0 S @ core-go `7747602``, which was — the real
`validate-complete.sh`, all six passes exit 0, pass 2 `55/55` and pass 3 `31/31` (up from 28;
core-go's three new TTL vectors pass on their first run against this peer).

**The finding worth reading is SA-PY-17.** core-go's new `registry.v15_dispatch_grammar` failed
against a 3828-test-green tree, and the failing row was not about the grammar: §4.1 step 2's
dispatch filter narrows **per name** (union of the matching entries' kinds) and we implemented
**per backend** (a kind named in no entry is always consulted), which is what step 2's own
clarifying sentence says. The two agree on every configuration where the narrowed backend is in
the chain — every fixture here. Ours made §4.1a's catch-all **MUST** inert: a name-transmitting
backend simply left *out* of the list was consulted for every name, a larger disclosure than
the one the MUST forbids. Adopted per-name on that argument. Four SAs filed today (SA-PY-14
`name_constraints`' undefined glob · SA-PY-15 the resolver ceiling's missing site · SA-PY-16
HISTORY §6.2's unreachable worked pair · SA-PY-17). Full detail:
`HANDOFF-2026-08-18-c-…`; the acknowledge and the matcher census are in
`ROUTING-2026-08-18-f-…`.

The delta against go is **14 W to their 0 W**. Nine are the type-definition cluster, unchanged
and ours to close. The tenth is new and points the other way: `registry/issuer-policy` differs
because go declares `max_ttl` as `primitive/uint?` and we read §6a.9.1's schema block literally
as required — routed for a same-day convergence.

### Superseded — the four owed items landed (2026-08-18 d)
**All four owed items are landed and py is back at the release bar.**
`ROUTING-2026-08-18-i` §3's list is closed: §2.4's four glob forms + §4.4.17 **V6**
(`1bedce3`), registry **D11 + D12** (`224ef5e` — py was the last seat), `log.since` →
`log.start_at` (`1bedce3`), and D1–D5's filtered root verified with D5's missing vector added.
Each is mutation-checked; all three oracle checks that named py now **PASS**.

**The citable number is `1595 · 1582 P · 13 W · 0 F · 0 S @ core-go `18e24c3``** — the real
`validate-complete.sh`, all six passes exit 0, superseding the stale `1594 @ 41ecf0b` below.
go's bar is *zero failures **and** zero skips on passes 1, 2 and 3*; py meets it on all three
(pass 2 `55/55`, pass 3 `28/28`). core-go's fixture blocker is fixed on their side.

The remaining delta against go is **13 W to their 0 W**, and nine of those are one cluster:
py's type definitions diverge from the spec's declared shape (`system/bounds.chain_depth`,
`continuation/join.completion_deadline_ms`, `network/backoff-config.max_attempts`, …), plus
`registry/revoke-request` carrying two fields nothing else declares. `open-type-tolerable`,
hence WARN — but a type definition is content-addressed, so each is a type-hash divergence.
**That cluster is the next work item.** The other four warnings are LOCAL-FILES (a Go-only
extension, an expected scope gap), one SHOULD, and one observed-and-advancing probe.

Two new SAs filed: **SA-PY-12** (§2.3 invokes `glob_match` on merge-config patterns while §2.4
scopes it away from that call site — and we were evaluating it with `fnmatch`, non-conformant
under both readings) and **SA-PY-13** (`renew-request` can still mint the null-ttl binding D11
and D12 forbid; `entity-core-go` has it in the same shape, so left unfixed deliberately).
Full detail: `HANDOFF-2026-08-18-b-…`.

### Superseded — core-go's fixture generator blocked the complete suite (2026-08-18 c)
`validate-complete.sh` aborts at step one, before any peer starts: their `d948b4f` added the
CAP registry F2/D3 refusal of null-ttl peer-issued bindings, and their own `RESOLVE-1`
happy-path fixture still mints one, so the generator's self-verify refuses its own output.
Same shape arch just filed against workbench-go — a new gate landed without the fixture that
feeds it being re-derived. Routed (`ROUTING-2026-08-18-d`). Fallback measurement via
`validate-peers.sh` at core-py `dc8c308` / core-go `8623c76`: **1552 ran · 1504 P · 20 W ·
0 F · 28 S — PARTIAL, 7 surfaces unexercised**, which their own banner says must not be cited
as a conformance number; it supports only the narrow claim that the §2.4 exclude change
regressed nothing. **The citable number stays `1594 · 1579 P · 15 W · 0 F · 0 S @ core-go
41ecf0b`**, pinned and stale by arch's own rule. Good news in the same run:
`continuations.join_target_received` is **PASS** again — we found the granter-frame divergence,
arch ruled it our way, core-go fixed the fixture (`8623c76`), and it is green with both peers
doing the stricter thing.

**Arch ruled all four open questions; two are now code (2026-08-18 b).** `ROUTING-2026-08-18-c`:
**SA-PY-9 yes** (§5.2's check binds every dispatch carrying a resource target — and our
framing was wrong: §5.2 tests the *field*, not the door, so core-go's gap is a **dropped
field**, not a reading split); **SA-PY-10 granter-framed**, our reading adopted whole, so the
WARN against core-go's join fixture is ratified as correct and §5.5a already names the losing
side non-conformant — the proximate cause is `EXTENSION-CONTINUATION` §3.5's worked example,
which taught the fixture the wrong shape; **SA-PY-8 confirmed and larger** — §6.1 contradicts
itself independently of any implementation, and a version's `root` MUST be the
exclude-filtered trie on every path that emits one. **Adopted at `cc73a60`:**
`compute_versioned_bindings` at `commit` (four call sites) *and* the filtered trie as the
auto-version root, O(1) fast path kept — the half that mattered most, because suppressing the
version *entry* for an excluded write never suppressed that path's contribution to the tracked
root, so the exclude did not work at all, one write late. **SA-PY-7 answered back to arch with
evidence:** the two `since` fields are a **behavioral** divergence, not prose —
`fetch(since=v2)` returns `[v3]` and `log(since=v2)` returns `[v2, v1]`, disjoint sets, so it
is a determinism pin. New: **SA-PY-11** — §2.4 names `glob_match` and never defines it, and
the matcher is hash-determining (Go's `path.Match` `*` does not cross `/`; Python's `fnmatch`
does), so the obvious tool in each language produces divergent version roots with no error.
Suite 3686 / 34 skipped. See
`ROUTING-2026-08-18-c-sa-py-7-answered-and-the-glob-is-wire-contract-to-arch.md`.

**The in-process dispatch path is authorized on resources for the first time (2026-08-18).**
§5.2 makes the dispatch-level resource check primary and the handler's own check secondary;
`handle_execute` ran it and `_dispatch_local_execute` never did, so on a sub-dispatch the
primary check was absent and the secondary one exists in **8 of the 70** non-`__init__`
modules in `entity-handlers`. §6.2 assigns `system/handler:register`'s install-path
authorization to exactly the missing check. **`entity-core-go` has the same gap**
(`makeLocalExecute`, `core/protocol/local.go` — `Resource` nil in the `CheckPermission`
literal); rust unverified. Fixed at `00b2c05`; the candidate rule *"a second dispatch path is
a second boundary"* is **ratified**. Running the check then exposed a §5.5a granter-frame
question on continuation `dispatch_capability`s that no peer had an opinion on because no
peer was checking — filed as **SA-PY-10** and deliberately not tuned away, at the cost of one
WARN against core-go's join fixture. Against core-go's `validate-complete.sh python`
**@ core-go `41ecf0b`**: pass 1 `1594 · 1579 P · 15 W · 0 F · 0 S`, pass 1b (`--profile core`)
`745 · 631 P · 11 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `27/27`, substitute `8/8` — every
pass PASS, and core-go's new `subscriptions.events_vocabulary_filter` passes on its first run
against this peer. Also corrected: the cohort record's **CAP-6a ingest ✅ for py at
`70493c9`** was earned by the narrower probe, not by the peer — py was fail-open there and the
refusal lands at `55016d9`; core-go's "~20s stall" was that fail-open's shadow, not a separate
availability surface. See
`HANDOFF-2026-08-18-the-in-process-dispatch-path-was-never-authorized.md`.

**Both core-tier fail-opens closed; the full surface is green again (2026-08-17 h).**
CAP-6a **ingest** (a received capability whose `expires_at` / `not_before` / `created_at`
does not fit `uint64` was honored — under Python a bignum compares cleanly instead of
failing to decode) and the V7 §5.2 **`peers` dimension** (parsed since V6.0, read by
nothing, so every grant we issued authorized dispatch into any peer's namespace). Against
core-go's `validate-complete.sh python`, live at this tree from a clean environment:
**pass 1 `1594 · 1581 P · 13 W · 0 F · 0 S`, pass 1b (`--profile core`)
`745 · 631 P · 11 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `27/27`, substitute `8/8` — every
pass PASS.** The peers fix took two
attempts; the first read the target peer after the dispatcher had stripped the peer segment
and passed our tests while changing nothing, which is recorded in `AGENTS.md`. See
`HANDOFF-2026-08-17-h-the-two-core-tier-fail-opens-are-closed.md`. Its §4.1 is worth
reading before trusting any intermittent validator failure on this machine: four of them
this session turned out to be a peer from an aborted run still holding the suite's **fixed**
HTTP-poll port, which presents as a refused dial, a peer that never binds, or a content
fetch 404 that looks exactly like a serving gap.

**The L3 revision surface, and a validator run that corrected the conformance number
(2026-08-17 g).** `entity_sdk.revision` covers all nineteen `EXTENSION-REVISION` §4
operations; building it against `SDK-EXTENSION-OPERATIONS` §4 produced four new
`SPEC-AMBIGUITIES` entries (SA-PY-5 … SA-PY-8) and surfaced a `checkout-result` shape
defect we shared with core-go, now fixed here. **Against core-go's
`validate-complete.sh python`, run live at this tree: pass 1
`1594 · 1577 P · 13 W · 4 F · 0 S`, pass 1b (`--profile core`) `745 · 630 P · 10 W · 2 F ·
103 S`, pass 2 `55/55`, pass 3 `27/27`.** The four are a CAP-6a **ingest** fail-open (a
received token with a negative `not_before` is honoured), a V7 §5.2 peers-dimension
escalation, and two published-root vectors; the first two also fail the core profile.
Not bisected, so not labelled pre-existing — the 08-10 line below (`1566 · 0F · 0S`) is
28 checks and several sessions older. See
`HANDOFF-2026-08-17-g-revision-is-l3s-largest-surface-and-the-validator-found-four.md`.

**Cohort catch-up round (2026-08-10).** The inbox type cut, `EXTENSION-REGISTRY`
§6a.9.2, and the DISCOVERY §3.3 erratum are landed, and `tree:put` no longer re-derives
a received entity's authored `content_hash` (a V7 §1.8 break invisible while author and
receiver share a hash format). Against core-go's `validate-complete.sh`:
**pass 1 `1566 (1537 peer-attributable) · 0 F · 0 S`**, pass 2 `55/55`, pass 3 `14/16`.
The two remaining are core-go's — its validator sends `revoke-request` / `renew-request`
unsigned and asserts success, which §6a.9 forbids. See
`HANDOFF-2026-08-10-catchup-inbox-cut-6a92-and-the-unsigned-revoke-python.md`; §"Open
questions routed upstream" carries three items for arch. *(The 2026-08-07 and 2026-08-08
handoffs are the record for the cycles between this and the 08-05 entry below.)*

**Symmetric origination authority + the namespace flag day (2026-08-05).** The
`EXTENSION-SIGNALING` §6.5 (b) reciprocal grant is built **both-sided and assembled** —
the S5 packet's gate #3 assignment for this repo. The dialer mints the acceptor's mirror
of the §6.6 cap on a rendezvous establishment (the grant an inbound dialer would actually
receive, advertisement-filtered — Q2/Q2a, not the flat §4.4 floor), and — the half that
fails silently — the **dialer now serves the reach-back**: an inbound EXECUTE on a
connection we dialed was previously dropped as an orphan response, so the acceptor's
authority was real and reached no handler. Both halves are pinned live, and the
reach-back vector was verified to fail (by timeout) when the serving branch is disabled.

The same pass ran the re-diff the signaling handoff promised for "the day the corpus
lands", and found this client was on the **pre-flag-day side of the `system/nat/*` →
`system/signaling/*` rename**: the derivation hashes the literal type string, so every
rendezvous key differed from go's and rust's and **the peers could not have met at any
key** since 2026-08-02. The stage-bisect payload, the 18 live node tests, and the pinned
go-agreement witness all passed throughout — the node is mode-blind and the witness
predated the rename. Fixed; both cross-impl witnesses re-derived live from
`entity-core-go` @ `94b6583`.
See `HANDOFF-2026-08-05-reciprocal-grant-and-namespace-flag-day-python.md` — §4 carries
two carriage findings routed to arch.

**Signaling client (2026-07-30).** The `signaling` **client** landed on `dev` —
§2.2 key derivation, §3.1.1 pool selection, the §3 coordination messages with §3.1 blob
framing and the §3.2 read rules, and the three wrapped-surface operations, in
`entity_handlers/signaling/`. Built against Rust's go/py build brief; the server role is
deliberately out of scope (§1.2 makes it optional). **86 same-impl tests plus 24 live**
against real Rust nodes. See `HANDOFF-2026-07-30-signaling-client-stage1-python.md`.

The admission blocker that handoff filed against Rust — the shipped
`entity-signaling-node` seeded no capability policy, so a foreign peer got `403` on every
signaling op — is **closed** (Rust `9714f13`: `--open` / `--grant`, closed by default).
The owner-keypair workaround is deleted and the live suite now runs **as an ordinary
stranger**, which puts the admission model itself under test. Also landed since: go's
byte-identical §2.2 keys and §3.1.1 selections pinned here as assertions, and
`tests/interop/signaling_meet.py` — Python's driveable half of the cross-process go↔py
meet, green with Python on both sides. *(Those pinned key/selection values were
pre-flag-day on both sides and were superseded on 2026-08-05 — see above.)*

Earlier on the `v0.8.0` "Genesis" research-preview line: NETWORK Amendment 12 rungs 1–2
(the reactive liveness floor: `system/peer/status` writes + §5 keepalive) landed on
`dev` — see `HANDOFF-2026-07-15-network-rungs-1-2-python.md` for the cohort convergence
input. Next substantive work is the cross-impl convergence pass once a second impl
completes the floor, plus running the conformance + interop suites live against a current
reference peer (below). *(This section predates the 2026-07-2x continuation
STANDING-MODEL work now on `dev`; those handoffs are the current record for it.)*

## Backlog

- Track the upstream spec as it lands and fold changes in. Per the **no-legacy policy**,
  delete legacy / deprecated / dual-format paths (and the tests that only assert them)
  once a path is confirmed not current-spec — verify against the spec before cutting,
  don't keep confirmed-legacy "just in case."
- Surface and route any spec gaps or ambiguities **upstream** rather than papering over
  them locally.
- The cross-impl peer validator's `local_files` profile is Go-scoped; Python not passing
  that profile is an **expected scope gap**, not a defect — keep it understood as such
  rather than chasing parity there.
- **The live go↔py meet** is the one open piece of the signaling gate: Python's side is
  built (`tests/interop/signaling_meet.py`, driveable by any language), Go's validator
  currently spawns both of its peers in-process.
  `HANDOFF-2026-07-30-signaling-client-stage1-python.md` §6. It is newly *meaningful*:
  before the 2026-08-05 rename it could not have succeeded.
- **Re-run the signaling interop suite against a live Rust node** post-rename, before any
  three-way-green claim — the keys moved.
- **The §7 punch is unbuilt here** (S5 packet gate #5), and there is no WebRTC substrate.
  §6.5 (b) is wired to `Peer.establish_via_rendezvous`, so the punch calls one existing
  site when it lands.
- ~~**Waiting on arch:** the signaling corpus is still uncommitted upstream~~ — **closed
  2026-08-05.** The corpus is committed (`EXTENSION-SIGNALING.md`,
  `PROPOSAL-CONNECTION-NODE.md`); the promised re-diff ran and found the namespace flag
  day (above). Two carriage findings routed back in the 2026-08-05 handoff §4.
- Open spec gaps / TODOs beyond the above: unknown / to confirm.

## Waiting on

- **The spec is upstream** (`entity-core-architecture`); this repo implements the landed
  spec and does not define it, so feature scope tracks what upstream lands.
- **Interop and cross-impl validation need a live reference peer.** `tests/interop/`
  requires a Rust peer started alongside, and the spec-conformance peer validator (see
  `docs/VALIDATING.md`) is an external, Go-hosted black-box harness that talks to a
  running peer over the wire — it is not runnable standalone from this repo. The
  authoritative cross-impl run is owned by the harness side at the release commit.

## Done recently

- **NETWORK Amendment 12 rungs 1–2 (the liveness floor)** — `system/peer/status` writes
  (`connected` both ends on establish; `suspect`/`transport-error` at the direct-dispatch
  seam with the behavioral no-clobber guard; `disconnected`/`keepalive-miss` from the new
  §5 keepalive loop), `system/connection` dialer-side transitions, the §5.1 ping op, and
  the six §3.13/NETWORK type registrations. Anchor vector reproduced (11 new integration
  tests). Surfaced + fixed two latent defects: dead-connection dispatch waiting out the
  full 60 s request timeout, and `Peer.stop()` deadlocking on Python 3.12+ while a remote
  held an open connection.
- **`v0.8.0` "Genesis" release** cut on `master`; the three published packages aligned to
  `0.8.0`; clone-fresh build verified (`make build` / `make test` green from a fresh
  clone with no sibling repos and no host toolchain beyond `make` + `podman`).
- **Build unified onto `make` + `podman` as the sole build door** — removed `mise` and
  the `docker-compose` alternate entrypoints; the `Makefile` drives raw `podman` over a
  pinned multistage `Dockerfile`, with podman resource caps added.
- **Conformance vectors moved out of `docs/`** into `tests/conformance/` so they survive
  the publish scrub (the content and type vector sets).
- **Multisig attenuation-across-depth vectors fixed** to spec-valid delegation chains —
  per-granter resource canonicalization correctly exposed that the stale tests granted a
  multi-sig root to a non-signer grantee; the implementation was right, the tests were
  wrong. Suite back to zero failures.
- **Encryption extension landed** — crypto substrate, three modes, a passphrase-wrapped
  (Argon2id) key-backup tier, and the associated entity type definitions. (The self-mode
  KATs run a memory-hard derivation and are marked `slow`.)
- **Registry extension** — a petname backend plus a peer-issued registry backend with
  live registration (register-request + issuer-policy) and a curated operator CLI.
- **Relay extension** — source-routing, raw-frame terminal-hop, and inbox-relay paths,
  exercised Python↔Go over a live wire.
- **Discovery extension** — substrate plus an mDNS backend and announce support.
- **Format agility / peer-id hardening** — Ed448 + SHA-384 support, content-hash-format
  negotiation, format-relative deletion markers and content paths, and identity loading
  that always re-derives the canonical peer id rather than trusting the file.

## Next

1. Run the conformance + interop suites live against a current reference peer to confirm
   green at HEAD — cross-impl reports lag, so trust a live run, not a dated report.
2. Continue tracking upstream spec changes; fold landings in and prune confirmed-legacy
   paths as the spec settles.
