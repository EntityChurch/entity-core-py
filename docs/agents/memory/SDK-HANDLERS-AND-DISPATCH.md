# The SDK tier, handler surfaces and dispatch

**When to open this:** Open this when wrapping a handler operation in `entity-sdk`, or when a change touches the dispatcher.

`SDK-EXTENSION-OPERATIONS` drift against the normative extensions, what an SDK absorbs at a `MAY`, the two dispatch paths, and values carried in two representations across a boundary.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **Two hand-rolled copies of one traversal are one defect with two consequences, and the measured
  one is not the worse one.** *Candidate, 2026-08-22 — the two-representations law with a
  **traversal** as the subject, found while fixing D8.* `_walk_deps` (reactive dependency
  registration) and `_audit_walk` (install-time static audit) each carried their own copy of the same
  four-case enumeration. Arch measured `_walk_deps` and named its failure: a reactive expression that
  evaluates once and is never woken. **`_audit_walk` has the same gap with a worse consequence** — a
  `compute/apply` nested past the enumerated shapes is never reached, so its install-time
  capability/resource check and the F5 structural error never run, and the subgraph installs clean.
  Nobody named that site, in any of the three seats' reports. **The check:** when a routed finding
  names a function, grep for the *concept* rather than the identifier — a traversal, a matcher, a
  validator — and fix the class. The second copy is always the one written for a narrower purpose
  before the rule existed. Enforcement point: `_referenced_entities`, the single traversal both
  walkers now call, plus
  `test_compute_d8_walk_completeness.py::TestTheAuditWalkerSharesTheTraversal`, whose F5 row is the
  one with teeth.

- **Two representations of one value is a bug that hides until the boundary — cover the
  form your own tests never mint.** `compute/error` is carried two ways here: `make_error`
  returns a **dict**, a stored error *literal* resolves to an **`Entity`**. Every
  evaluator-internal consumer goes through `is_error`, which handles both, so the split was
  invisible — right up to the compute→non-compute crossing, where two of three paths
  assumed dict, the `Entity` fell through `_as_entity` as `primitive/any`, and cbor2 killed
  the inbound handler task (`CBOREncodeTypeError: cannot serialize type Entity`). The peer
  then answered **nothing**, so the caller saw an i/o timeout — a serialization bug wearing
  a network bug's costume, and the worst shape a failure can take.
  **Why our suite missed it for so long:** every pre-existing error-propagation test
  triggers errors with *unresolvable hashes*, which mint the dict form. ~300 compute tests,
  100% on one of the two representations. **The check:** when a value has more than one
  in-flight representation, find the boundary functions (anything that returns to the wire,
  the tree, or the content store) and parametrize over *both* forms — the one your test
  helpers construct is not the one that breaks.
  **Third instance, 2026-08-16 — the same law twice more, so read the two refinements it
  forced** (arch's SA-9 `store` ruling, `662e409`):
  - *One value can have two boundaries wanting two answers.* The fourth crossing arrived
    and it did **not** want `error_to_wire`. §2.4 splits them: the **in-flight/dispatch**
    crossing (the F10 status-200 error-as-value) MAY carry `message`/`at`; a **written,
    content-addressed** crossing (§7.2 `result_path`, SA-9 `store`) is `{code}` **alone**,
    or two conformant peers writing the same error to the same path get different hashes.
    The enforcement point is the pair — **`error_to_wire` for the wire,
    `error_materialized` for a write** — and a fifth crossing picks by asking *do these
    bytes get hashed?*, never by copying whichever neighbour it found first.
  - *A predicate can fold two opposite things into one answer.* `resolve_or_error` returns
    the same `is_error` verdict for **resolution failed** and **resolved to a
    `compute/error` literal**. Every consumed operand short-circuits on both, so the fold
    was invisible — until `store`'s write payload, where they are opposites (a literal is
    a value the caller asked to store; a failure never became one). `entity-core-go` has no
    such hazard: there the two are different *types*. **When a helper answers a predicate
    for two causes, check whether any caller needs them apart before you exempt it.**
  **Fourth instance, 2026-08-17 — the law jumps from values to the gates that watch them.**
  Building the presentation-purity gate (`test_package_layering.py`), the first draft
  budgeted one form of protocol leakage: the `{"type", "data"}` envelope literal. But
  protocol leaks into a renderer **three** ways — hand-built payload, raw `.execute()`
  dispatch, hand-built `entity://` addressing — and the CLI does all three (8 / 17 / 21).
  A gate watching one form **reports the other two as clean**, which is worse than no gate:
  it converts an unmeasured risk into a false green. Same law, new subject — *one concern
  with several representations, coverage on one of them* — except the thing under-covered is
  now the **enforcement point**, so the failure is silent by construction.
  **The check when you write a gate:** enumerate the forms the thing you are forbidding can
  take, and budget each separately. If you can name a second form and your gate does not
  count it, the gate is not yet a gate.
  **And measure the budget, never guess it.** That same first draft asserted a budget of 17
  from *"one envelope per subcommand"* reasoning. The staleness half of the ratchet — an
  entry that overstates reality fails too — reported the real figure as **8** on the first
  run. **A ratchet must fail in both directions**: a too-loose budget is cover, and it is
  the direction an author's own estimate always errs. The gate's first act should be able to
  correct its author; this one's was.
  **Fifth instance, 2026-08-17 — a config field has two sites, and the tests all pile onto
  the validator.** `EXTENSION-REVISION` §2.4's `exclude` is *checked* at config write
  (§4.4.17 V1-V5, which refuses `auto_version: true` without the required patterns) and
  *used* at snapshot build (§4.4.1's `compute_versioned_bindings`). This repo implements
  the first and **not the second**: `_get_snapshot_bindings` never reads the config, so an
  exclude list is validated, stored, and applied to nothing — and a py peer's trie root for
  a configured prefix differs from go's, i.e. different version hashes for identical
  content. All ~87 revision tests exercise the validator; none drove the snapshot. **The
  check: for any field with a validator, find the consumer and test *there* — a validator
  proves the field was accepted, never that it acts.** Filed as SA-PY-8 (the auto-version
  half is a genuine spec question), pinned by
  `test_commit_does_not_yet_apply_config_excludes`, which fails when the fix lands.

- **`SDK-EXTENSION-OPERATIONS` has drifted from the extension specs it summarizes — check
  both before implementing a wrapper.** *Ratified 2026-08-17 — three instances in one
  session (SA-PY-2, -3, -4), across two unrelated extensions.* The SDK doc is *the document
  an SDK author reads*, and on every wrapper built this session it disagreed with the
  normative extension: §3's `events` vocabulary (`put`/`remove` vs the pinned
  `created`/`updated`/`deleted`), §3's `rate_limit` unit (per-second vs per-minute, 60×),
  and §6's whole query result shape plus an operator name (`entries`/`content_hash`/`neq`
  vs `matches`/`hash`/`not_eq`).
  **Triage by failure mode, because they are not equally dangerous.** SA-PY-4's items all
  fail *loudly* — a `KeyError`, a `400` — and cost one debugging session. **SA-PY-2 fails
  silently**: a subscription built from the SDK spec is created, returns an id, appears in
  the tree, and never fires for its entire lifetime. That is the one worth finding first,
  and the class to hunt for in every remaining extension: *a value compared by equality
  against a list the other document spells differently.*
  **The procedure:** open the extension's normative schema section **alongside**
  `SDK-EXTENSION-OPERATIONS` before writing the wrapper, and where they differ, implement
  the extension, absorb the difference at the SDK boundary, and file the SA. Never resolve
  a disagreement by picking the doc you happened to open. Enforcement point: an SA entry
  per divergence plus a test that drives the *engine's own* predicate with the SDK doc's
  spelling — `test_the_pre_ruling_spelling_would_have_matched_nothing` is the template,
  because it proves the contradiction against the implementation rather than arguing it
  from two texts.
  **Outcome, same day:** all three ruled in our favour at `SDK-EXTENSION-OPERATIONS` 0.8.1
  as SA-2 / SA-3 / SA-4, each recording the pre-ruling text inline. The proof-against-the-
  engine test is what made them decidable rather than arguable — write that test first.
  **Fourth extension, same day — and the drift is not only in names (SA-PY-5, SA-PY-6).**
  §4 vs `EXTENSION-REVISION` diverges in **seventeen** places: thirteen params/result rows
  and four rows about *which layer an operation lives in*. The second class is new and is
  worse, because following it means **building the wrong thing** rather than misspelling a
  field — §4 files `pull`/`push`/`diff`/`cherry-pick`/`revert`/`find-ancestor` as SDK
  workflows the extension makes handler operations, and tells you to write branches and
  tags as plain tree puts at **unhashed** paths (`system/revision/branches/{name}`) that
  the handler, which reads `system/revision/{H}/branches/{name}`, never looks at. The
  branch write returns 200 and reads back with `get`; every revision operation says the
  branch does not exist. Worse still, §4's client-side `checkout` recipe ("read trie,
  batch-write bindings") violates §4.4.4's version-transcription invariants — wrong diff
  baseline, and deletion markers bound into the live index. **So the check is not only
  "does this field have the same name?" but "is this even an SDK's job?"** — and the answer
  lives in the extension's §4.1 manifest and §4.2 core/convenience table, which is the
  first thing to open on any wrapper.

- **An absorption is a debt to the ruling, not a permanent feature — retire it when the
  spec lands.** *Candidate, 2026-08-17, and the first thing a ruling asks of us.* While an
  SA is open the SDK absorbs the divergence so callers see one behaviour. **The moment
  upstream rules, the compatibility path names a vocabulary no document defines**, and an
  SDK accepting a spelling nothing sanctions is manufacturing precisely the local
  divergence this repo exists to *find* in other people's stacks. `AGENTS.md`'s no-legacy
  rule is not a separate concern; this is what it is for. Retired at the SA-2/-3/-4
  rulings: the `put`/`remove` subscribe alias, the `neq` operator alias, and
  `QueryResult.entries` / `Match.content_hash`.
  **Two things the retirement has to get right, and both were nearly missed:**
  - *Check whether the retired spelling is still normative somewhere else.* `put`/`remove`
    are **not** dead — they are `ChangeEvent.event_type` in `SDK-OPERATIONS` §6.1, the L1
    `watch()` surface. So the caller passing `put` to `subscribe` is confusing **two real
    vocabularies at two levels**, not typing badly. Deleting the alias silently would turn
    a documented confusion into a bare "invalid". The 400 names the level each belongs to
    and gives the mapping.
  - *Say which ruling moved it.* A caller on a pre-ruling copy of the doc made a
    **documented** mistake. `neq` raises an error naming SA-4 and the new spelling, not
    "unknown operator". An error that only refuses makes the reader re-derive what the
    corpus already decided.

- **A second dispatch path is a second boundary, and the in-process one is the untested
  half.** ***RATIFIED 2026-08-18*** *— third instance, and the first where the untested half
  was an* authorization *check rather than a lookup. Filed as a candidate 2026-08-17; the
  two-representations law again, subject = the pathway.*
  **The instance that ratified it.** §5.2 requires all four grant dimensions at dispatch and
  names the handler's own check *secondary*: "the dispatch-level `check_permission` handles
  the primary resource check." `handle_execute` ran it. `_dispatch_local_execute` accepted
  `resource_targets`, forwarded them into the child `HandlerContext`, and consulted
  `grant.resources` **nowhere** — so on a sub-dispatch the primary check was absent and the
  secondary one exists in **8 of the 70** non-`__init__` modules in `entity-handlers`.
  `system/handler:register` is the sharp end: §6.2 assigns the authorization of the install
  path to precisely that check and the handler performs none, so under a grant scoped to
  `app/*` a sub-dispatch reached it with pattern `pwn`. Fixed `00b2c05`.
  **`entity-core-go` has the same gap** (`makeLocalExecute`, `core/protocol/local.go`,
  `41ecf0b`: `CheckPermission(types.ExecuteData{Operation: operation}, …)` — a literal with
  `Resource` nil, while `childResource` is computed twelve lines later for the child
  context). rust unverified. So this is not a py quirk; it is the shape the *cohort* gets
  wrong, which is the argument for making it a standing rule rather than a fixed bug.
  **Why the suite was no help, and the part to carry:** every join/continuation test here
  drives a **stub** `_execute_dispatcher`. 3667 tests, and not one exercised real in-process
  authorization. *A test that substitutes the dispatcher cannot be evidence about the
  dispatcher* — when the thing under test is the seam, the stub is the bug's hiding place.
  **Second instance, 2026-09-09, at the same seam and in the opposite direction (SA-PY-45).**
  Landing PD-2's outbound check took `convergence.rexec_delivered` FAIL against a **4359-green**
  tree — a cross-peer continuation advance stopped being delivered. Same cause, one layer out:
  every continuation *cross-peer* test here also drives a stub, so the suite could not see a
  change to the real outbound path either. **The first instance was a missing check the stub hid;
  this one is an added check the stub hid.** A stub is not biased toward false green or false red
  — it is blind, and what it hides is whatever you just changed.
  **The consequence for scheduling, which is the actionable half:** a change to the dispatcher is
  a change **no local run can measure**, so the cohort validator is not a final gate for it, it
  is *the* measurement — run it before believing a dispatcher diff, not after. Here the two-peer
  check found a cohort-wide spec conflict that three green suites had no way to surface.
  Enforcement point: `tests/integration/test_authz_resource_dimension_in_process.py`,
  which drives a synthetic handler that performs **no** `check_caller_permission`, so the
  assertion is about the dispatcher's verdict and not a handler's, with in-scope controls on
  both seams and the wire rows in the same file.
  **And the fix's own fallout is the lesson's second half.** Running the check for the first
  time turned core-go's `join_target_received` PASS → WARN, deterministically. Traced (A1)
  from the peer's log — `[dispatch:internal] resource scope denied` — to a §5.5a granter-frame
  question nobody had an opinion on *because nobody was checking*. **Adding a check that
  should always have run is a behaviour change; budget for the second finding it exposes.**
  Filed SA-PY-9 (does §5.2 bind internal sub-dispatch) and SA-PY-10 (which peer frames a
  stored `dispatch_capability`).

- *(the candidate that became the rule above)* The registry handler found its §6a.9 layer-1 proof (the bundled `system/peer`
  + `system/signature`) by searching the tree and the content store. Both are populated on
  the **wire** path, where `_store_included_entities` persists `included` on receipt (V7
  §1.5). An **in-process dispatch has no receive step** — the bundle exists only as
  `ctx.included` (V7 §3.3 v7.51), which `capability.py`, `relay.py` and `identity.py`
  (SI-11) all read and registry alone did not. So a correctly signed request got
  **`401 signature_invalid`**: an authentication verdict handed to a caller who failed no
  authentication, which sends the reader hunting a key problem that does not exist.
  **Why nothing caught it:** every caller was the CLI reaching a peer over a connection.
  The defect surfaced on the *first in-process caller registry ever had* — an
  `EntityClient` composed over `HandlerContextDispatcher` — i.e. it was created by
  building the SDK tier, not found by it.
  **The check:** `EntityClient` composes over a `Dispatcher`, and there are two
  (`HandlerContextDispatcher` local, connection-backed remote). When wrapping a handler
  that reads *anything* off the envelope — `included`, bounds, author attribution — drive
  it on **both**, because "works over a connection" is not evidence about the local path
  and every existing test of that handler used the same one. Enforcement point:
  `tests/integration/test_sdk_registry.py::TestLayer1ProofReachesTheHandlerOnBothDispatchPaths`.
  And when reading a bundled entity, **validate the hash before trusting it** (§1.8): the
  map key is the sender's claim, so `_bundled` returns nothing unless the entity hashes to
  the key it arrived under.

- **`EmitPathway.subscribe` accepts any pattern and silently matches nothing.** Its
  matcher (`_pattern_matches`, `storage/emit.py`) handles `*`, `prefix/*` and exact, and
  falls through to an **exact string compare** for everything else. So a reserved form
  like `docs/*/intro` registers without error and never fires, for the life of the
  process — a subscription to nothing, with no moment at which it looks wrong. **Audited
  2026-08-17: every in-tree caller subscribes `"*"`, so nothing is currently dead**, and
  the only caller-supplied pattern is the diagnostic tap's. `entity-sdk` converts the
  unsupported forms to a 400 at its boundary (`validate_watch_pattern`), which is the
  §6.1 status for invalid pattern syntax. **The peer's behaviour is pinned by a test**
  (`test_the_peer_really_does_accept_and_never_match`) rather than asserted in a comment,
  so if core ever starts rejecting or supporting the form, the SDK check gets revisited
  instead of quietly becoming wrong.

- **A spec `MAY` is cross-peer nondeterminism the SDK absorbs, not nondeterminism it
  forwards.** *Candidate, 2026-08-17 — bit us once, at the first operation we built.*
  `SDK-OPERATIONS` §3.4 lists 404 for `remove` and then says *"implementations MAY
  silently succeed."* Our tree handler silently succeeds; a conformant peer may 404. The
  first draft of `EntityClient.remove` exposed a `missing_ok` flag — which **forwards the
  coin flip to the caller**: identical caller code raises against one peer and not
  another, and the defect surfaces only on contact with a second implementation. That is
  precisely the class of bug this repo exists to *find* in other people's stacks, so
  shipping it in our own SDK would be an unusually poor trade. **The rule:** at a `MAY`,
  the SDK picks one branch, once, and documents which — every peer then looks the same
  from above. Where the caller genuinely needs the distinction, give them a separate
  operation that answers it directly (here: `has`), never a flag that means "tell me
  whichever thing this particular peer happens to do."
  **The enforcement point** is a test per absorbed `MAY` that drives *both* peer
  behaviours — one against the real peer, one against a stub returning the other answer —
  and asserts the SDK surfaces the same result. `test_sdk_l1_operations.py`
  `test_remove_is_idempotent` + `test_a_404_from_a_peer_that_reports_one_is_also_absorbed`
  are the pair. A single-sided test proves nothing here: our peer only ever produces one
  of the two answers, so the untested branch is the one that breaks on contact.
