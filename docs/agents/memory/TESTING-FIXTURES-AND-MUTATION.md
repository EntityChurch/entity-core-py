# Tests, fixtures, mutation and what a green suite does not prove

**When to open this:** Open this when writing a test for a rule, building a probe, or reading a result you are about to cite.

The mutation discipline and its failure modes, fixtures that cannot discriminate what they claim to, controls, skips that read as passes, and the several ways a suite can be green about the wrong thing.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **A vector whose expected value is unfilled RUNS your code and measures nothing — and it is
  green, every time, for the life of the corpus.** *Candidate, 2026-09-16.* Arch's `.26` note
  is *"nobody had ever EXECUTED a Class-B category… reading a normative artifact and running it
  are different acts, and only one of them is a measurement."* This implementation is the sharper case:
  py **executes** all three Class-B signature constructions on every suite run, via
  `emit_canonical`, and `test_emit_canonical_no_errors` asserts `errors == {}` and the result
  counts. The corpus it loads is the **pre-cross-bless STARTER** copy in which every
  `encode_equal` vector's `canonical` is `h''`. **So the act was performed and still was not a
  measurement** — an emission compared to nothing cannot disagree, and that is exactly how
  `_emit_signature` carried the losing reading undetected.
  **This is `AGENTS-STANDARD`'s *a skip counts as a failure* with an unfilled ORACLE instead of
  a skip** — and it is worse, because a skip is reported and an empty expected value is
  indistinguishable from a pass in every counter. The suite says *"64 encode_results, 0
  errors"*, which reads as coverage and is a count of *emissions*.
  **The check:** for any corpus-driven harness, assert that the expected values are **present**
  before trusting the run — and where they are absent, the oracle has to be the rule itself.
  Enforcement point: `tests/unit/test_corpus_provenance_s2.py`, which pins that the Class-B
  canonicals are still `h''` **with the retirement condition in the assertion message**, so the
  day the published corpus is adopted the row tells its reader to flip to byte equality.
  *(Its own first run corrected its author — the draft asserted py's corpus had no Class-B
  category at all; the categories are identical and 69-vs-71 is two extra `nested` vectors.)*

- **Your own DECODER is a filter between your probe and the defect — the receive-side mirror
  of "your own serializer cannot express the attack."** *Candidate, 2026-09-15.* The N4 row
  named `test_undecodable_cbor_still_gets_a_coded_frame` drives
  `b"\xff\xff\xff\xff not cbor"`. **That payload decodes.** `\xff` is the CBOR break
  marker, so `ecf_decode` returns a `BreakMarkerType` and never reaches its error path; the
  refusal came from `data.get("root")` raising a bare `AttributeError` one line later. The
  row passed, and it was measuring an `AttributeError` rather than un-parseable CBOR for the
  life of the file.
  **And the thing it was hiding is a rule of arch's own.** §4.7's widened scope is *"a frame
  that never becomes an **Envelope**"* — which is broader than *"does not decode"*, and this
  peer had no check for the gap between them: CBOR `null`, an integer, a break marker all
  decode cleanly and none has a `root`. Found only because the arm (f) survival row demanded
  a stream disposition, and an `AttributeError` carries none.
  **The check:** when a probe's input is meant to be rejected by a **parser you own**, assert
  that it was rejected **by that parser** — not merely that the request failed. A payload
  that survives your decoder is testing whatever happens next, and the two are
  indistinguishable from the outside because both answer 400. Cheapest form: drive the input
  at the decoder directly in one row, and keep the wire row for the behaviour.

- **If the claim is about what goes on the WIRE, the row has to read the wire — and a docstring
  is where an unasserted claim gets laundered into a cohort measurement.** ***RATIFIED
  2026-09-14*** *— the "two representations" law with a **claim** and its **evidence** as the
  two, and the first instance where the false claim had already been routed to two sibling
  seats as our data point.* `test_resolution_integrity_k1.py`'s module docstring read: *"go
  refuses by a receive-boundary connection close with no status … **py answers a coded 401 on
  one arm and a coded 400 on the other**, so this implementation's data point is: the coded response is
  reachable."* The 401 arm is true. **The 400 arm was false.** Its row asserts
  `pytest.raises(HashValidationError)` against `recv_envelope` called **directly**, and the
  bridging sentence — *"which the wire boundary renders as that pair"* — is prose nothing drove.
  The serve loop caught the exception, logged at INFO and `break`'d: **a bare close, nothing on
  the wire**, exactly the go behaviour the paragraph contrasts us with. So py argued for a rule
  it did not implement, and go's routed finding was about both of us.
  **The mechanism is that the test was RIGHT about its own subject.** The row measures which
  mechanism refuses the forgery, and it measures it correctly; the docstring then added one
  clause about what reaches the wire, which is a different surface with a different boundary and
  no assertion behind it. **A docstring sits at the same indentation as evidence and is not
  evidence** — and it is the part a routing packet quotes, because it is the part written in
  prose.
  **Two checks.** When a test's docstring makes a claim about a **layer the test does not
  drive**, either drive it or delete the sentence; *"renders as"*, *"which the wire boundary
  turns into"*, *"i.e. a 400"* are the tells. And before quoting your own tree into a packet as
  a cohort-comparable number, **open the row that backs the number and check what it asserts** —
  ours asserted an exception type. Enforcement point:
  `test_decode_boundary_refusal_n4.py`, every row of which opens a socket and reads the frame,
  with the K1 docstring corrected in place (not edited away) so the retraction is legible to
  whoever arrives from the old packet.

- **A race with TWO windows has ONE observable, so closing either window turns the cohort row
  GREEN — and the row cannot tell you the other is still open.** *Candidate, 2026-09-13 — found
  running the cohort number `entity-core-go` asked for, which reddened a row with nothing to do
  with the diff that prompted the run.* `validate-complete.sh python` scored
  `published_root.v5_outbound_dial` **FAIL** — `fetch signature entity: … 404`. The prior number
  was `1644 · 0 F @ b8ee9e5` and the check has not changed in go since their initial release, so
  the row moved at this implementation. **It was not the session's diff:** `published_root.py` was untouched
  and `serving.py`'s only change sat inside `CapTokenScope`, which the `--publish-root` path never
  constructs.
  **The verify cycle is TWO fetches** — `MANIFEST_GET` hands a consumer the head, then it fetches
  that head's signature and MUST verify before walking (§1.1). **Two independent windows produce
  the identical 404:** *consumer-side*, a republish between the consumer's two fetches, because the
  §6.5.6 Amendment 10 recompute replaced the anchor set wholesale; and *publisher-side*, because
  `publish_root` bound the head **before** its signature, so there was an instant at which this peer
  served a head no one could verify.
  **Fixing the consumer-side window alone turned the row green — measured, `0 F`, with the
  publisher-side window still fully open.** That is the entry. A wire row that samples a race is
  evidence about the sample it drew, and *"we fixed it and the gate is green"* is the weakest
  possible evidence about a race.
  **The sibling had both halves and labelled which was primary.** go's `ext/httplive/
  closure_scope.go` carries a bounded `recentSigs` ring **and** *"the publisher now binds the
  signature before the head to close the window"* — with the ring called, in their own words,
  *"the second line of defence."* **We had independently built their backup and not their primary**,
  and no local run and no cohort row could have said so. *(Ours is the reverse of the usual
  direction: the cohort's convergence laws are about a sibling's claim being wrong; here their code
  was simply ahead, and reading it was the whole check.)*
  **Two checks:** when a cohort row reddens on a race, **enumerate every window that produces that
  observable before fixing one**, and read the sibling's fix for which window *they* call primary.
  And the fixture half, a new subject for a standing law: `test_live_closure_scope_follows_the_
  republished_root` drove the **payload** arm of the exact recompute that dropped the anchors — so
  **when a cache is invalidated wholesale, the rows you owe are one per thing the old cache
  CARRIED, not one for the thing the invalidation was written for.**
  Enforcement points: `TestSupersededAnchorsStayServable` — the headline row plus a **control**
  asserting a retired root's *content* stays out of scope, which the tempting over-broad fix (union
  the old closures) fails while passing the headline — and `TestTheSignatureIsBoundBeforeTheHead`,
  a behavioural row observing from inside the emit cascade plus a **structural** source-order row,
  because two adjacent correct-looking `emit(...)` calls read fine in either sequence. Three
  mutations, three correct predictions.

- **Your own SERIALIZER cannot express the attack, because it is conformant — so a probe built
  through it tests a degraded shape and passes.** *Candidate, 2026-09-13, building the K1
  author-forgery probe.* `Envelope.to_dict` keys each `included` entry by the entity's own
  `content_hash`. That is correct of a sender and fatal to a probe: *"file the attacker's
  identity under the victim's hash"* silently became *"the victim's identity is absent"*.
  **Both produce 401 on this peer and completely different answers on a key-trusting one**, so
  the degraded arm would have scored a non-conformant peer **green** while reading as coverage.
  **Found by the mutation, not by re-reading the arm.** Restoring the defect (*trust the wire
  key*) should have made the forgery succeed; it did not, and the un-predicted red row was the
  finding. Second cause in the same probe: the arm swapped the identity but kept the **victim's
  signature**, so it refused on the signature — a second, independent refusal, which is the
  standing *"your fixture is not the discriminating configuration"* shape. Re-signing with the
  **attacker's** key while still declaring `signer = victim` is what isolates the binding.
  **The check:** when a probe forges a wire-level value, ask *which of my own constructors
  normalizes it* — a conformant encoder is a filter between your test and the attack. Build the
  wire form by hand (here a `rekey` map applied after `to_dict`), and **verify by mutation that
  the attack SUCCEEDS when the guard is removed**; a probe that never accepts is not a control.
  Enforcement point: `tests/integration/test_resolution_integrity_k1.py::TestTheAuthorForgery`
  — four mutations, and the one that corrected the probe is documented at `_through_the_wire`.

- **THIRD instance of the mutation-restore trap, with the entry on screen and the rule already
  ratified — and the reason it recurred is that the restore is written as CLEANUP.** *2026-09-13.*
  A `git checkout --` was placed in the same shell invocation as a mutation, on an **uncommitted**
  fix, and took the fix out with the mutation. The file's tests then passed (the tests were
  committed, the source was not), and the loss surfaced only on the next full run, as an
  `ImportError` for a function that had existed twenty minutes earlier.
  **What the existing entry does not say, and this is the increment:** the rule is stated as
  *"mutate a committed file"*, which reads as a precondition to check **once**. It is not — it
  is a precondition on **every** mutation in a session, and a session lands fixes continuously,
  so the same script that was safe at 14:00 is destructive at 14:40 with no edit to it. I had
  committed twice already and treated the rule as discharged.
  **The mechanical form that actually holds:** `git status --short <file>` immediately before
  the mutation, or simply `git commit` first — and **never** put the mutation and its restore in
  one invocation, so there is a moment at which the dirty tree is observable. Cost here: one
  re-apply, no shipped defect, because the full-suite run caught it — which is the argument for
  running the full suite after a mutation pass rather than only the mutated file's tests.

- **A SCOPED test run is a claim about the scope, and this repo's tests live at THREE levels.**
  *Candidate, 2026-09-11 — cost: two real regressions rode four commits.* The session's baseline
  was the full `uv run pytest`; every run after it was `pytest tests/unit tests/integration`, for
  speed. **`tests/` also holds root-level modules** (`tests/test_compute.py`,
  `tests/test_handlers_handler.py`, …), and `tests/test_compute.py` is where two G6 regressions
  sat green-by-omission until the final full run. The narrowing was invisible because the scoped
  run *grew* (4099 → 4178) while the full suite's count is 4534 — **a rising number reads as
  coverage**, and nothing in the output names what was not collected.
  **The check:** re-run bare `pytest` before every commit that touches a shared predicate, and
  when you scope a run, scope it to a *file*, never to a directory that has siblings. The
  charter's own build section says `uv run pytest` for the full suite and the scoped forms are
  documented as *one file* / *one test by name* — the directory form is the one nobody sanctioned.

- **A rule that only makes sense against a stricter core is a rule you cannot test here — say
  so in the test rather than letting it read as covered.** *Candidate, 2026-08-18, building
  §11.6.* Two of §11.6's rules turned out to be unobservable in this peer, in opposite ways:
  - **The write ORDER** (tree first, dispatch index second) exists to close a window in which
    dispatch reaches a handler the tree does not declare. This peer cannot open that window —
    V7 §6.2 already makes the handler entity and its grant dispatch prerequisites, so an
    index-first implementation 403s rather than serves. Implemented as written anyway, because
    the rule is cross-impl and a peer that relaxes §6.2 later inherits the window silently.
  - **Close's ordering** has the same shape from the other side: removing the tree entries
    alone already stops dispatch, so the obvious *"dispatch stops after close"* test passes
    against an implementation that forgets to unregister the index. Found by **mutation** —
    the mutation was caught, but by a different test than the one whose docstring claimed to
    be the sharp one. That docstring was corrected rather than the test moved.
  **The check:** when a mutation is caught by a test you did not predict, the prediction is
  the finding. Write down which test actually discriminates and why the obvious one does not —
  an over-claiming docstring is how a later reader deletes the test that was doing the work.

- **A ruling you already satisfy produces no diff, and no diff produces no test.** *Candidate,
  2026-08-20 — R-27.* All **four** of R-27's clauses were already true here on the day it landed, and
  the same was true at `entity-core-go`. That reads as the cheapest possible ruling to absorb and it
  is the most dangerous one: **the normal forcing function for a test is a behaviour change**, so a
  ruling that demands none leaves the surface exactly as untested as it was before it became
  normative. Two of ours were *correct by accident* in the literal sense — `pin-bindings` is
  non-dispatchable because it falls through to `404 unknown_operation`, which nothing prevents a
  later refactor from routing, and it sits textually beside the two operations that *are* routed.
  **The check when a ruling lands and you already comply:** treat "already matched" as a **finding
  about your coverage**, not as work avoided — enumerate the clauses, and for each ask *what mutation
  would break this, and does anything catch it?* Enforcement point:
  `TestSetResolverConfigPinDeltaRequiresPinCap`'s clause rows (dispatchability, ordering, the
  ordering's *reason*, the byte-identity field-drop), each mutation-verified RED on exactly the
  predicted row — because the prediction is the finding, and here it was right for the first time in
  four attempts across this file's history.

- **A detector is only mutation-verified on the peer you mutated — on every other seat it is an
  unarmed claim.** ***RATIFIED 2026-08-30*** *— the "a control-only fixture is not coverage" law with
  a **cross-impl oracle** as the subject, and the first instance where the blind gate was a
  **sibling's** and we were the seat it read as green.* `entity-core-go`'s
  `auto_version.burst_convergence_no_capture_loss` is the wire detector for the last-burst-write
  loss. It is impl-agnostic **by construction** — its oracle is REVISION §6.1 `status.pending`, a
  spec field — and go verified its teeth honestly, by reverting the go fix and watching it go RED.
  It then reported **py PASS** and **rust FAIL**. Measured here: **the check cannot see a capture
  loss on a py peer at all.** With auto-version capture stopped outright by mutation, py still
  reported **16/16 PASS**; with the `pending` fix below, the identical mutation FAILs at the 8s
  settle window. Six clean runs PASS either way, so nothing about the green was suspicious.
  **The mechanism, and it is the reusable half.** `pending` was computed under `if local_hash:` —
  a guard that reads as a null-check and is a **ruling on the absent case**, so 0 meant two opposite
  things: *fully captured* and *captured nothing*. The detector bursts at a **freshly generated
  random prefix**, so a peer that captures nothing for that prefix never mints a head, answers 0,
  and passes the check whose entire purpose is that loss. This is the same shape as the
  `min(binding.ttl, local_max)` entry — a binary operator with no arm for the absent case — arriving
  as an **oracle** rather than an authorization control, and our fixtures sat on the arm with an
  answer exactly as they did there: `TestStatus` covered *(empty tree, no head)* → 0 and
  *(entities, head)* → >0, and never *(entities, no head)*, which is the only combination the guard
  decides.
  **`entity-core-go` carries the identical guard** (`if !headVal.IsZero()`, `ext/revision/status.go`)
  — so this is a blind spot in the **shared** oracle, not a py-vs-go divergence, and go's own teeth
  check could not reveal it because the go bug leaves a head behind. **A verified-RED mutation on
  one implementation licenses a claim about that implementation and nothing else**; the oracle being
  a spec field makes the check *portable*, which is not the same as *armed*.
  **What this does NOT license, stated because it is the tempting over-read:** py's PASS still rules
  out the *partial* shape (head exists, a later write uncaptured) — that arm was armed all along.
  The unmeasured half was total capture failure. **And it reframes rust's FAIL rather than excusing
  it:** a peer can only FAIL this check by having a head *and* uncaptured paths, so rust's
  `pending=3` is not reachable by the blind path and their finding stands as measured.
  **The checks, in the order they are cheap:**
  1. **When a sibling's gate reports you green, mutate your own peer until it goes red before you
     accept the row.** One mutation, one rebuild. A cross-impl check is a claim about your peer that
     someone else armed against theirs.
  2. **When a check's oracle is a spec-defined count, ask what that count answers in the state where
     the subject is absent** — and if the answer collides with the healthy value, the check is blind
     in exactly the state it exists to detect.
  Enforcement point: `tests/unit/test_revision_status_pending_oracle.py` —
  `test_live_paths_with_no_head_are_uncaptured_but_pending_reports_zero` (the arm nothing drove),
  the empty-tree control that keeps it a count rather than a flag, and the head-arm teeth row.
  *The teeth row's first draft asserted `pending == 0` right after `commit` and was wrong (measured
  1: commit writes the head pointer into the live tree, which the new version does not contain) —
  recorded because `test_status_after_commit` had already skipped that count for the same reason,
  and the prediction being wrong is the finding.*

- **A gate that skips when its dependency is absent has never told you it passes.** *Candidate,
  2026-08-21 — found incidentally, and it had been red since the initial public release.*
  `tests/integration/test_cross_impl_publish_fetch.py` is the headline Go-publishes→Python-consumes
  byte-equality drive. It `skipif`s cleanly when the Go toolchain or the sibling checkout is absent
  — deliberately, so a Python-only runner is not blocked. On **this** host both are present, and it
  **fails**: `scripts/fetch_published_fixture.py`'s `PINNED_ROOT_HASH` is
  `c0c1c2c3…dcdddedf` — the literal byte sequence `0xc0..0xdf`, a **placeholder that was never filled
  in**, against a fixture that actually serves `af1c9f6b…`. Bisected to session start and to the
  squashed release commit; it has never passed in visible history.
  **The shape:** *skip-on-absence* + *a dependency almost no runner has* = a check that reports
  green by not running, forever, and whose first real execution is a surprise. `AGENTS-STANDARD`
  already says **a skip counts as a failure**; what this adds is that the rule has to be applied to
  the *conditional* skip, which is the one that looks principled. **The check:** for every
  `skipif` on an external dependency, ask *when did this last actually run?* — and if the answer is
  "unknown", run it once on a host that has the dependency before trusting anything it guards.
  **Was deliberately left unfixed at filing:** the correct pin is not derivable from either tree
  (neither hash appears in any `.md` in `entity-core-go`), and **updating a pin to whatever the code
  currently emits is how a pin stops meaning anything** — that would convert a loud placeholder into
  a silent tautology. Routed to core-go with the measured value instead.
  ***CLOSED at `c27b07b`.*** `PINNED_ROOT_HASH` is now `af1c9f6b…cdd9ab` and the row **passes on a
  host that has the Go toolchain and the sibling checkout** — re-measured 2026-08-30, 2 passed. The
  resolution is the part worth keeping: the pin was *not* set by copying what our code emits. go's
  own consumer (`cmd/fetch-published-fixture/main.go`) verifies the signature and then only
  **prints** the root, so there was no upstream table row to mirror and never will be — which is
  why the slot was stubbed in the first place. Ours is the stricter of the two checks and the only
  one that would notice Go's tree-root computation moving under a fixture whose content did not
  change, so the pin is load-bearing *here and nowhere else in the cohort*, and the call-site
  comment says so. **A pin with no upstream mirror is not thereby a tautology — it is a pin whose
  justification has to live at the call site**, and that is the distinction the original entry
  could not yet draw.

- **A fix that moves a refusal earlier retires the seam an existing test was standing on — and the
  stale row keeps passing for one release if the statuses happen to differ.** *Candidate, 2026-09-01,
  found by running the full suite rather than the new file.* PD-1h moved the foreign-namespace
  refusal from §5.2 authorization (403) to §1.4 canonicalization (400).
  `test_authz_peers_dimension.py::TestOverARealConnection` had two rows driving that seam: the one
  asserting `foreign == 403` failed loudly, which is how the seam-move was found — but its sibling
  asserted `foreign != 403`, and **that row passed, silently, now measuring nothing at all**. A
  negative assertion survives the very change that empties it. The class is broader than this fix:
  **when a refusal changes layer, every test written against the old layer is either a loud failure
  or a passing row that has stopped discriminating, and only the first kind tells you.** So the move
  is: grep for the *old status* across the suite, not for the function you changed. Here the honest
  outcome was that the `peers` dimension is no longer wire-observable at all (core-go's PD-1d #2
  reached from the other side), so the rows were **re-pointed at the gate and relabelled** rather
  than deleted — a reader who finds the class gone has no way to learn the seam moved. The
  re-pointed wildcard row is now the load-bearing one: it drives a request the grant *permits*,
  which is the case a peer with only an authorization path gets wrong, and the case the old row
  could not express.

- **A control-only fixture at a call site is not coverage — and the spec's own example is
  usually the control.** ***RATIFIED 2026-08-19*** *— the "matcher gains a call site" law
  (SA-PY-12) arriving from the coverage side, and the second instance of a test set whose only
  row cannot discriminate the thing it names.* `name_constraints` (§6a.9.1) was pointed at
  §4's matcher in `c65bfe2` and the choice was filed as SA-PY-14 — **correctly**, and the
  ruling adopted it (v1.15). What did not land in the same commit was a row that could tell
  the two candidate matchers apart. The only `name_constraints` test in the repo used `*.lab`,
  which is the example the spec itself carries, and it is **grammar-identical under every
  candidate reading** — so a mutation of the call site to `fnmatch` left the suite green. Arch
  names that same example as the reason the divergence *survived upstream review*, which is
  the tell: **when a spec gives one example for a field, assume it was chosen to be readable,
  not to discriminate.**
  **The check:** after picking a semantics for an under-defined field, write the row that
  fails under the *other* reading, at the call site, in the same commit — and run the mutation
  rather than predicting it. Here the prediction was wrong twice in one pass and both
  corrections went into the docstrings: row 4 (`a[b`) discriminates a `path.Match`-family impl
  (which errors) and a later write-time validator, but **not** Python's `fnmatch`, which
  treats an unterminated `[` as a literal exactly as the ruled grammar does; and the
  "one matcher" identity test asserted two *other* functions' behaviour and never reached the
  admission site at all. Enforcement point:
  `test_registry_ttl_and_dispatch_grammar.py::TestNameConstraintsGrammar`, whose identity row
  reads the admission function's own source — and whose first draft failed on the call site's
  **comment** explaining that it used to be `fnmatch`, the same prose-inflates-a-code-gate
  shape as `entity://` in docstrings. A gate that cannot tell a sanctioned mention from a
  smuggled call is not a gate.

- **When a new rule turns your whole suite red at once, read the fixtures before the rule.**
  *2026-08-18, implementing registry D11/D12.* §6a.9.2 D11 refuses a live issuer policy with
  `default_ttl: null`. Landing it failed **35 of 63** registry tests in one run — and the
  correct reading of that is not "the rule is too strict", it is *every helper in the suite
  had been arming the one policy shape the spec forbids.* The whole registry surface — layer-1
  proof, replay defense, the pending queue, live-wire registration — had only ever been
  exercised against a registry that could mint nothing but bindings §6a.3 rejects. Nothing
  looked wrong because **no test read the `ttl` a binding ended up with**: the field was
  carried, never asserted, so the invalid value rode through every green run.
  Same law as the two-representations entries below, inverted — there the tests covered one of
  two forms; here they covered *only* the invalid one. **The check when adding a validity rule:
  count how many existing tests construct the newly-invalid form. A large number is evidence
  about your fixtures, not about the rule** — and the interesting question is which assertions
  should have caught it (here: any that read the minted binding's lifetime).
  **Repeated the same day with `max_ttl` (v1.11): 14 tests armed the newly-invalid form.**
  Lower than 35 only because the D11 pass had already funnelled them through two helpers —
  which is the useful part. *The count is a measurement of your fixture centralization as much
  as of the rule*, so a second rule on the same entity is the cheap check that the first pass
  actually consolidated rather than patched call sites. And the refusal rows for D11 were given
  a **valid** `max_ttl` so their `400` stays attributable to `default_ttl`: when two rules gate
  one write, every rejection test must satisfy the rule it is not about.
  **A rule can also invalidate the test that proves a different rule.** `set_issuer_policy`'s
  replace-whole test demonstrated "absent means unset" by dropping `default_ttl` — the exact
  field D11 makes undroppable. The rule was unchanged; the field carrying its demonstration
  had to move. **When a MUST lands on a field, grep for tests using that field as an
  *example* rather than as their subject.** Enforcement points:
  `test_reg_set_issuer_policy_null_default_ttl_400` (D11, with the not-stored read-back) and
  `test_reg_null_ttl_stored_policy_fails_closed_403` (D12, seeded by direct tree write since
  D11 now refuses the storable path), each with a teeth control beside it.

- **Mutate a *committed* file, or you will `git checkout` your own work.** *2026-08-18, cost:
  re-applying a finished change.* The mutation discipline (§5.2b.1 — a mutation nobody runs
  is a claim) says disable the fix and watch the test fail. The restore step is the trap:
  `git checkout -- <file>` restores **the last commit**, not the pre-mutation state, so
  mutating a file whose feature is still uncommitted deletes the feature along with the
  mutation. Commit the change first, then mutate, then restore — or keep the mutation in a
  patch you reverse by hand.
  ***THIRD instance, 2026-09-11, with this entry on screen*** *— which is the finding, because
  "be careful" has now failed three times.* The new half is **where the restore lives**: the
  mutation and its `git checkout --` were written as one shell invocation (mutate → run →
  restore), so there was **no moment between them at which the dirty tree was observable**. The
  fix had passed its tests, it had not been committed, and the restore took it out along with
  the mutation — invisible until a `grep` for the identifier came back empty two steps later.
  **The rule is structural, not behavioural: a mutation script MUST NOT contain its own restore
  unless the file is committed.** Either commit first (then the restore is exact), or reverse the
  mutation by re-applying the inverse edit in a separate step you can see fail. Cost here: the
  fix was re-applied from the same script and the commit amended, so nothing shipped wrong — but
  the tests were committed alongside the REVERTED source for one commit, which is a state that
  reads green on the tests it was written to fail.

- **A prescribed VECTOR is a claim that it discriminates, and the two vectors a row's author writes
  are the two on which the readings agree.** ***RATIFIED 2026-09-10*** *— third instance of the
  compose-discriminator law (`F67`'s confused deputy, the `EXTENSION-TREE` Appendix A row ordering),
  and the first where the non-discriminating pair was prescribed by **arch** as a check-set
  requirement.* F68's ruling asks every seat for two vectors: **two targets** → `ambiguous_resource`,
  and **a lone self-excluded target** → `path_required`. Both correct. **Both passed by a peer that
  still ships the bypass**, because the composition has two authorities — *arity* and *identity* —
  and each vector exercises only the first. The discriminator is the **ordered mixed** input,
  `targets=[victim, authorized]` / `exclude=[victim]`: effective arity is 1 under every
  implementation, so a peer that reduces the set to decide the count and then indexes the **raw**
  list answers both prescribed vectors correctly and acts on the target the authorizer skipped.
  **What makes this instance worth the entry rather than a repeat:** the same input is also the row
  **`entity-core-go` currently fails in the opposite direction** — go authorizes every raw target
  (`core/capability/check.go:204`), so it *refuses* a request the ruling makes valid. One input,
  three seats, three different answers, and **no vector in the set reaches it**. A ruling that
  licenses one seat's divergence as *"stricter, safe direction"* is describing the refusal arm and
  not the accept arm; strictness on an accept path is non-conformance.
  **The check:** when a ruling hands you its vectors, ask *what does each one hold constant?* — and
  if every vector holds the same dimension constant, the set cannot see a fix that only moves that
  dimension. Then assert the **identity** of the surviving value, not only its count.
  Enforcement point: `test_effective_resource_target_set_f68.py` row **F-2**, beside
  `TestArchsTwoVectorsCannotDiscriminateAlone` — the arity row kept and **labelled as the
  non-discriminator**, because four rows in a class read as four rows of coverage unless one of them
  says otherwise. Four mutations, four correct predictions; the precise one (drop the rebind, keep
  the import) is what showed the structural row was grepping for an identifier the import line
  already satisfies.

- **A new gate on an argument that gets normalized is a gate on the wrong side of the
  conversion — and your fixtures are all on the arm where the conversion is a no-op.**
  ***RATIFIED 2026-09-03*** *— second instance of the §5.2 `target_peer` shape, and both were
  caught by a sibling's probe rather than by us.* Building row 4's refusal for
  `system/type:compare`, `_unresolvable` resolved the **raw** `type_a`/`type_b`, while
  `op_compare` resolves through `_normalize_type_lookup` — which accepts a bare name
  (`app/user`), a peer-relative path (`system/type/app/user`) and an absolute one. So every
  prefixed form read as unresolvable and answered `404` for a type that exists.
  **The two instances are the same defect in two languages of itself:** there, a new
  authorization check derived `target_peer` *inside* `_resolve_for_dispatch`, after
  `extract_handler_path` had stripped the peer segment. One parameter name, two
  representations, and the check standing before the conversion instead of after it.
  **And in both cases the local test passed because it handed the function a value production
  never gives it.** Here every fixture in the class used a bare name — *including the teeth
  control*, which passes `system/type` — so the whole class sat on the arm the normalizer does
  not change and could not fail. That is the *"two readings that agree everywhere your fixtures
  live"* law with a **normalizer** as the thing being agreed about, and the direction is not
  random: **a fixture author already holds one representation, and it is always the short one.**
  **The check:** when you add a gate to a function, find the conversions between the parameter
  and the value the *existing* logic reads, and write a row per representation — starting with
  the one you did not type. `git grep` the parameter name for a `_normalize`/`extract`/`canon`
  call on the path between the two. Enforcement point:
  `test_type_operation_error_taxonomy.py::test_a_resolvable_type_in_the_PREFIXED_form_still_answers_200`
  plus its absent-type mirror, so a fix that stops checking cannot pass the first.

- **The control that makes a measurement attributable is also what stops it covering the
  neighbour.** *Candidate, 2026-09-03 — 0.8.2.6 Q1, and it is the row rust asked for on exactly
  this ground.* CE-1's rows target the responder's **own** namespace deliberately, so §1.4's
  address gate cannot be the refusing mechanism and the 401 attributes. go's probe carries the
  same precaution for the same reason. **Consequence: nothing in the cohort drove the foreign
  arm, and this peer answered `401 authentication_failed` for every pre-establishment address**
  — which is precisely the *"a peer that fixes CE-1 by relabelling its catch-all passes every
  own-namespace row and fails only this one"* shape, live in our tree one commit after landing
  CE-1. **When a test documents a control as protecting attribution, the case it excludes is
  owed a row of its own**, and the two must be asserted as *different* answers (ours is
  `test_the_foreign_arm_and_the_local_arm_do_not_collapse`) — a peer answering one code to both
  inputs has one gate, not two.
  **And the mutation run found the same asymmetry in the test file itself:** disarming the
  address gate reddened two rows; removing `uri=` from the **HTTP** call site reddened nothing,
  because the foreign rows were TCP-only. The refusal was shared and the *coverage* of it was
  not — the two-hand-rolled-copies shape reappearing on the test side one commit after the code
  side closed it, on the boundary no cohort probe dials.
  **Second half, and it is a correction of mine:** the other routed row —
  *"unauthenticated post-handshake `ping` must be served"* — is **not** a defect here, and the
  first draft of its test said it was. Driven against a **hello-only** socket it gets `409`,
  which looked wrong against the summary. The ruling's own argument is *"by the time the
  connection is established **both peers have authenticated** (§4.6)"*: the subject is a
  **frame-level** unsigned ping on a **fully established** connection, which we already serve.
  **Two senses of *unauthenticated*, and the one-line summary is true under both** — the
  standing *"open the ruling, not the packet that tabulates it"* rule, this time reaching a
  summary **arch wrote about its own ruling**. Both arms are pinned now, the half-open one with
  its reasoning and filed as SA-PY-35, because a later reader "completing" Q2 from the summary
  would serve a keepalive to a peer that has proved nothing.

- **A mutation that reddens NOTHING is a finding about the code, not a shortfall in the test —
  and the usual culprit is a defensive arm that already answers the same thing.** ***RATIFIED
  2026-09-09*** *— second instance in a different shape, and the two shapes want **opposite**
  remedies, which is the part the candidate could not yet say.*
  **Second shape, 2026-09-09, building PD-2's presented-authority arm.** Four verifications, four
  mutations. Two reddened the predicted row. **Two reddened nothing:** disabling the `granter`
  check and disabling the `grantee` check both left 15/15 green. Asking *what else answers this?*
  found, in each case, a **legitimately independent** second refusal rather than a dead arm:
  - the third-party-minted capability the granter row drove is *also* rejected by chain
    verification, whose root check runs in the target's frame;
  - the grantee row left the third party's identity out of the bundle, so `grantee` did not
    **resolve** — a weaker and different refusal than a *mismatched* grantee.
  **So the remedy was the fixture, not the code.** The configuration that isolates the granter
  check is a chain **rooted at the target** whose leaf was delegated on to a third party:
  chain-valid, leaf granter not the target, and nothing else refuses it. Both mutations now
  redden exactly one row.
  **The discriminator between the two remedies, which is what ratification adds:** ask whether
  the second path refuses **the same input for the same reason** or **a different input for a
  different reason**. Same-and-same (the `adopt` shape) is redundancy — delete the arm, because
  the next seat will delete the load-bearing one instead. Different-and-different (this shape) is
  defence in depth, and the finding is that **your fixture is not the discriminating
  configuration** — it is satisfying two refusals at once, so it can never tell you which one is
  doing the work. The tell is cheap: if you can describe an input that the *other* path accepts,
  the arm is live and the fixture is wrong.
  **And the non-discriminating rows are kept and labelled**, not deleted — a reader who finds
  four rows in a class counts four rows of coverage unless one of them says otherwise.
  *(Original candidate, 2026-09-04, landing the type-op alignment:)* The new `404 type_not_found` gate went onto five
  operations and each got a mutation. `converge`'s unarming reddened the two predicted rows;
  `adopt`'s reddened **nothing — 33/33 green with the gate deleted**. The reason is not a weak
  assertion: `op_adopt` raises `ValueError` for exactly one cause, the `except ValueError` arm
  routed it to the same `_type_not_found`, so **two independent paths produced one wire answer**
  and no single mutation could distinguish them.
  **Why the standing laws do not already cover it.** The mutation discipline says *a mutation
  nobody runs is a claim* — this one ran. The prediction rule says *when a mutation is caught by
  a test you did not predict, the prediction is the finding* — nothing caught it, which is the
  case that rule has no arm for, and the tempting reading is *"my row is too weak, strengthen
  it."* **That reading is wrong here and it is wrong in the expensive direction**: it sends you
  to write a sharper assertion for a gate that is not doing any work, and leaves the duplicate
  path in place, where the *next* seat deletes the arm that was actually load-bearing.
  **What it is a shape of:** the two-representations law with **control-flow paths** as the two
  representations. It is invisible to review for the ordinary reason — both paths are correct,
  and a reviewer checking that each produces the right code finds nothing wrong at either. It
  is invisible to the *mutation run* for the interesting reason: the run's whole method is
  single-point disablement, and redundancy is precisely what that method cannot see.
  **The check:** when a mutation fires on nothing, ask *what else answers this?* before touching
  the test. If the answer is a `try`/`except` or a fallback the new gate now precedes, the arm
  is dead by construction — delete it, and let the gate be the only path. Keep a fallback only
  where it answers a **different** status for a **different** cause, which is exactly why
  `converge`/`reconcile` keep theirs and why their mutation fires.
  Enforcement point: `_op_adopt_dispatch` has no `except` arm at all, with the measured 33/33
  green recorded at the call site so a later reader restoring it "for safety" is told what it
  costs; the row that now discriminates is
  `test_an_unresolvable_type_is_404_type_not_found[adopt]`, re-verified RED.

- **Two defects that cancel inside one tree are invisible to that tree's entire suite — and the
  pair you are most likely to own is a lenient RECEIVER plus a lax SENDER of the same field.**
  ***RATIFIED 2026-09-06*** *— the two-representations law with a **protocol layer boundary** as
  the thing represented twice, and the first instance where our own SDK and our own peer were the
  two halves. Filed as SA-PY-41, ruled the next day at 0.8.2.11 §6.3.*
  `EntityClient._put` sent `{"type", "data"}` — two of `core/entity`'s three required fields — and
  `system/tree:put` fell through to `Entity.from_dict` and minted the third. Each defect is the
  other's cover: the SDK's omission never surfaces because the peer supplies it, and the peer's
  authoring never surfaces because nothing local omits the field on purpose. **4289 tests, ~90
  driving `put`, and not one could fail** — a round-trip test asserts the value the caller gets
  back, and that value was right the whole time.
  **The tell is structural, not behavioural, and it is the reusable half.** A compensating pair
  needs *one tree containing both roles* of a wire contract. This repo carries the SDK and the peer
  in-tree (deliberately — see "Project structure"), so **every field on every request we both send
  and serve is a candidate**, and the isolation the tier gates give us is about *imports*, not about
  this. rust has the identical shape at the identical field and did not see it either; go, which
  had only the receiver defect, was the seat that could not help finding it.
  **The check, and there is only one that works:** for a field your own code both **emits** and
  **admits**, the discriminating test is one where the other end is *not yours*. A same-tree test
  cannot distinguish "we agree with the spec" from "we agree with ourselves" — the standing
  `entity-core/7.0` shape (*our constant against our constant*), now with a **required field's
  presence** as the constant. Enforcement points: `test_sdk_l1_operations.py::
  TestTheSDKConstructsTheEntity`, whose rows read the **request** rather than the result and whose
  last row drives the peer's refusal of the old shape so restoring either half alone fails; and
  `tests/interop/test_go_peer_tree_put_decode_predicate.py::test_our_own_sdk_can_now_put_to_a_go_peer`,
  which is the same assertion inverted at the boundary and is the only row in either repo that can
  see the SDK half at all.
  **Two corollaries earned landing it.**
  1. **A ruling that names two layers has a landing ORDER inside your seat, and getting it wrong
     breaks you rather than the cohort.** Sender-side construction first, receiver-side strictness
     second — the reverse leaves your own SDK talking to your own now-strict peer. Arch stated it;
     it is worth restating because *the receiver fix is the one that reads as "the conformance
     work"* and is therefore the one a seat reaches for first.
  2. **Fixing the receiver is not fixing the seat: census every SUBMITTER, including the ones no
     SDK reaches.** Ours were compute's `store` builtin (in-process, dispatches to `system/tree:put`
     with a hand-built dict) and `system/storage:write`'s wire callers. A grep for the *operation*
     finds them; a grep for the SDK method does not.
  *And the count is the fixture measurement, again: **10 of 4289** tests armed the newly-invalid
  form and one asserted it as the contract, docstring and all. A rule landing on a field you have
  never asserted turns your fixtures into the finding.*
