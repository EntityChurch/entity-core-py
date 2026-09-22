# Reading the spec, and censusing our own tree against it

**When to open this:** Open this when implementing a normative rule, walking an error table, or deciding whether something is ruled, unruled or merely unreached.

How a spec sentence turns into a defect: rows with two inputs, codes with no census, clauses with two MUSTs, arms that were never written, and readings that agree everywhere your fixtures live. The recurring unit problem — *what is the thing I am enumerating?* — is what most of these have in common.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **A validator can be complete, tested, corpus-backed — and never called on the path the rule
  governs; and the thing that hides it is that the rule reads as UNIMPLEMENTED rather than
  UNREACHED.** *Candidate, 2026-09-16 — fourth instance of the validator-vs-consumer law (§2.4
  `exclude`, the `peers` dimension, the resolver ceiling), and the widest.* `.26`'s `DR-3` makes
  the CBOR tag policy a §4.11 pre-admission refusal: bytes that DO decode and carry a
  major-type-6 item → `400 non_canonical_ecf`. Measured here before any edit, a **tagged EXECUTE
  and its untagged twin answered identically** (`401 authentication_failed`, CE-1) — the frame
  was **admitted**, because `ecf_decode` preserves tags as `CBORTag` for §1.8 byte fidelity and
  nothing downstream looked. `non_canonical_ecf` had **zero emission sites**.
  **And `is_canonical_ecf` has carried an explicit *"tag encountered (major type 6 forbidden in
  ECF)"* arm since the initial release** — with its only call site in `conformance/emit.py`,
  scoring `decode_reject` **vectors**. A validator with a test suite *and a conformance
  category* and no consumer on the wire path. The three earlier instances were a field with a
  validator and no consumer; this one is a **whole rule** with a validator, and the extra cover
  is that a grep for the concept returns hits, so the surface reads as done.
  **The check:** for a rule your repo owns a validator for, grep the validator's **call sites**,
  not the validator — and ask whether any of them is on the path the rule is about. A
  conformance-emitter-only consumer means the rule is scored against *vectors* and enforced
  **nowhere**. Enforcement point: `tests/integration/test_tag_policy_preadmission_5a.py`, two
  mutations, two correct predictions.

- **A SWEEP is scoped by the input you censused, and a rule whose sentence names two inputs
  will be swept on one of them — by the same author, in the same commit.** ***RATIFIED
  2026-09-13*** *— second instance of the "a ROW can have more than one INPUT" law, and the
  first where the incomplete sweep was **ours**, three commits old, and the missed site sat
  **one method away** from the fixed one.* `SA-PY-58` landed §6.3's handler frame as an
  argument and swept the call sites. **It found two of seven.** The five that kept the widening
  default include `compute`'s `check_write_permission` — whose **sibling read arm was fixed in
  that very commit**, directly above it, under a docstring that *explains the hazard in prose*.
  §6.3's own sentence is *"a tree read, **a tree write**"*; the sweep was censused on the read.
  **Why the adjacency is the tell and not the excuse.** A sweeper greps for the shape they just
  fixed. `check_read_permission` had been *made* correct, so it no longer matched the grep for
  *"omits the frame"* — and its neighbour, which still did, was invisible for the ordinary
  reason that nobody re-reads the function they just edited. The other three sites (§7.2 Phase
  2's `read_paths` loop and both write loops) were missed because **Phase 2b already carried
  the literal**, which is exactly what made Phase 2 read as done.
  **The check, and it is a rewrite of the sweep's own grep:** after fixing a call site, grep for
  the **concept** (*"which call sites of this function authorize an access they do not own?"*)
  rather than for the defect's *syntax*, and enumerate from the **callee's** call graph, not
  from the sites your first grep returned. A census keyed on *"omits the argument"* shrinks as
  you fix things; a census keyed on *"calls this function"* does not.
  **And the structural half is what made the residue findable:** the parameter now has **no
  default**, so a site that cannot name its frame `TypeError`s at its own line instead of
  widening silently — the ordinary spelling of the mistake became a hard failure rather than a
  policy. Enforcement point: `check_path_permission`'s required `handler_pattern` plus
  `tests/unit/test_capability.py::test_an_absent_frame_is_REFUSED_not_match_all`, whose
  predecessor **asserted the opposite** and was inverted rather than deleted.

- **When a ruling has two clauses and only one carries a MECHANISM, the cohort implements that
  one — "we never built the defect" answers the first clause and says nothing about the
  second.** *Candidate, 2026-09-13 — `SA-PY-60`, J4.* §5.2 (0.8.2.22) says (1) *MUST NOT take
  the dispatch type from a received entity's `scope.type`*, and (2) *a received `scope` whose
  declared `type` contradicts its dimension is a **malformed token** and MUST be refused `403
  capability_denied`*. **Both ground-up seats satisfied (1) structurally and neither satisfied
  (2)** — go because their struct has no `Type` field, we because the type is derived from the
  dimension name. go filed **CONFORMS, no code change**, with a regression guard that pins (1)
  and is silent on (2).
  **Dropping is not refusing.** Clause 1 forbids *reading*; clause 2 requires *answering*. A
  peer that silently ignores a contradicting type accepts a token the spec calls malformed, and
  nothing about clause 1's mechanism produces clause 2's pair.
  **Why this direction is systematic rather than sloppy:** a clause you satisfy by construction
  produces **no diff and no test**, so the disposition writes itself and the *other* clause has
  nothing to attach to. It is *"a ruling you already satisfy produces no diff"* with only
  **half** the ruling already satisfied — and the satisfied half supplies the confidence.
  **The check:** when a ruling is a paragraph, **count its `[MUST]`s and answer them
  separately**, and be suspicious of any clause you discharge with *"we don't do that"* — that
  sentence answers a prohibition and never an obligation. Then ask whether the field is one
  **anyone in the cohort populates**: `scope.type` has no producer in any of the three trees, so
  nothing sends one by accident and no suite can see the divergence — the standing *"a field
  with no producer is not converged, it is unmeasured"* law, with the first seat to implement
  creating the divergence. Enforcement point:
  `tests/integration/test_scope_type_is_a_dimension_property_j4.py`, whose absent-type class
  pins the boundary a "be stricter" fix gets wrong (silence is not contradiction) and whose two
  unit rows pin that the malformed unit is the **token**, not the axis and not the capability.

- **When a spec EXEMPTS an operation from a check, the exemption rests on a property of some
  OTHER operation — and that property is the row a sweep skips.** *Candidate, 2026-09-12 — found
  auditing go's completed H1 sweep; the unswept row did not merely leave a gap, it re-opened the
  two that were swept.* `EXTENSION-TREE` §8.4's table has **four** rows — `snapshot`, `diff`,
  `merge`, `extract`. go's `77da7ea` filtered `handleListing` and `handleExtract`;
  `handleSnapshot` still builds its trie from `LocationIndex.List(prefix)` unfiltered, checked at
  the prefix alone. So did ours.
  **The composition, driven rather than argued.** §11's table says *"`diff` — operates on stored
  snapshots; **no path-level check**."* That exemption is correct **only while a snapshot cannot
  commit to bindings the caller may not see.** With an unfiltered snapshot: snapshot the prefix,
  diff it against an empty one, and read the excluded keys — and their content hashes — out of
  `added`. Measured here. The filtered listing and the filtered extract are both reachable around,
  using the one operation the corpus says needs no authority at all. *And this peer hoists the trie
  **nodes** into `envelope_included`, so the excluded key is **delivered** in the response body; no
  second request is needed to walk it.*
  **Why a sweep skips it, and this is the generalizable half.** A sweep enumerates the sites that
  **perform the check**. An exempt operation performs none, so it is *structurally absent from the
  enumeration* — and its exemption is the reason it is absent. The check whose absence matters is
  then in a **third** operation (`snapshot`), which the sweeper has no reason to visit because
  nothing about it names the code being swept.
  **The check:** when a spec exempts an operation from an authorization check, write down the
  sentence that makes the exemption safe — it will name a *different* operation — and put that
  operation on the sweep. *"No path-level check"* is never a property of the exempt operation; it
  is a bet on its inputs. Enforcement point:
  `test_bulk_read_per_entry_filter_6_3.py::TestSnapshotIsTheRowThatSubsumes::
  test_diff_against_the_snapshot_enumerates_nothing_excluded`, which drives the composition rather
  than asserting the snapshot row alone — the snapshot row passes on a peer that filters snapshot
  and nothing else, and says nothing about why it matters.

- **An ABSENT arm is invisible to every method that starts from the code — mutation, grep and
  review all need a call site, and it has none.** *Candidate, 2026-09-11 — found auditing
  0.8.2.21, not routed by it; `SA-PY-54`.* §5.2's `check_resource_scope` has **two** arms and
  says so in its own opening comment. This tree had the concrete one and fell through to it for
  patterns, so against `include:["/{p}/*"] exclude:["/{p}/data/secret"]`: the **concrete** target
  `/{p}/data/secret` was DENIED and the **pattern** `/{p}/data/*` — which spans the exclusion —
  was **ALLOWED**. A caller neutralizes a grant exclude by re-spelling its own target, needing no
  authority it does not already have. `F68`'s law with the **spelling of the target** as the
  vacuum-inducing input.
  **The three helpers §5.2 names by name — `patterns_overlap`, `strip_wildcard`, `is_covered_by`
  — had ZERO occurrences in this repo.** That is what makes this class different from a weak
  check: there is no line to mutate, no token to grep, no call site for a reviewer to stop at, and
  the function containing the hole reads as complete because the arm it is missing was never
  written. **Landing it broke no existing test among 4580** — the same fact from the other side.
  **The only method that finds it is walking the spec's normative pseudocode against your function
  BLOCK BY BLOCK**, asking *which branches does this function have that mine does not* — the
  inverse of the usual direction, which reads your code and asks whether it is right. Schedule it
  the way the corpus's source-audit rows are scheduled: on the catch-up pass, per normative
  algorithm, not when something fails. Nothing will ever fail.
  **And an existing vector set can be structurally unable to discriminate it.**
  `CORE-RESOURCE-EFFECTIVE-1` arm (e) *does* drive a single pattern target — at a
  resource-**requiring** operation, where §3.3 answers `malformed_resource` **before** this arm is
  reached. So the one vector in the corpus that looks like coverage of pattern targets cannot tell
  a peer with this arm from a peer without it. Enforcement point:
  `tests/integration/test_resource_scope_pattern_arm.py` — the bypass, the **concrete-form
  control** (which is what shows the defect was a divergence between two spellings of one request
  rather than a missing exclusion), both allow-arms, and the row where the caller supplies *an*
  exclude but not the overlapping one.

- **A status slot nobody NAMES is a slot nobody walks — every census this repo has run was
  triggered from outside it.** *Candidate, 2026-09-11.* 501 came from a 0.8.2.7 ruling, 500 from
  0.8.2.8, 404 and 400 from `entity-core-go` probe families. **403 had never been censused**, and
  asking §3.3's own question of it — *which codes do we emit at this status, and does the corpus
  define them?* — found **thirteen** spellings defined nowhere, in eight handlers. Twelve name
  conditions and are ledgered for their owning tables (SA-PY-51). The thirteenth, `403
  forbidden`, is ten sites carrying *"Capability doesn't grant {op} on {path}"* — §5.2a's
  condition verbatim, which `EXTENSION-TREE` and `EXTENSION-REVISION` both spell
  `capability_denied` — and **two of the ten are `system/tree` `get` and `put`**, the most
  dispatched refusals in the peer.
  **Why 403 is the slot this happens in**, and the part that generalizes: *every row that reads
  a 403 is asserting the status.* A refusal is the expected outcome, the test passes, and the
  code field is decoration — the *"a negative security test can PASS for the wrong reason"* law
  with the **code** rather than the gate as the thing nobody checks. Same reason no probe family
  exists: a prober writes rows for codes it can predict.
  **And the census corrected its own routing paragraph.** A `grep -c '"forbidden"'` reported go 1
  / rust 4 and the draft called it a cohort spelling; **walking the sites** shows all five are
  comments and test fixtures and **neither sibling emits it**. That is AP-21's own law — *a count
  of the token is not a census of the slot* — firing inside a census written to apply it, in the
  flattering direction, where it would have converted a local defect into a cohort convergence
  question. Enforcement point: `tests/integration/test_undeclared_403_code_census.py`, monotone
  in both directions, reading **both** emission shapes — `tree.py`'s two sites are hand-rolled
  dict literals, so the call-only extractor the 500 ledger uses would have found eight of the ten
  and missed the two that matter most.

- **A PRIVATE copy of a rule that is CORRECT is the copy nobody revisits when the rule grows an
  arm — and the reason for the copy is usually the ENVELOPE, not the rule.** *Candidate,
  2026-09-11, landing §3.3's third arm.* 0.8.2.20 adds *a single **pattern** target →
  `malformed_resource`* to a row this repo had already censused twice and closed *"at one site"*.
  Adding it to the shared helper turned the gate red on **four operations the helper does not
  reach** — `compute:eval`/`install`/`uninstall` and `continuation:install` — each holding its
  own **correct** copy of the first two arms. Correctness is what made them invisible: every
  behavioural row passed, and a class whose members are codes cannot see a site that emits the
  right ones.
  **The reason all four re-derived the rule is the reusable half:** their refusals carry a
  `compute/error` envelope rather than `system/protocol/error`, so *the shape of the answer* was
  the reason to re-derive *the rule*. The fix is to make the envelope a parameter
  (`require_single_resource_target(..., result_type=…)`) — **a differing result type must not be
  a reason to own a copy of a row** — and to delete the constants the private copies used, since
  a constant left behind after its call sites move is the invitation to re-inline.
  **Measured, and it is why the class rows are labelled:** deleting the shared arm reddens **7 of
  18** rows. The other eleven — `system/handler`'s two verbs and all seven `role` operations —
  answer `malformed_resource` anyway from their own downstream path-shape check, so they score a
  peer without the rule as conformant, *and they are the rows a later reader would cite because
  §6.13 names them*. The three-arms-do-not-collapse row reddens on **none**: without the arm the
  pattern input still produces some third code, so three-distinct is satisfied by a peer with no
  pattern rule at all. Enforcement point:
  `test_path_required_is_raised_by_the_handler.py::TestTheClassClosesAtOneSite::
  test_no_resource_requiring_handler_keeps_a_PRIVATE_copy_of_the_row`, which reads the modules'
  source — because a private copy that happens to be correct today is behaviourally
  indistinguishable from the shared one.

- **Two readings that agree everywhere your fixtures live are one reading, until an oracle
  writes the configuration you would not.** *Candidate, 2026-08-18 — SA-PY-17, found by
  `entity-core-go`'s `registry.v15_dispatch_grammar` against a **3820-test-green** tree.*
  `EXTENSION-REGISTRY` §4.1 step 2's dispatch filter can be read as narrowing per **name**
  (eligible = union of the matching entries' kinds) or per **backend** (a kind named in no
  entry is always consulted). We implemented the second, which is what step 2's own clarifying
  sentence says. **The two readings give identical answers for every configuration in which the
  narrowed backend is in the resolver chain** — and that is every fixture this repo had, plus
  every one a person writes, because narrowing to a backend you do not have looks like a typo.
  The oracle narrows to `did-web`, which the peer does not implement, and only there do the
  readings separate.
  **The check when a spec sentence admits two readings:** do not ask which is more natural, ask
  **what configuration distinguishes them**, and write that configuration down. If you cannot
  name one, the ambiguity is not yet real. If you can, that configuration is the test — and it
  will not be one your existing fixtures resemble, because a fixture is written by someone who
  already holds one of the readings.
  **And the tiebreaker, which is the part that generalizes past this bug:** *a reading under
  which one of the spec's own MUSTs protects nothing is the wrong reading.* §4.1a's catch-all
  MUST forbids naming a name-transmitting backend in the catch-all row; under our reading a
  backend simply **left out of the list** was consulted for every name — a strictly larger
  disclosure, reached by not writing a row rather than by writing a bad one. That argument
  decided it, not the oracle's authority, and it is the argument to reach for first, because it
  is available from the text alone before any peer has an opinion.
  **Corrected within the session, and the correction is the sharper half.** §4.1 step 2 has
  **two** edge cases, not one, and the catch-all argument only reaches the first (*a kind named
  in no entry, when another entry matches*). The second (*a kind named by an entry, when no
  entry matches*) changed in the same commit and was never argued for — it rode along because
  one edit touched both. **An oracle failure that makes you change behaviour is a claim about
  the rows it names, not about the rows the same edit happens to touch: enumerate them and
  justify each.** We settled on excluding in both, which is the conjunction of go's and rust's
  exclusions rather than either seat's position — chosen because it is the only reading that
  satisfies both of step 2's clauses *and* keeps the MUST non-evadable, and because §4.1 step 4
  already says *"fail-closed; no silent fallback."*
  **And the oracle was withdrawn, for the mirror-image reason.** core-go pulled
  `v15_dispatch_grammar` (`8d2f5ad`) with the ratchet *"a wire check must not discriminate on
  an unruled or divergent semantic"* — it passed go-on-go and failed a conformant rust peer.
  **Our error was the mirror image: we let a wire check settle an unruled semantic for us.**
  The check was right that we had a defect and wrong about which rows. *A failing oracle is
  evidence that something is wrong, never evidence about what is right* — and the giveaway here
  was available at the time: the probe narrowed to a backend the peer does not have, i.e. the
  only configuration in which the readings differ, which is exactly the shape of a check
  measuring a semantic rather than a behaviour.
  **Fourth instance, 2026-08-19, filed as SA-PY-23 with the claim *"this one has no bug in
  it"* — and ~~that was the new part~~ that claim was wrong, which is the new part.** §4.1 step 2
  requires a rule *"whose pattern matches unscoped names"* and never
  defines *unscoped name* as a predicate. go and py derived **two sound classifiers** that agree
  on every one of §4.1a's shipped rows and disagree on `*.*`, `a.b`, `*.e*`. We concluded
  neither was wrong and the corpus owed a sentence, took **the conjunction — the strictly larger
  refusal set** — on the section's own cost asymmetry (a false positive is a visible edit with a
  documented override, a false negative is silent irreversible disclosure), and filed.
  **All of that procedure was right and the conclusion it reached was still an under-refusal**,
  because the divergence we enumerated was not the whole divergence.
  ***RULED 2026-08-20*** (§4.1b, v1.19): four conditions, and the third clause **both** seats
  carried — *a dotted literal suffix the star cannot reach into is narrow* — is refused outright.
  *"Any literal at all" is not the line*, because dotted **bare** names are ordinary local names
  under §6a, so `*.lab` handed every such name a user typed to a third party while reading as
  scoped. The line is *does the literal identify an authority or a naming system*, hence §4.1b.1's
  **enumerated** suffix list (`.eth`, and it grows only by spec revision `[MUST]`).
  **The correction, and it is the reusable half:** *when you take the conjunction of two readings,
  you have bounded the disagreement — you have not bounded the error.* Both seats can be wrong in
  the same direction, and a conjunction inherits that shared error silently, because the rows where
  the seats agree are exactly the rows nobody re-examines. **So the conjunction move needs a second
  step: enumerate the rows the two readings agree on and ask what would make *those* wrong** — here,
  *"is `.lab` an authority?"* was never asked by either seat, and one honest reading of the question
  answers it in one line. Enforcement point:
  `test_registry_name_privacy.py::TestUnscopedReach::test_the_rows_the_v1_19_ruling_moved` (the
  moved rows, in both directions, each naming which rule moved it) plus
  `::test_the_enumerated_suffix_list_is_exactly_what_the_spec_enumerates`, which fails on a seat
  that "helpfully" adds `.sol` — because the list growing is a privacy decision, not a config change.

- **Being right about the conclusion is not being right about the rule — and the conclusion is
  what stops anyone re-reading the rule.** ***RATIFIED 2026-08-20*** *— second instance in a
  different shape, and the shapes are mirror images.*
  - *First shape (SA-PY-21 Q1, 2026-08-19).* Our **conclusion** was right (kind-scoped) and our
    **argument** was wrong; arch recorded the argument as explicitly not the justification. Cost:
    the reviewing seat spent a real argument writing the refutation.
  - *Second shape (SA-PY-23, 2026-08-20).* Our **conclusion** was right on `*.*` and `*.e*` — we
    moved to the conservative side ahead of any grammar — and our **rule** was wrong. Cost: a live
    disclosure hole on `*.lab`, a row our rule reached and our conclusion never covered, sitting in
    a **3931-test-green** tree behind a classifier we had just audited and moved.
  - *Third shape (R-27 clause 4, 2026-08-20) — the corollary, and it is the one with teeth.* Our
    **code** was right (authorize-then-validate) and our **reason** was weaker than the real one. We
    ordered it on a *kinds* argument: an authz verdict and a policy verdict are different things.
    Arch's ruling gives an **information-disclosure** reason — §4.3's refusal is deliberately verbose
    (*"every violation, not the first"*), so validating first hands a **config-shaped disclosure to a
    caller with no authority to change anything**. Same lines of code, materially different weight.
    **Cost: none yet, and that is the point** — nothing was wrong, so nothing would have surfaced,
    and *our reason would not have survived a refactor.* Anyone hoisting the violation computation to
    the top of the function reads a tidiness comment, sees no security argument, and reorders.
  **Why the second shape is worse than the first and the third is the sneakiest:** a wrong argument
  behind a right conclusion is inert until someone reads it; a wrong *rule* behind a right conclusion
  **keeps deciding new cases**, and every one it decides inherits the error; a **weak reason** behind
  right code is inert *until someone refactors*, and then it fails silently in the direction the
  comment licensed. The tell is identical in all three and it is a feeling, not a finding: *we
  already looked at this and moved.* **A conclusion you changed recently is the least-audited code
  you own** — the move feels like the audit and is not one.
  **The two checks, both cheap:**
  1. After adopting a position, write down the *rule* you adopted as a sentence, and find one input
     it decides that your evidence never touched.
  2. **Write down the strongest reason you know, not the one that convinced you** — the comment is
     the artifact a future refactor consults, and a correct implementation held for a weak reason is
     one refactor from incorrect. Where the reason is a security property, say which property, and
     put the assertion on the thing the property is about: clause 4's row asserts the **response
     body carries no violation list**, not the status code, because a peer can answer `not_entitled`
     and leak the list anyway.

- **A clause that names a grep as its enforcement point is read as having one — run the grep before
  you believe it.** *Candidate, 2026-08-22, filed as SA-PY-27.* D8's §10.3 clause 3 states a
  grammar invariant (*every reference field is a scalar `system/hash`*, with `apply.args` and
  `let.bindings` the two enumerated exceptions) and names the grep that binds it. Writing that grep
  and running it against the shipping grammar found **both halves wrong**: `compute/construct.fields`
  is a third `{map_of: system/hash}` reference container, unenumerated and long-shipping; and
  `compute/let.bindings` is declared `{array_of: primitive/any}` — its `value: system/hash` lives in
  an untyped struct described only in the prose beneath — so **the grep cannot match the one shape
  the whole ruling exists because of.** The clause enumerates as an exception a row its own
  enforcement point would never have flagged, and that is what makes the blindness read as coverage.
  Same law as the presentation-purity gate two entries down (*enumerate the forms the thing you are
  forbidding can take*), with a **spec clause** as the gate and the declared `type_ref` as the wrong
  inventory unit. **The check:** when a ruling hands you an enforcement point, implement the
  behavioural rule so your conformance does not depend on the gate being right, then build the gate
  and let it correct its author. Ours did, twice, in one run. Enforcement point:
  `tests/integration/test_compute_d8_walk_completeness.py::TestEveryReferenceFieldIsAScalarHash`,
  whose exception list carries *why* each row is there and whose
  `test_the_clause_3_grep_cannot_see_let_bindings_at_all` pins the blind spot rather than working
  around it — so the thing actually protecting us stays legible: the recursive traversal, not the
  grep.

- **A binary operator with no arm for the absent case is a policy decision wearing a type
  guard.** ***RATIFIED 2026-08-19*** *— the validator-vs-consumer law's third shape, and the
  first where the untested arm was the one production always takes. Found by core-go's
  `v4c_ttl_resolver_ceiling` against a **3820-test-green** tree.* §6a.9.1's resolver ceiling is
  written `min(binding.ttl, local_max)`. A binding's `ttl` may be **null** — the sticky kinds
  (`local-name`, `pinned`) always are — and `min` has no answer for that, so the natural
  implementation guards it: `if isinstance(ttl, int)`. That guard reads as type hygiene and *is*
  a ruling: it applies the ceiling **only where a bound already exists**, leaving the unbounded
  case — the entire reason the control exists — uncovered. The control ends up pointed exactly
  backwards, and nothing looks wrong, because every row that *does* have a `ttl` behaves
  perfectly.
  **Why our own suite could not see it, and this is the sharper half:** every fixture in
  `TestResolverCeiling` hand-seeded a `local-name` binding **carrying an explicit `ttl`** — a
  shape `_handle_bind` has never minted (it writes `ttl: None`, sticky per §6.3). So the class
  exercised the arm `min` has an answer for and never the arm production produces, while reading
  as thorough: five rows, a hash-identity gate, an expiry-teeth row. Same law as the
  two-representations entries, with the **fixture** on the wrong side of it: *a hand-seeded
  entity is a claim about what the write path produces, and it is the one claim in a test nobody
  re-checks.*
  **The checks, in the order they are cheap:**
  1. When a spec rule is a binary operator over a field that can be absent, **the absent case is
     a ruling you are making** — write the arm explicitly and name it in the code, or you have
     silently narrowed a MUST. Grep for `isinstance(x, int)` guards standing where a spec
     sentence expected an answer.
  2. **Seed fixtures, then pin them against the production write path in the same class** —
     `test_the_bind_path_mints_the_sticky_shape` is the template: it asserts `bind` still mints
     the shape the other rows seed, so the class cannot drift into testing a shape no deployment
     reaches.
  3. **An oracle vector that reads the response says nothing about the verdict.** go's `v4c`
     reads the surfaced `ttl` off a *freshly bound* name, so an implementation that stamps
     `local_max` into the result and never feeds it to the expiry check **passes the vector and
     still honors a sticky binding forever**. The security property is the honoring. Owed to
     core-go, and covered here by
     `test_row_d_teeth_the_sticky_arm_bounds_honoring_and_not_just_the_number`.
  Enforcement point: `_effective_lifetime` in `entity_handlers/registry.py` — three arms, one
  function, **both** call sites (the expiry verdict and the surfaced `ttl`), because clamping
  one and not the other is the two-representations bug with an authorization decision on one
  side. Rows: `TestResolverCeiling` (all four `REG-TTL-RESOLVER-CEILING-1` rows + read-at-
  resolution + the sticky teeth).

- **A code SLOT is the unit for auditing a CODE; the row's INPUT is the unit for auditing a
  ROW — and a slot is keyed by a status, so it cannot see a site that got the status wrong.**
  ***RATIFIED 2026-09-03*** *— the "walk every row of a table when a sibling reports N" law
  with the **census method** as the subject, and the third turn of arch's own AP-21.*
  Arch ruled §3.3's default-code force (0.8.2.7) on the finding that *a count of the token is
  not a census of the slot*: 0.8.2.6 swept `unknown_operation` and reported the 501 class
  closed while `not_implemented` survived in all three trees. They then censused **by slot**
  — every code emitted at status 501 — across six trees and routed us four spellings.
  **Censusing instead by the row's INPUT** (*a handler is registered at this path and does not
  implement the named operation*) **found four more at this seat, every one outside status
  501**: two at `404 unknown_operation`, one at `400` with **no `code` field at all**, and one
  at `400 invalid_request`.
  **The last is the shape to remember, because it is invisible twice over.**
  `invalid_request` is the *correct* default for status 400, so the pair reads conformant at
  every glance short of asking what the input was. It carried a written argument for the 400 —
  `reflect` is the unwrapped listener's verb, so answering "not implemented" would imply a
  surface where it could be — which is an *intent* distinction, and §3.3's rows are defined by
  **inputs**. §6.2 says so outright and arch had ruled the identical distinction out at
  keystone's `pd` in the same packet. **And `storage.py`'s was the handler registered at `*`**,
  i.e. the most reachable refusal in the peer, answering with no code.
  **A slot census is a grep with better manners: it still starts from what you emit.** The
  spec's *input* is the only starting point that reaches a site whose status is wrong, and
  those are exactly the sites no cross-impl probe keyed on status can report.
  **Two corollaries earned building the gate, both from mutations that behaved unexpectedly:**
  1. **A gate whose search key is part of what the defect removes reports clean.** Reverting
     `storage.py` left the structural fallthrough row **green** — that row locates sites by a
     message convention, and the mutation deleted the message along with the fix, so the site
     dropped out of the population rather than failing. A count with any slack cannot fire for
     the same reason. Remedies: enumerate from the **registration list** (`handlers.
     list_handlers()`) — the one inventory a defect cannot edit, since a handler that stops
     answering the row is still registered — and make the marker guard a **ledger of modules**,
     not a floor.
  2. **A handler with no fallthrough is not a handler with nothing to audit.** `system.py`
     had *one* 404 serving both *"I do not implement that operation"* and *"that path holds no
     entity"*, so it was absent from every census in the file until the arm was split out. The
     ledger is what reported it joining.
  Enforcement point: `tests/integration/test_status_code_slot_3_3.py` — three complementary
  rows, each stating its own blind spot, plus the 404 row's reachability finding and the 500
  row's *deliberately assert-they-are-still-here* ratchet (arch **held** the ~16 specific 500
  spellings under §3a; a later reader of the 501 sweep must not infer the 500 slot was missed).
  Six mutations, six correct predictions after the two corrections above.

- **A ROW can have more than one INPUT, and censusing one of them is what makes the row read as
  done.** ***RATIFIED 2026-09-10*** *— second instance of AP-21's own refinement (*a code SLOT is
  the unit for auditing a CODE; the row's INPUT is the unit for auditing a ROW*), in the shape
  that law could not warn about: the unit was right and there were **two** of it.*
  §3.3's 400 row is a **pair**: *an operation that requires a resource answers ABSENT with
  `path_required` and MORE THAN ONE with `ambiguous_resource`.* This repo censused that row
  **twice** — 0.8.2.18 (four sites) and 0.8.2.17 before it — each time by the row's input, each
  time correctly, and **both times only the absent half**. Measured on the third pass:
  **thirteen** operations (all seven `system/role`, `system/quorum:create`,
  `system/attestation:create`, `system/content:{get,ingest}`) refused the absent case and refused
  more-than-one **nowhere** — they read the value through `_common.resource_target`, which
  returns `targets[0]`, so a three-target request was served as if it named one.
  **Why two input-censuses in a row missed it, and this is the entry.** The absent arm is the one
  the *sentence* leads with and the one an implementer hits, so a census that finds and fixes
  real defects on it **feels complete and produces a green suite** — the forcing function fires,
  the work lands, and nothing is left pointing at the second half. The missed arm is then
  invisible three ways at once: a **token grep** cannot see it (`role.py`, `quorum.py`,
  `attestation.py` held **zero** occurrences of `ambiguous_resource`, so they read as unrelated
  to the code entirely); the **absent-arm rows** cannot see it (every one passes on a peer with
  the defect, because they send zero targets); and **no probe sends two** — nobody supplies two
  resource targets by accident, so it is unreachable by fuzzing, by a conformance client, and by
  ordinary use. It is reachable only by asking.
  **The check, and it is one sentence of re-reading:** when a spec row names a code, **count the
  inputs in the row's own sentence** before censusing, and parametrize the class over all of
  them. A row joined by *"and"* is two rows; a row saying *"the two are different inputs with
  different remedies"* is telling you the count outright. Then assert the arms are **different**
  — a class that checks each code separately still passes a peer answering one code to both,
  which is the collapse the row exists to forbid.
  **And the fix goes where the value is READ, not where the check is written.** Nine of the
  thirteen had inlined the absent check at the call site and delegated the value to a lenient
  shared getter — so the class had re-opened nine times independently, each time by an author who
  wrote a correct-looking guard. Enforcement point:
  `_common.require_single_resource_target` (both arms, one site) plus
  `test_path_required_is_raised_by_the_handler.py::TestTheClassClosesAtOneSite`, which asserts no
  resource-requiring handler reads through the lenient getter — because the behavioural rows only
  cover the operations already in the census set, never the next one somebody adds.
  *The gate corrected its author on its first run again (fifth instance): the new arm was written
  for role/quorum/attestation and immediately reddened `system/content:{get,ingest}`, which
  answered `missing_input` — falling through to a params check with two targets in hand.*

- **A sweep justified by "nothing defines a better code" is a NEGATIVE claim about the corpus,
  and your own tests will agree with you because you moved them.** ***RATIFIED 2026-09-03***
  *— SA-PY-37, and it is AP-21's own shape arriving inside AP-21's own remedy.* §9.1 (0.8.2.7)
  lists five *"non-conformant spellings"* of the 501 row. **`EXTENSION-REGISTRY` §6a.9.2 pins
  one of them, `unsupported_mode`, twice, both `[MUST]`** — and the second pins it *"because
  this is a cross-impl-observable answer with four plausible codes."* We swept both registry
  sites from the list; 0.8.2.7's own escape clause (*defined … in the owning domain handler's
  own table*) says §6a.9.2 wins.
  **Why the list is persuasive and wrong:** it enumerates spellings seats were **emitting** and
  reads as an enumeration of spellings the corpus leaves **undefined**. AP-21 is *a count of
  the token is not a census of the slot*; this is *a census of emissions is not a census of
  definitions*. Both are positive-sounding sentences whose truth condition is a negative, so
  `AGENTS-STANDARD`'s **prove a negative** rule never fires — the sentence reads as measured,
  and it cites five real spellings.
  **The unit suite could not catch it and the reason is the standing one.** We moved the
  assertions with the code — *our constant against our constant*, the exact configuration that
  hid `entity-core/7.0` and `bad_request`. **3854 green, and only a peer that does not share
  our constant could see it**: `entity-core-go`'s `registry_issuer.set_issuer_policy_domain_
  control_rejected`. **So: run the validator on a code sweep even when the unit suite is
  green** — a sweep is precisely the change whose tests move with it.
  **The checks, in the order they are cheap:** before retiring a spelling on a corpus-wide
  list, **grep the owning extension for it** — one command, and it reframes the task. And when
  a ruling hands you a list of forbidden values, treat the list as *evidence about
  implementations* and the ruling's escape clause as *the rule*; implement the rule.
  Enforcement point: the gate's `DEFINED_ELSEWHERE`, whose entries each **name the section that
  pins them** so a later seat cannot widen it by assertion, plus a row asserting each exemption
  is still emitted — an exemption that stops matching anything is cover for nothing while
  reading as a live carve-out.
  *Our own separate defect in the same pass, recorded because it is the funnier half: the 501
  site emitted `domain_control_unsupported` — a **fifth** spelling for the answer §6a.9.2
  pinned specifically because it had four plausible ones.*

- **When the spec assigns a row to SOURCE AUDIT, nothing will ever fail on it — so the census is
  the only detector, and it has to be scheduled rather than triggered.** *Candidate, 2026-09-04 —
  `remote_empty`, which shipped wrong from the day `pull` was written and was found by
  `entity-core-go` censusing 500 spellings, not by any probe.* §3.3's satisfaction mode (0.8.2.8)
  says the 500 row is **not drivable by a conformance client**: *"a conformant peer cannot be made
  to fail internally on demand over the wire, so this row is satisfied by a source audit of the
  implementation's emit sites at a named commit."* That is correct, and it has a consequence the
  paragraph does not state: **a status class excluded from wire testing is a status class in which
  a wrong answer is structurally undetectable.**
  **And the shape that made this one worse than a mis-spelled code.** The defect was not a wrong
  *code* at a real failure — it was a `500` on something that **is not a failure at all**. A
  remote with no versions is a normal outcome, so the wrong status was reachable by ordinary use
  and *still* invisible: no probe drives it (500 is exempt), no local test drove it (~90 revision
  tests and every one used a remote that had committed), and the emit site reads perfectly
  sensible in isolation. The census caught it because a census enumerates **emit sites** rather
  than failures, and an emit site on a success path is exactly what a failure-driven method
  cannot reach.
  **The check, and it is a calendar item rather than a rule:** for every row the corpus hands to
  source audit, put the census on the same schedule as the validator run — and census by **emit
  site**, then ask of each *"is the condition that reaches this line actually a failure?"*. That
  second question is the one that finds this class; *"is this code defined?"* would have passed
  `remote_empty` right up until the moment REVISION defined it as a 200.
  Enforcement point: `tests/integration/test_undeclared_500_code_census.py` (the standing census,
  monotone in both directions) plus
  `test_revision_extension.py::test_pull_from_an_empty_remote_is_200_remote_empty` and its
  unreachable-remote teeth control, because the substantive half of the ruling is that `502
  remote_fetch_failed` still means something different.

- **A fold answers some questions by OMISSION, and an omission from a table nobody had before is
  a ruling that arrives with nothing to prompt it.** *Candidate, 2026-09-04 — filed as SA-PY-40,
  found walking `EXTENSION-TYPE` v1.3 Appendix A after the fold rather than only the rows a
  sibling's gate drives.* This is the *"a ruling you already satisfy produces no diff"* law's
  sibling and it is worse in one specific way: there the normal forcing function (a behaviour
  change) is absent; here **there is no notification at all**, because the ruling is a row that
  is not present.
  **The mechanism.** A code minted where its extension had no error table is merely *undeclared*.
  The moment a table lands, §3.3's *"an undefined spelling is non-conformant"* binds it — so **a
  table landing retroactively converts every undeclared code in that handler's surface into a
  defect**, without touching a line of anyone's code. Measured: `entity-core-go` implemented three
  of the fold's four type-surface rulings in one clean cycle and reported the seat conformant and
  gate-green; the fourth (`decode_error` ×8 / `encode_error` ×3 / `invalid_entity` /
  `invalid_strategy` → the Appendix A defaults, which the proposal's §6a.4 had *already* routed as
  *"go aligns; nothing new is minted"*) had no row to implement **against**, so nothing surfaced
  it. Their own type gate drives neither a decode failure nor a bad strategy, which is the
  under-scoped-gate law they ratified in the same session, applied to the gate they wrote.
  **And the mirror was here**, disclosed in the same filing rather than after: py emits `400
  invalid_strategy` at two sites (`revision:merge`, `tree:merge`) whose owning tables define no
  such row — the code is real, it is just defined for a *different operation*. **"Defined in the
  corpus" is not the test; "defined for the operation" is**, and a grep that answers the first
  question reads like it answered the second.
  **The check:** when a table lands for a surface you implement — *especially* one you helped
  argue for — census that surface's whole code slot against the new table in the same session, in
  both directions. And do not route the sibling's half without walking your own first: the
  finding is the class, and the class is never one-sided.

- **A cross-impl probe that reads one field of a result says nothing about the others — and
  two implementations agreeing is not a majority verdict.** *Candidate, 2026-08-17 — found
  by building the `entity_sdk.revision` wrapper against §4.5.* `checkout` must answer
  `{status, target_version, head, branch?}`: `target_version` is what the caller asked for,
  `head` is where the prefix actually ended up, and under `auto_version: true` **they
  differ**, because applying the bindings mints versions and the head becomes a new
  descendant (§4.4.12). This peer answered a single `version` field. So did
  `entity-core-go`. Only `entity-core-rust` carried the spec pair — with `version` kept as
  a documented compat alias beside it. Two impls agreeing looked like the shape being
  right; it was two impls with the same gap.
  **Why every gate stayed green:** go's `validate-peer` checkout probe decodes the result
  and asserts `Status == "checked_out"`, full stop. A cross-impl run is only evidence about
  the fields it reads, and "cross-impl green" gets remembered as "the result shape is
  agreed". No local test asserted the shape either — 87 revision tests, none on this
  result.
  **The check:** when you wrap a handler, decode its result against the spec's result type
  **field by field**, and treat any field no test names as unverified regardless of how
  many peers pass. Where the spec gives two fields for what looks like one value, find the
  case that separates them and test *that* — here `auto_version: true`, which is the only
  configuration in which the old shape was observably lying. Enforcement:
  `tests/integration/test_sdk_revision.py::TestCheckout::test_under_auto_version_the_head_is_not_the_target`.
  Owed to core-go: the same field, and their probe cannot see it.
  ***RATIFIED 2026-09-01 — second instance, and the unit is a normative TABLE rather than a
  result's fields, which is what makes it worse.*** core-go's G-28 probe family measured us on
  §4.7 and reported two rows FAIL. Both reports were right. **Fixing them meant reading the
  table against the function, and four more rows were also wrong** — none of them probed:
  row 6's *mismatch* arm (FM-1 had fixed the same row's *pre-hello* arm three frames up and
  stopped), row 8's *second* named input, §4.6 step 2's *absent*-signature arm, and row 10,
  whose code we emitted for neither of its two inputs.
  **Why a table is the dangerous unit.** A result's fields are at least visible together in one
  decode. A §4.7 row is a `(failure, code, status)` triple whose *inputs* are scattered across a
  handler, and the probe family is named for the **table** — `connect_authenticate_*` reads as
  coverage of the connect-error contract. Three of ten rows were driven. **The report's scope is
  the probes it seeds; the reader's impression is the section it cites**, and nobody writes down
  the difference.
  **The check, and it is the cheap half of a relayed fix:** when a sibling reports N rows of a
  spec table failing, open the table and walk **every** row against your own code before fixing
  the N. It is the same read either way — you are already in the function — and the rows nobody
  drove are where a peer stays non-conformant *after* the cross-impl run goes green. Then say
  which rows they cannot reach, so their next probe family is not written to the same scope.
  Enforcement point: `tests/integration/test_connect_error_table_4_7.py`, which drives all four
  unprobed rows plus the two probed ones, each as a `(status, code)` pair, and carries
  `TestTheRowsDoNotCollapse` for §4.7's actual MUST (which is about the table, not any row).
  **Third instance, 2026-09-02, and the two new parts are *where* the unprobed arm lives and
  *why* a second walk of a row you already walked is not redundant.** core-go routed one row
  (`connect_ping_before_hello`: a pre-handshake `ping` answered `400 invalid_request` where
  0.8.2.4 pins `409 connection_sequence_error`). Walking row 10 *again* — the same row this
  entry's second instance had just walked — found the **mirror** defect: an unknown operation on
  an **established** connection answered `409 connection_already_established`. One predicate
  (*does the responder implement this operation*), two wire boundaries, classified by two
  hand-rolled comparisons that disagreed in opposite directions. The two-representations law with
  the **classifier** as the subject, and the fix is a set both call sites read
  (`IMPLEMENTED_CONNECT_OPERATIONS`) plus a structural row that fails a seat which re-rolls one.
  1. **A probe family's blind spot has a shape, and it is the seat the prober sits in.** A
     conformance probe dials in, so *every* state it can reach cheaply is a pre-handshake state;
     reaching the established side means completing a handshake first, which a probe author
     writes as **setup**, not as a state under test. So *"in any state"* clauses are
     systematically driven in one state, in every seat, and the arm nobody probes is not random —
     it is the far side of the setup. rust and go both happen to hold this arm correctly (checked
     first-hand, `connection.rs` `_ =>` and `execute.go`'s switch); **we were the only seat wrong,
     and no cross-impl run in the cohort could have said so.**
  2. **Walking a row once does not retire it — the *second* report on the same row is the cue to
     re-walk, not to patch.** The instance above walked row 10 and fixed both of its named inputs;
     this defect was live the whole time, in the same row, one state over. What changed was that
     0.8.2.4 re-cut the row on a *predicate* rather than on a list of inputs, and a predicate is
     what makes the unnamed cases enumerable. **When a ruling replaces a row's examples with a
     rule, re-derive every input from the rule** — the examples are what your last walk covered.
  Enforcement point: `TestTheSplitIsClassifiedByWhatWeImplement` in the same file — the routed
  row, its mid-handshake sibling, the established-state arm, row 9 as teeth (undriven on the wire
  until now), a control asserting we *serve* `ping` (the 409 is only conformant for a peer that
  does — go's probe carries that caveat in prose and nothing asserted it), and the structural row
  pinning both boundaries to one set. Four mutations, four correct predictions.
  **Fourth instance, 2026-09-06, and the unit shrinks again: the sibling reported ONE row, and a
  row is a PREDICATE while a probe is one member of it.** `entity-core-go` drove
  `EXTENSION-TREE` Appendix A's three `put` rows and reported py `3/4` — row 1 (*"the submitted
  entity does not decode"*) answered `500 internal_error`. Correct, reproducible, and their vector
  is `entity = 42`. Walking the **predicate** instead found **five** shapes reaching
  `Entity.from_dict`/`validate_entity_hash` intact, each answering a non-conformant pair.
  **The instructive one answered `200`.** A `type` of `42` is not a decode *failure* in Python at
  all — `cbor2` returns a native mapping, `compute_ecf_hash` encodes the integer, and the entity is
  **stored and bound under a type no typed peer can decode**. So the class had a member that was a
  success, and *nothing keyed on a status can reach it*: not go's relay (keyed on the 500), not our
  §3.3 slot census (keyed on the status), not a grep for a code (there is no code). Only driving
  the predicate's inputs finds it. **A defect class is bounded by its INPUTS; a success is a member
  of the class exactly as often as a wrong code is, and it is the member every status-keyed method
  is blind to.**
  **And the shape of the gap is language-shaped, which is why the cohort could not see it.** In go
  and rust *"does not decode"* is a language event — a typed decode — so the predicate is defined
  by their type system and never written down. Python has no such event, so this seat had to write
  the predicate as a function and found there was **nothing in the corpus to write it from**
  (filed, SA-PY-41). **When a spec row names a failure your siblings get for free from their type
  system, you are the only seat that has to state it — and the statement is a spec question, not
  an implementation detail.** The guard is deliberately the **intersection** of what go and rust
  refuse, so adopting it cannot make this seat the outlier on any shape; the two rows where the
  siblings disagree with *each other* are pinned at today's answer with the filing named in the
  assertion message rather than settled.
  Enforcement points: `tests/integration/test_tree_put_error_rows_appendix_a.py` (three mutations,
  three correct predictions) and `tests/interop/test_go_peer_tree_put_decode_predicate.py`, which
  **drives** the go column of SA-PY-41's table rather than reading it — 6/6 against a live peer at
  `69ec9e2`, including `EntityClient.put` itself raising a `400`, because *"our SDK cannot put to a
  go peer"* is a claim about a sibling and this repo does not route those on a source read. Same
  `ENTITY_GO_PEER=host:port` opt-in as the v324 probe, so the same **calendar** obligation applies:
  run it on every cohort catch-up and before replying to any routed tree item, and record the
  result with the go commit attached — never as a green suite.

- **The ORDER between two rows of one table is a rule no row states, and no per-row vector can
  reach it.** *Candidate, 2026-09-06 — found landing the row-1 fix above; reached independently by
  `entity-core-go` in their cycle 4, which is what makes it a shape rather than our bug.*
  `EXTENSION-TREE` Appendix A gives `put` two 400 rows: *does not decode* → `invalid_request`, and
  *the claimed hash is not its hash* → `hash_mismatch`. **An entity that is malformed AND carries a
  hash satisfies both descriptions**, so the table is individually satisfiable and jointly
  ambiguous. py validated the hash first and answered `hash_mismatch` for a submission whose defect
  was its shape — the caller told *"your hash is wrong"* when the fix is *"your entity is not an
  entity"*. go recorded the same thing about their own tree (*"`Validate` checks structure before
  hash — flipping wholesale to `hash_mismatch`, as the worklist prose read, would mis-code the
  structural case"*).
  **Why no vector catches it:** a vector is written per row, so it carries exactly the one fault its
  row names. go's row-1 vector (`42`) has no `content_hash` to disagree with, so a hash-first peer
  reaches the structural branch anyway and **passes**. The discriminating input is the one no
  row-scoped author writes, because it belongs to two rows at once.
  **The checks:** when a table gives one operation two rows over overlapping conditions, write the
  input that satisfies both and decide the order **explicitly** — then pin the order **structurally**,
  not behaviourally, because two correct-looking branches read fine in either sequence and a later
  seat hoisting one for tidiness reintroduces the defect at every overlapping input. And route the
  ordering: it is a missing sentence in the table, not a local choice
  (`TestTheOrderIsTheRow::test_the_source_orders_the_structural_check_before_the_hash`).

- **"Unruled" is a claim about the corpus, and three peers disagreeing is evidence about three
  peers.** *Candidate, 2026-09-02 — CE-1. Cost: a routing packet, a proposal, and three seats'
  design attention on a question the spec answered two releases earlier.* `entity-core-go`
  measured the pre-establishment non-connect EXECUTE on all three live peers, found
  `403 connection_required` · `400 handshake_failed` · `403 capability_denied` — no two alike,
  none in any spec code set — and routed it by the divergence rule as *all-three-differ ⇒ spec
  ambiguity, tighten the spec*. Arch's first read agreed and argued a **401** lean on semantics.
  **§4.2's third pre-authorization bullet had ruled it at 0.8.1**, where F32 replaced that
  bullet's blanket 403 with the auth/authz discriminator, and §5.2a's table gives the code.
  **The mechanism, and it is why nobody was careless.** Every seat was reading **§4.7**, which
  declares itself the MUST-emit contract for that surface and had no row for this input. §4.2
  states the rule in the vocabulary of *pre-authorization*; the implementer is holding the
  vocabulary of *connection state*. **A rule stated in a vocabulary you are not searching in is
  indistinguishable from an absent rule** — and the missing cross-reference is exactly the
  SA-PY-32 defect (§4.5's `protocols` row, whose literal lived in §8.4) recurring one section
  over, which is the standing shape, not a coincidence.
  **Why divergence-by-measurement is the dangerous evidence:** it is the most convincing
  possible demonstration that a question is open, and it is **not evidence about the text at
  all**. It measures what implementers found, and every implementer read the same wrong section.
  This is *"two readings that agree everywhere your fixtures live"* inverted: there a shared
  corpus manufactured false agreement, here a shared **blind spot** manufactured false
  disagreement, and both are sustained by the cohort rather than caught by it.
  **And the two branches cost wildly different amounts, in the wrong direction.** *Unruled*
  terminates in a proposal, a routing packet and a design conversation — the expensive branch,
  and the one that feels careful and collaborative. *Ruled* terminates in a one-line fix. So the
  cheap check has to run first: **before accepting "unruled", grep the normative sections for
  the INPUT, not for the code.** Restate the input in the other vocabulary — *"an EXECUTE with
  no verified signer"* as well as *"a frame before the handshake"* — and search both. Two greps.
  **Two corollaries earned in the same pass:**
  1. **When you file a corpus conflict, name the section that governs your surface, not the
     section your constant transcribes.** SA-PY-33 filed §9.2-vs-§4.7 because §9.2 was the enum
     our constant copied; the ruling put the defect in **§4.3**, which is the section governing
     the surface we actually serve, and left §9.2 untouched. Same remedy, different sentence —
     and only one of the two tells the next person which line to grep.
  2. **A test that describes itself by reference to another surface makes no independent
     claim.** The HTTP pre-connect row asserted the old `403` under the docstring *"mirrors the
     TCP path's pre-connect reject"* — and what it mirrored was the TCP path's bug. It sat on
     the one boundary **no cohort probe reaches** (they all dial TCP), so it was the only thing
     that could ever have caught the divergence, and it was pinning the defect. The seam-move
     rule says grep the old status; this adds that a row asserting the defect and a row
     asserting the contract are textually identical, and the tell is a docstring that names a
     sibling instead of a spec sentence.
  Enforcement point: `tests/integration/test_pre_establishment_execute_ce1.py` — the ruled pair
  at both boundaries, an AST ratchet on the two codes 0.8.2.5 names non-conformant, and
  `test_the_two_states_now_agree_on_the_same_frame`, which is the row that states the defect:
  this peer already answered `401 authentication_failed` for the identical frame one state
  later, so it had been disagreeing with **itself** the whole time. *A cross-impl divergence
  that is also an internal one was never a spec question.*
