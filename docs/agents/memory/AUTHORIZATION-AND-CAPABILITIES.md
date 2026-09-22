# Authorization, capabilities and scope matching

**When to open this:** Open this before touching `capability/`, a grant dimension, a scope matcher, or any handler's permission check.

V7 §5.2's four dimensions, §6.3's path check, scope canonicalization, resource targets, and the delegation paths. Most entries here are live security findings that a green suite did not see.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **A guard is scoped by its CALL GRAPH, not by where it sits — and a comment describing the
  call graph as a design decision is what stops anyone reading it.** *Candidate, 2026-09-14 —
  0.8.2.24 N2 at four sites.* `NEVER_MATCH` is a §5.4 **path**-canonicalization sentinel, and
  it sat in `matches_scope` — which **is** the path-scope matcher, correctly, since 0.8.2.16
  split `matches_id_scope` out *"so that which matcher a dimension uses is visible at the call
  site."* The guard was in the right place. **Four call sites handed it an id-scope value**:
  subscription's and substitute's `operations`, and both of query's `type_scope`. So an
  `operations` exclude of `*/apply` — an ordinary literal the id matcher would ignore, an
  escaping path to the canonicalizer — **denied every operation**.
  **The tell was a true sentence.** The comment over the guard read *"reached by every dimension
  of every grant, so this is the widest of the three arms."* False as a design statement and
  **true as a description of the call graph**, so it read as a considered scoping decision by
  someone who had thought about it. *A comment that is accidentally true is worse than one that
  is wrong, because nothing about it invites a check.*
  **And two of the four sites carried the citation that refutes them.** `query.py`'s own comment
  says *"type_scope is an id-scope"* directly above a path-matcher call, and `EXTENSION-QUERY`
  §5.2 names the arm outright — *"the same function that evaluates `id-scope` include/exclude
  patterns for operations and peers dimensions."* Not a reading; a citation four call sites did
  not follow. Landing it broke **nothing among 4314** — the SA-PY-54 signal — because nobody
  writes `*/apply` by accident, so the defect was reachable only by asking.
  **The check:** when a matcher is split by type, the enforcement is a census of **who calls
  which**, not the split itself. Enforcement point:
  `test_never_match_is_path_scope_only_n2.py::TestNoIdScopeDimensionReachesThePathMatcher` —
  **and its first mutation run corrected its author (sixth instance).** The census keys on the
  *argument's text* carrying an id-scope token, so it caught `matches_scope(grant.operations, …)`
  and was **blind** to a site that binds the value to a local named `scope` first. That is AP-21's
  own shape — a gate whose search key is part of what the defect removes — firing inside a gate
  written to apply AP-21. Remedy is a **module ledger** (a module whose every scope match is
  id-scope must not reference the path matcher *at all*), not a better regex.

- **Fix the class at the HANDLER, because a census keyed on "reads the field" cannot reach a
  site that ignores it.** *Candidate, 2026-09-14 — 0.8.2.24 N6, and my own test row caught the
  error.* N6 separates the two empties: an absent `resource` takes the operation's own
  absent-case behaviour, a `resource` **present** whose effective list is empty is `400
  path_required`. The distinction was already carried — the dispatcher sets `resource_targets`
  to `None` when absent and to a list when present — and every consumer wrote
  `if ctx.resource_targets:`, where `None` and `[]` are both falsy. *A truthiness test on an
  `Optional[list]` is the `min(binding.ttl, local_max)` shape: a construct with no arm for one
  of the cases is a ruling, not a null check.*
  **The placement is the finding.** I guarded the three tree operations that *read*
  `ctx.resource_targets` — `get`, `put`, `extract`. **Five of the eight do not read it at all**:
  `snapshot`, `diff`, `merge`, `create`, `destroy` take their path from `params`
  unconditionally. SA-PY-59's class on the most-dispatched handler in the peer — and the
  params-only operations are exactly where serving the absent-case behaviour is **widest**:
  `snapshot`'s default prefix is `""`, the whole tree, and `snapshot` is the row
  `EXTENSION-TREE` §8.4 **exempts** from the path-level check. Predicted 400, measured 200, and
  the prediction being wrong is the finding. The guard is now at the tree handler's **entry**:
  thirteen operations covered, and one added later inherits it without knowing it exists.
  **Second correction in the same pass, recorded because it read as a regression and was not:**
  the `put` teeth row sent `{type, data}` and got a 400. The **fixture** was wrong — 0.8.2.11
  §6.3 makes `put` a receipt path, so the submitter authors the hash (SA-PY-41). *"N6 broke
  put"* was this repo's own conformance working. **When a new guard reddens a row, check whether
  the row was ever conformant before blaming the guard.**

- **A convenience WRAPPER that fixes a spec argument is a policy decision with no call site to
  review it — and the corpus writing that argument as a LITERAL is the tell you are about to
  lose it.** ***RATIFIED 2026-09-13*** *— third construct of the "a default argument is a wire
  decision with no call site" law (after the `=` default and the status-named constructor), with
  an **authorization frame** as the constant and a method as the hiding place. `SA-PY-58`.*
  §6.3's `check_path_permission` filters the caller's grants by `handler_pattern` **before** their
  `resources` scope is read, so a grant scoped to another handler is discarded unread. **Four
  extensions write that argument as a literal at the call site and they do not write the same
  one** — `"system/tree"` at SUBSCRIPTION §2.3, HISTORY §4.2 and COMPUTE §7.2; `"system/query"` at
  QUERY §5.2 step 6b. `HandlerContext.check_caller_permission` supplied `self.handler_pattern` —
  *the handler currently dispatching* — and offered no override, so the argument was right only
  where the dispatching handler happened to be the one the corpus names.
  **The wrapper IS the mechanism, and that is the reusable half.** §7.2's Phase 2b, written as a
  direct `check_path_permission(...)` call, **kept its literal**. Every site that went through the
  wrapper lost one. So the discriminator is not care and not review — it is whether the call site
  had a slot to write the value into. **Grep for a wrapper that drops a parameter the spec varies;
  it converts a per-site decision into a global one silently, and a global one is what nobody
  re-reads.** Measured: a caller holding §2.3's own described shape (`{system/subscription:
  subscribe}` + `{system/tree: get}` — separately scoped, which is the only reading under which
  §2.3's argument *"a caller may legitimately hold `subscribe` without `get`"* has content) was
  refused; history refused the same; and compute, which omitted the argument rather than defaulting
  it, was **wider** than the corpus, because `None` disables filtering entirely.
  **Two things no local method could see.** `HandlerContext.handler_pattern` defaults to `None`,
  and every in-process fixture in this tree leaves it there — so **every existing row ran with the
  filter disabled**, the one configuration in which the wrong frame and the right frame agree. And
  the class written for this very rule three commits earlier (`SA-PY-56`) mints
  `handlers: {"include": ["*"]}` in every row, blind for a second, independent reason. *A fixture
  is a claim about what production supplies, and these two claimed nothing.*
  **And the frame runs UPSTREAM of every dimension, which is why it was mis-diagnosed rather than
  missed.** A peer with a perfect matcher and the wrong frame answers DENY with **no dimension to
  attribute it to** — so `entity-core-go`, reading py's 403/403 from outside, offered two candidate
  causes and both were dimension-level, because a 403 is all the wire shows. They routed it to arch
  as a §2.3 *pattern-subject* question. **It was this argument, and §2.3 already names it.**
  Enforcement point: `tests/integration/test_handler_frame_of_the_6_3_check.py` — the argument in
  isolation, all three behavioural sites at the spec-shaped cap with teeth, the compute widening,
  and **both non-discriminators kept and labelled** (the wildcard cap, the absent frame). Three
  mutations, three correct predictions, one row each.

- **A cell table measures a MATCHER; it does not measure whether the matcher is REACHED — and the
  handler that takes its path from `params` is reached by nothing.** *Candidate, 2026-09-13 —
  `SA-PY-59`, found auditing the cohort's nine narrow-cap arms against this tree.*
  `system/revision` has nineteen handler operations. This peer authorized **eight**;
  `entity-core-go` authorizes sixteen. The module reads `ctx.resource_targets` **zero times** —
  every prefix comes from `params.prefix` — and §5.2's resource arm is conditioned on
  `resource_target is not null`, so **a caller that simply omits the `resource` field reaches the
  handler with nothing having looked at a path.** `check_path_permission` on the params prefix is
  then the only authorization there is, and eleven operations did not call it. `diff` returns every
  changed **path and content hash** between two versions of any prefix: the same disclosure as the
  `snapshot` + `diff`-against-empty composition the whole `H1` sweep exists for, through a handler
  that sweep does not touch, and **without needing an exclude at all**.
  **Why every instrument in the cohort is blind to it.** keystone's scope-cell table enumerates
  `(layer, dimension, polarity, operand)` — the cells of a matcher. A peer can be **146/146 green**
  and never call the matcher. The nine narrow-cap arms all drive `system/tree`, `system/query` and
  `system/subscription`; **no check anywhere drives a revision operation under a cap that does not
  already cover the prefix**, which is go's own *"every category drives the broad connection cap"*
  headline, unextended to the handler where it bites hardest. And locally: ~90 revision tests, every
  one minting a permissive capability, so landing eight gates reddened **nothing among 4638**.
  **The check, and it is a grep not a doctrine:** for every handler, ask *where does the path come
  from* — `resource.targets[0]` or `params`. V7 already answers it for the tree handler and this
  repo already carries the invariant; what it does not say is that the answer must be **re-derived
  per handler**, and the ones that take it from params are exactly the ones §5.2 cannot cover. Then
  count the operations that authorize against the operations that exist: *eight of nineteen* is a
  number no one had because no one had asked for the ratio.
  **And the residual is a cohort finding, not a py one.** At 16/19 we match go exactly, and the
  three neither seat checks are **the same three** — `find-ancestor`, `config`, `merge-config`, two
  of them **writes** to a prefix's revision configuration, and `merge-config` decides which side
  wins a merge, hence the merged bytes, hence the version root. Neither seat has a sentence to point
  at: `EXTENSION-REVISION` never enumerates which operations are path-authorized. **Two ground-up
  seats converging is evidence about implementers**, so it is routed rather than closed — refusing
  where go accepts manufactures the divergence out of a gap. Enforcement point:
  `tests/integration/test_revision_unchecked_operations.py`, including a **structural** row pinning
  that the module still reads no resource field, and a class asserting the three residual ops at
  **today's** answer with the retirement condition in the message.

- **A predicate's subject SHAPE is chosen by the CALL SITE, so fixing a matcher at one site says
  nothing about the same matcher at another — and the prose is what stops you looking.**
  *Candidate, 2026-09-12 — `SA-PY-56`, the `G-4` pattern arm at the site all three seats skipped.*
  0.8.2.21 gave §5.2's `check_resource_scope` a pattern arm (`patterns_overlap` / `is_covered_by`)
  because a **pattern** target spanning a grant `exclude` was re-spellable past it. go landed it at
  `CheckResourceScope`; we landed it at `check_resource_scope`. **Neither seat landed it at
  `check_path_permission`**, and both had the same reason available in the text: §6.3 describes its
  subject as *"the path this handler is ABOUT TO TOUCH"*, which reads as concrete **by
  construction**, so the arm looks inapplicable rather than missing.
  **The corpus itself supplies the pattern.** `EXTENSION-SUBSCRIPTION` §2.3 requires, verbatim,
  `check_path_permission("get", resource_path, …)` when `include_payload` is set — and a
  subscription's resource **is a pattern** (§3.1). The exclude loop then evaluates
  `matches_pattern(concrete_exclude, pattern_string)`, an exact-string comparison no concrete path
  can satisfy. Measured: a grant reading *"everything under data except `data/secret`"* was
  **accepted** for a payload subscription on `data/*`, and delivery re-checks nothing — so the
  excluded entity's **body** is pushed on every write to it, for the life of the subscription. A
  push channel carrying bodies, which is strictly worse than the read leak above it.
  **This is the SA-PY-12 law (*a matcher gains a call site, the rejection rule gains it in the
  same commit*) inverted:** there a matcher moved and its validator did not follow; here the
  matcher never moved and a **caller with a different value shape** was added to it by a *different
  specification*. Nothing in §6.3 changed, nothing in §5.2's ruling names §6.3, and no grep for
  either identifier crosses the two documents.
  **The check:** when a rule is fixed at one matcher, `grep` every **call site** of that matcher
  and ask *what SHAPE of value does this one supply* — concrete or pattern, caller-authored or
  derived — rather than whether the site exists. A site that supplies a shape the fixed site never
  sees has not been fixed; it has been counted. And the fix itself needed no invention, which is
  the tell that it was owed: §5.2's arm with `caller_exclude = []` reduces to *overlap → DENY*.
  **And the cohort's vector cannot see it, for the standing reason.** go's
  `include_payload_unauthorized` mints a subscribe-only cap with **no** `system/tree` grant —
  the *neither* arm; the *both* arm is the other one everyone writes. The discriminator is where
  include and exclude **disagree**, and it belongs to both arms at once. That row is kept in our
  class and **labelled as the non-discriminator**, mutation-confirmed: removing the pattern arm
  leaves it green.

- **A predicate anchored at the START of a string stops holding the moment someone concatenates a
  prefix onto it — so the unit to validate is what the CALLER wrote, not what you built from it.**
  *Candidate, 2026-09-11, landing 0.8.2.21's `H3`.* `canonicalize` decides `NEVER_MATCH` on a
  leading `./` / `../` / `*/`. The first draft of the params-path guard validated the **joined**
  path (`full_prefix + entry`), which is the form that reaches the tree and therefore looks like
  the right unit — and `paths: ["../escape"]` still answered **200**, because concatenation had
  moved the reserved prefix into the interior where nothing looks for it.
  **Two things to carry.** The caller's entry is the unit because it is the thing the caller
  authored and the thing the rule is written about; the joined path is *derived*, and validating a
  derived value tests your derivation rather than their input. And **when a validator's predicate
  is positional, every caller that transforms the value before validating has silently opted out**
  — grep for concatenation on the path between a caller-supplied path and its validator.
  *Same pass, the mirror error: the guard also ran `validate_absolute_path` on the canonical form,
  whose peer_id-segment check is only the CALLER's claim when the caller wrote an absolute path.
  For a peer-relative path `canonicalize` prepends OUR id, so the check tested this peer's own
  identity and reddened 34 unrelated rows. **A validator applied to a value you supplied half of
  is not validating input.***

- **A safety property that rests on *nothing happens to match it* is not a property — and the
  ARGUMENT for it is what stops anyone re-checking.** ***RATIFIED 2026-09-11*** *— second shape of
  R-27 clause 4's law (*write down the strongest reason you know, not the one that convinced
  you*), with the reason not merely weak but **withdrawn by the ruling that arrived next**.*
  Before 0.8.2.20 our `canonicalize` passed a reserved (`./`, `../`) or ambiguous (`*/`) string
  through unchanged, and the docstring argued it: *a non-absolute string matches no canonical
  `/{peer_id}/...` target, so a malformed grant pattern is fail-closed by construction.* **That
  sentence is true of every input anyone named, and it is exactly what §5.4 now refuses to rest
  on** — `matches_pattern` returns True for a bare `"*"` operand, one recursion step through the
  `/*/` arm can produce one, and the ruling says in terms that *"safety MUST NOT rest on a value
  merely looking unmatchable."* The remedy is a **named sentinel** (`NEVER_MATCH`) whose refusal
  is a matcher rule stated FIRST, so the arm ordering is the property rather than the string
  shape. Behaviour barely moved; what moved is that the next person to add a matcher arm cannot
  silently delete the guarantee.
  **Why this shape is worse than a weak reason:** a weak reason is inert until a refactor. An
  argument of the form *nothing can reach this* is **load-bearing** and reads as a proof — it is
  the sentence that makes a reviewer stop, and it cannot be falsified by any test, because a
  test can only sample the inputs the author already thought of.
  **Two findings fell out of wiring it, and both were reachable only from a new call site.**
  §5.2's G6 rule (*consume `validate_absolute_path`'s verdict and fail closed*) put that
  predicate on an authorization path for the first time — and (1) a **peer-wildcard** grant
  (`/*/*`) strips the first segment whatever it is, so a target rooted at a non-peer segment was
  **covered**, which the sentinel alone does not close; (2) `is_peer_id` compared `!= 46` where
  §5.4 says `< 46` and calls 46 a **minimum**. The two forms agree on every peer this cohort has
  minted; they disagree on a longer algorithm, where the equality form misclassifies a foreign
  absolute path as peer-relative and `EntityTree.normalize_uri` re-roots it under **our own**
  namespace. **Putting an existing predicate on a new path is a census of that predicate** — the
  new call site is what tells you the old one was wrong, and a 48-character fixture peer id
  refusing was the whole signal. Enforcement point:
  `tests/integration/test_canonicalize_total_never_match_r11.py` — the arm-ordering row
  (`matches_pattern("*", NEVER_MATCH)`), the G6 row driven at the ONE configuration that
  separates it from the sentinel, its one-dimension-apart teeth control, and the minimum-not-
  equality rows. Four mutations, four correct predictions.
  *And `entity-core-go` diverges here: their `validConcreteTarget` checks the leading slash and
  the path characters and **not** the peer_id segment — the one clause that bites against a
  `/*/*` grant. Routed.*

- **Cohort AGREEMENT is evidence about the reading implementers reach, not about the text —
  and it is the most convincing green there is.** ***RATIFIED 2026-09-10*** *— the CE-1 law
  (*"unruled" is a claim about the corpus, and three peers disagreeing is evidence about three
  peers*) in **mirror image**, which is what ratifies it: there, measured **divergence** falsely
  said the corpus had a gap; here, measured **convergence** falsely said the code was right.
  Cost: a confused-deputy bypass live in all three ground-up peers, and in ours for the life of
  PD-2.*
  §1.4's 0.8.2.17 wording said a target-minted credential's *"own four dimensions authorize the
  sub-dispatch"* while exempting only the handler's `peers` scope **by name**. **All three
  ground-up implementations resolved that ambiguity as a bypass of the whole grant**, two of them
  with design prose defending it — ours is in this file's own history. Because the credential
  arrives as a caller-supplied parameter and capabilities travel in `included` maps, a caller
  holding a copy of any `target -> P` capability could steer **any** handler on P past its own
  grant. The caller cannot wield it itself, the leaf `grantee` being P: the confused deputy, with
  the ceiling §1.4 names removed by name.
  **What could not see it, and this is the whole entry.** A 1616-check cohort validator, a
  358-vector cross-bless, and three green suites — all agreeing, all agreeing *because* they
  agreed. `dispatch_outbound_reentry` (credential + covering grant → allow) and
  `dispatch_outbound_ambient_refused` (no credential → refuse) read as the two arms and **are the
  two vectors a bypassing peer passes**. It was found by `entity-core-keystone` auditing **its
  own ruling** — their standing rule being *the exculpation most likely to be wrong is the one we
  wrote, because nothing routes it back for review.*
  **The three checks, in the order they are cheap:**
  1. **When a rule COMPOSES two authorities, the discriminating vector is the one where they
     DISAGREE** — a valid credential presented to a handler whose grant does not cover the
     request. Neither arm's author writes it, because it belongs to both at once: the
     `EXTENSION-TREE` Appendix A row-ordering law with **authorities** as the subject rather than
     error rows. *"Both agree → allow"* and *"neither → refuse"* are the two vectors that cannot
     discriminate a compose from a bypass, and they are the two everyone writes.
  2. **Structure the fix so the wrong shape needs a new statement, not a flipped operator.** The
     credential path must produce a **bit**, never a verdict: `_presented_credential_relaxes_peers`
     returns `bool` and the gate reads it as `relax_peers`. Reintroducing F67 now requires *adding
     an early return*. A predicate named for what it authorizes is an invitation to return early
     from it — the rename was load-bearing, not cosmetic.
  3. **A negative security test can PASS for the wrong reason.** `403` is the expected outcome, so
     a row refused upstream of the gate is indistinguishable from one with teeth. Pair every
     refusal row with a **502 control differing in exactly one dimension**, and verify the row
     REACHES the gate by running the restore-the-bypass mutation. Measured here: the mutation
     reddens 5 rows and leaves **all 16 pre-existing rows green** — which is the entry restated as
     a number.
  **And the corollary that cost the second half of the session: removing a short-circuit
  ACTIVATES every latent defect it was hiding downstream.** ***Second instance*** of *"adding a
  check that should always have run is a behaviour change; budget for the second finding"*, with
  the arrow reversed. The continuation advance passed the B-rooted credential as **both** the gate
  and the presented credential — inert while the presented arm returned early, because the
  credential was then only ever read in the target's frame. Composing the gate made it fatal:
  §1.4 evaluates the handler's grant in the **local** frame, and a B-rooted credential's resource
  patterns are authored in B's namespace, so as a local grant they can never match a target naming
  B. `convergence.rexec_delivered` FAIL against a **4382-green** tree. **A duplicated argument that
  is provably harmless is harmless *because of* something — find out what, before you remove it.**
  **Two smaller things earned here, both about how the diagnosis was reached:**
  - **Adjacency in a concurrent log is not causation.** The `relax_peers=True` line and the `403`
    line sat 17 lines apart and named **different** dispatches — 16-way concurrent reentry. Pairing
    them yields a confident wrong diagnosis. Bisect (restore the bypass → PASS → the regression is
    yours and it is in this diff), then trace the value with an instrumented run; do not read a
    concurrent log as a sequence.
  - **A refusal that names the wrong dimension is the only artifact a cross-impl debugger has.**
    Ours said *"Dimension 4"* unconditionally while `check_handler_scope` covers 1, 2 **and** 4 —
    so it was wrong in exactly the case where a credential relaxed 4, i.e. the one case where 4
    cannot be the reason.
  Enforcement points: `tests/integration/test_outbound_sub_dispatch_authorization_pd2.py`
  (`TestTheConfusedDeputy` — the discriminator, its one-dimension-apart control, Dimensions 1 and
  3 separately, the no-grant row, and the cross-entry row that fails a fix which relaxes by
  widening the *search* instead of skipping one dimension inside `§5.2`'s single-entry loop) and
  `test_continuation_handler.py::TestTheCrossPeerAdvanceGatesOnTheHandlerGrant`, whose rows are
  **source** rows and say so — every continuation cross-peer test here drives a stub dispatcher,
  so no local run can see that seam. Four mutations on the gate, four correct predictions.

- **A rule can be CORRECT and UNREACHABLE, fail-closed by an absence — and the absence is what a
  later seat wires up as an improvement.** *Candidate, 2026-09-10, landing §1.4's multi-granter
  root rule (E3/F66).* 0.8.2.19: a K-of-N root satisfies the root-granter check *"only when the
  target peer's identity is the multi-granter itself; a root whose signer set merely includes the
  target does not."* We accepted the signer-set form — not by oversight:
  `verify_capability_chain`'s M6 asks *"is the local peer among the root's signers"*, correct for
  its own job, and this gate calls it with the frame set to `target_peer`, so M6 answered *"is the
  **target** among the signers"* and a group credential relaxed Dimension 4 on one constituent's
  say-so. Fixed at the **gate**, not in M6 — tightening M6 refuses every legitimate *local*
  multi-sig root. **Two rules disagreeing on purpose, and the frame is what makes them disagree.**
  **Then the mutation reddened nothing.** Traced rather than patched (the standing law): the gate
  passes no `find_signature_by_signer`, so the chain walk refuses **every** multi-sig root one
  layer earlier — including one where the target genuinely IS the multi-granter. So the rule was
  right and inert.
  **What this adds to the mutation-reddens-nothing law, which had two remedies and now has a
  third.** It is neither *redundancy* (delete the arm) nor *your fixture is not discriminating*
  (both paths live) — the second path is **strictly broader** and refuses by **accident**, and the
  accident is an absent argument that reads as an oversight. Deleting the rule leaves a
  fail-closed property resting on nothing; keeping it silently is a rule nobody can test. **The
  remedy is a third artifact: a REACHABILITY row** that asserts the mechanism keeping the rule
  inert, so the day someone wires the finder in, the row goes red and points at the rule that has
  just become live — instead of the over-acceptance returning with nothing watching it. Enforcement
  point: `TestTheMultiGranterRootIsFailClosed::test_the_rule_is_unreachable_today_and_this_is_why`,
  beside a row driven at the configuration that isolates the rule (chain verification forced to
  succeed), which is the fixture the first draft got wrong.

- **A capability whose "operations" column is a bare tree-write is an unenforceable gate — and
  the missing operation shows up first as a check nobody can construct.** ***RATIFIED 2026-08-19,
  and the census it prescribes closed the whole table on 2026-08-20*** *— core-go ran step 2 over
  all seven §5 rows and found exactly the one row we had filed and no fourth, which is what turns a
  finding into a bounded class. Arch landed the invariant that keeps it closed:* **a new row is not
  landable without naming the operation the check runs at.**
  *Filed as a candidate 2026-08-19, implementing `EXTENSION-REGISTRY` §4.3.* We and core-go both routed *"read-at-resolution has no
  instrument"* as a **harness** gap. It was not: `system/capability/registry-configure` was
  declared as a bare tree-write against `system/registry/resolver-config`, so there was no
  operation for a client to drive, **no site for the write-time MUST to bind to**, and nowhere for
  an operator's override to live. A configuration surface with no defined write operation cannot
  be validated, cannot be rebound, and cannot be conformance-driven at all — three symptoms, one
  cause, and the ruling that fixed all three (§4.3's `set-resolver-config`/`get-resolver-config`)
  was invisible from any of them taken alone.
  **The checks:**
  1. **When a check cannot be constructed, ask which operation is missing before concluding the
     instrument is limited.** *"What would a conformance client call?"* is the question; *"the
     harness can't hold one process across a config rebind"* is the wrong answer to it.
  2. **Census the capability table.** A raw write cannot refuse selectively, cannot carry a
     qualifier, and cannot be told apart from any other write to the same entity — so a cap gating
     one is a name with no enforcement point. Running that census on the table arch had just
     edited found the **third instance in one table**: `registry-pin` still reads *"tree-edit
     `resolver-config.pinned_bindings`"*, and §4.3's new operation writes that field under a
     **different** capability. Filed as SA-PY-24 — a pin short-circuits §4.1 step 1, so the
     capability that got merged away is the one that outranks the control §4.3 exists to enforce.
  3. **A new operation is a new authorization surface: diff it against the capability table in the
     same commit**, field by field. The escalation here is not in the operation's own semantics —
     it is in which fields of a whole-entity write the gate was ever meant to cover.
  **SA-PY-24 ruled in our shape at v1.19 (§4.3's pin-delta `[MUST]`), and the deferral is the part
  that generalizes `[2026-08-20]`.** The filing pinned the gap as *behaviour* and **implemented no
  local fix** — inventing the delta check would have refused a client core-go accepted,
  manufacturing a cross-impl divergence out of a spec gap. That call held for exactly one day and
  the ruling arrived; the row that demonstrated the escalation (one peer, one config: a bare name
  is `chain_exhausted` and the pinned name resolves anyway) survived into the gate class unchanged,
  because it is *why the gate exists*, not *why the gate was missing*.
  **What the ruling did NOT settle is the sharper half: a ruled behaviour can still have an unruled
  encoding, and that alone can hold a conformance row off the wire.** §4.3 fixes *when* pin
  authority is required; §5 names `registry-pin` **descriptively** and fixes no way for a capability
  to *express* it. So each seat invents one (we and go both use an operation-axis discriminator,
  `pin-bindings`) — and `REG-DISPATCH-CONFIG-REFUSED-1` row 8 **cannot go on the wire**, because a
  shared harness minting one seat's encoding answers `403 not_entitled` to a **conformant** peer
  that checks another. That is a false red manufactured by the vector, the mirror of the
  deceptive-green trap, and it is the same law as *"a wire check must not discriminate on an unruled
  or divergent semantic"* with the **capability encoding** as the unruled thing.
  **And matching a sibling's encoding is not converging — say which it is.** We match core-go byte
  for byte here on purpose; that is two seats not making the vector worse while a ruling is pending,
  and recording it as convergence would manufacture exactly the *"cohort-consistent, not
  independent"* overclaim `AGENTS-STANDARD` forbids. Routed by go as spec-issue `2026-08-20-a`; we
  concur rather than filing a duplicate, and add nothing to the wire until it rules.
  ***RULED next day as R-27*** *(arch `08841d8`) — and the deferral is the half worth keeping.*
  **The forward half of a deferral rule actually executed**, which almost never gets recorded: the
  wire row was held for a **stated retirement condition** (*the discriminator is ruled AND every
  conformant impl agrees*), the condition was discharged, and go landed row 8 one cycle later
  (`2e8b9f8`) minting both caps in the ruled encoding. **A deferral without a retirement condition is
  just an omission with better prose** — this one had one, in writing, and it is why nobody had to
  re-litigate whether the row was ever coming.
  **Two corrections from the ruling, both about the reasoning and neither about the code.** Arch
  derives the operation axis from **V7** — a grant scopes on path-scope and id-scope only and the
  path axis is *explicitly non-portable*, so the operation name is the **sole portable
  discriminator**, true regardless of this entity's shape. Ours was narrower (*a resource split
  discriminates nothing **here***) and would not have generalized. And arch cites the three seats'
  independent agreement **last, labelled as corroboration** (L18), with the operative test written
  out: *if all three had chosen a resource path, would the argument change?* **That is the shape to
  copy when you are the one agreeing** — unanimous agreement on a wrong reason is the failure mode
  that looks most like validation.
  Enforcement point: `test_registry_name_privacy.py::TestSetResolverConfigPinDeltaRequiresPinCap` —
  eleven in-tree rows with teeth, including the **removal** row (§5 says *"add **or remove**"*, and a
  check written as *"does the submitted config carry pins"* passes every other row while letting the
  weaker grant delete the operator's pins) and the **unmodelled-key** row, which is the fail-open
  `entity-core-rust` found in `entity-core-go` (`f44ed4d`): a typed-struct decode drops a §4.2
  forward-compat key, so adding or stripping one reads as *"no change."* Python's native-mapping
  decode does not have it — **verified here rather than accepted from arch's summary of us**, which
  is the standing rule with our *code* as the subject instead of our filing record.

- **Python's unbounded `int` turns a decode failure into a silent comparison — and a
  parsed-but-unread field is not a checked one.** *Two security defects, 2026-08-17, both
  found by running core-go's validator rather than by any test of ours.*
  - *CAP-6a ingest.* A received capability whose `expires_at` / `not_before` /
    `created_at` is a bignum or negative must be refused (`GUIDE-CAPABILITIES` §6.2). In Go
    and Rust the CBOR decode into `u64` fails and the token never reaches the bounds check.
    `cbor2` hands back an arbitrary-precision `int`, so `2**64 + 1000 < now` is a
    well-formed comparison that answers **False** — the token is not rejected, not
    truncated, just found to expire after the heat death of the universe. Four of the six
    field×shape variants were honored; the other two were refused **by accident**, as
    ordinary expiry verdicts, which is exactly how a narrower probe reports this clean.
    **Where a peer language fails closed by decoding, we have to fail closed by checking.**
    Enforcement: `capability/temporal.py` — one predicate, seven call sites, plus
    `tests/integration/test_capability_ingest_temporal_cap6a.py` (which carries the probe's
    *teeth control*: the same construction with a normal expiry MUST be honored, or a
    refusal is attributable to the re-sign rather than the field).
  - *The §5.2 `peers` dimension.* `system/capability/token` has parsed `peers` since V6.0
    and **nothing ever read it**. Two halves were missing: the target peer comes from
    `extract_peer(execute.uri)`, not `local_peer_id`; and an absent `peers` defaults to
    `{include:[local]}` **and is still checked**. Since every grant in this repo omits the
    field, every capability we issued authorized dispatch into *any* peer's namespace — a
    foreign-namespace privilege escalation. The whole suite passed before and after the
    fix, because nothing in it ever dispatched at a foreign URI.
  - *And the fix for the second one was itself wrong once, in the same shape.* The first
    version derived `target_peer` **inside** `_resolve_for_dispatch`, which runs after
    `extract_handler_path` has stripped the peer segment — it read `system/tree`, answered
    "local", and authorized every foreign dispatch exactly as before. The new test passed,
    because it handed that inner function a full URI **production never gives it**: one
    parameter name (`path`) carrying two representations at two call sites. Only re-running
    core-go's probe caught it. **When you add a check, verify the value it reads is the
    value at *that* point in the pipeline, not the one the caller had** — and prefer a
    required keyword argument to a derivation, so the next call site has to state what it
    means instead of silently inheriting a pass. The test seam has to be the one production
    uses: an in-process dispatch at a foreign URI never reaches local authorization at all
    (`_is_remote_uri` routes it), so that test could not have measured the thing it named.
  - **The rule both teach:** *a field the type system parses is not a field the
    authorization path checks.* For every dimension a capability can carry, name the line
    that reads it — and if the answer is "the dataclass", that dimension is unenforced.
    Same shape as the validator-vs-consumer lesson above (§2.4 `exclude`), one layer down:
    there the field had a validator and no consumer; here it had a *parser* and no
    consumer.
