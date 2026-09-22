# Filing spec ambiguities, and arguing a position into a ruling

**When to open this:** You are about to route a finding upstream, answer a cohort poll, or hold work pending a ruling.

What we send is somebody else's premise. These entries are the ways an outbound claim has been wrong here: a measurement that was real and diagnosed the wrong thing, a conclusion that was right for a wrong reason, a dichotomy that foreclosed the right answer, and a census that measured one seat and argued about the cohort.

**And the standing posture: a ruled-but-unfolded ruling is a thing to BUILD, not a thing to wait on.** Waiting contributes nothing to the fold and holds the cohort at two of three.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **A FILING is a claim about your own tree, and it is the claim in a filing nobody checks —
  because the filing is framed as not knowing the answer.** *Candidate, 2026-09-16 — caught
  pre-routing, cost nothing, which is why it is recorded.* SA-PY-66 was drafted asserting *"py
  implements the WIDER refusal (any depth)"* for §4.11 row (5a) vs ECF §6.3. Driven before
  routing: a **tag-55799-wrapped envelope** — the one tag real encoders emit by accident —
  decodes to a `CBORTag`, **which is not a dict**, so the non-map arm fired **first** and
  answered `400 invalid_request`. py was on the **narrow** reading, not by choice but by the
  order of two adjacent checks, with no line anywhere stating a position.
  **The shape:** an SA's *"what we do in the meantime"* paragraph is written from the code you
  just wrote, at the moment you are most certain of it, and it is the paragraph arch quotes back
  as this implementation's data point. Same family as the `test_resolution_integrity_k1` docstring that
  routed a false claim to two seats — with a **filing** rather than a docstring as the carrier,
  and the routing not yet sent.
  **The check:** every sentence in a filing whose subject is *py* is a row you owe before the
  packet goes out, especially the reassuring one. Enforcement point:
  `test_included_ingress_census_dr5.py::
  test_a_tag_55799_WRAPPING_the_envelope_is_the_tag_row_not_the_framing_row`, plus its `\xf6`
  control pinning that an ordinary non-map payload still takes the framing code — the row the
  ordering fix could have broken.

- **Trace the value before you route the reading — the divergence you can see is rarely the one you
  read.** ***RATIFIED 2026-08-21*** *— A1 applied to a **sibling's** code, and the third instance of
  the SA-PY-9 shape. The first two cost the reviewing seat an argument; this one would have cost them
  a fix in the wrong function.*
  Building v3.24 I read two departures in `entity-core-go`: `builtinConcat` answering `type_mismatch`
  for an error-valued sub-collection, and `builtinAssoc` resolving args positionally against §8.2's
  canonical-order `[MUST]`. Both readings were correct about the source. **Driven on the wire against
  a live go peer, they collapsed into one defect with three call sites and one unmeasurable claim:**
  `resolveCollection` (`ext/compute/builtins.go`) evaluates the `collection` arg with `Evaluate`
  where `evalOperand` is required, so a consumed operand that is an error-as-value gets a **shape**
  verdict instead of propagating — at `concat`, at `assoc`, **and** at `group-by`, the third of which
  neither reading predicted. And the ordering claim is **not separable on the wire at all**, because
  the collection defect answers first and masks it.
  **Three things to carry:**
  1. **A source reading gives you the site; only a trace gives you the extent.** Two of the three
     call sites came from running it, not from reading it. Had we filed the reading, go fixes
     `builtinConcat`, both other sites stay open, and the report reads as closed.
  2. **A blocked claim is `skip` with a written retirement condition, never `xfail`.** An `xfail`
     here flips to XPASS the day the *other* bug is fixed and gets read as this claim confirming —
     a false green manufactured by the harness. Same law as the deferral rule (a deferral without a
     retirement condition is an omission with better prose), with a *test* as the subject.
  3. **Point the probe at your own peer too, in the same run.** Six rows, three of which fail on go,
     **all six passing against py** is what makes the report a measurement rather than an assertion;
     without the py leg it is *"our reading of the spec disagrees with your code."*
  **What could not settle it, and this is the tell:** go's compute corpus cross-blesses **352/352
  byte-identical** go↔py. Neither configuration is in it — the *"two readings that agree everywhere
  your fixtures live"* law, arriving as a **corpus** that agrees everywhere. A locked cross-bless is
  evidence about the vectors it contains and nothing else, and it is the most convincing green there
  is. Enforcement point: `tests/interop/test_go_peer_compute_v324.py` — three divergence rows, three
  discriminating controls (including one that localizes the defect to a single helper by showing
  `index` handled correctly), and the skipped ordering row carrying its own un-skip condition.
  **It is opt-in via `ENTITY_GO_PEER=host:port` with no default, and that is a real weakness to state
  rather than a design flourish:** rows asserting a *sibling's* conformance must not put our gate on
  their release schedule, but the cost is a skip-on-absence check — the very thing the entry above
  says has never told you it passes. So the obligation moves from the suite to the calendar: **run it
  on every cohort catch-up against core-go and before replying to any routed compute item**, and
  record the result with the go commit attached, and route it, never as a green
  suite. The py-side half of each row *is* armed in the fast suite
  (`test_compute_v324_collection_primitives.py::TestV325FlowThrough`), so a regression on **our** side
  of the disagreement fails immediately; only the claim about theirs is on the calendar.

- **A one-word disposition column is where a two-reading word loses its second reading — open the
  ruling, not the packet that tabulates it.** *Candidate, 2026-08-21 — the "hearsay" law with the
  **ruling itself** as the subject, where the previous three instances had our code, our filing
  record, and our version.*
  Arch's C-8 (`172589e`) ruled `map`/`filter`/`fold`'s closure-result positions. `entity-core-go`
  relayed it as a three-row table with a disposition column: `map` *contain* · `filter`
  *short-circuit* · `fold` **propagate** — a faithful transcription of arch's own heading word. Arch's
  next sentence is what that word meant: *"`fold` binds it into the next closure invocation and never
  reads it, **so a closure that ignores its accumulator recovers**,"* and D2 puts *"`fold`'s final
  accumulator"* in the contained set of five. go implemented `propagate` as **abort**. Both readings
  are ordinary English for the word; only one survives the paragraph under it, and **the table is the
  artifact everyone downstream implements from.**
  **The compression happened three times and each step was individually reasonable**, which is why
  nothing looked wrong:
  1. *The ruling* used a word with two readings for the position it separately flagged as *"the
     widest blast radius if wrong — the only one where the alternative reading produces a different
     **value**, not merely a different cost."*
  2. *The report* rendered it as a table cell, dropping the sentence that disambiguated it.
  3. *The vector* was seeded at the **position** rather than at the **discriminator**: CV-8c is
     `fold(λacc x.E, 0, [1])`, one element with the closure *returning* the error — contain and
     short-circuit give the same answer, so it locks under either reading. Arch's own conformance
     table names CV-8**d** instead (*a closure that **ignores** its accumulator*), *"deliberately the
     shape where contain and short-circuit produce different values"* — and the report's vector set
     did not include it.
  **The proof is first-hand and it is the part to keep: the 358-vector corpus cross-blessed
  byte-identical go↔py at the same commits where the two peers answer differently on four measured
  rows.** Not "a corpus could miss this" — *this* corpus, LOCKED, on the day. The enclosing law
  (*two readings that agree everywhere your fixtures live are one reading*) is long ratified; what is
  new is that **the fixture set was authored by the seat that had just been told which shape
  discriminates**, and still landed the other one.
  **The three checks, in the order they are cheap:**
  1. **When a routed report tabulates a ruling, open the ruling and read the sentence each cell
     compresses.** One `git show` in the sibling's tree. The disposition column is exactly where a
     word like *propagate* / *pass through* / *flow* loses the half that decides behaviour.
  2. **When you seed a vector for a ruled position, write the configuration in which the two
     readings answer differently — and if you cannot, say the vector is a control.** A vector at the
     position is not a vector at the discriminator, and the corpus cannot tell you which one you
     seeded.
  3. **A carve-out added to fix an asymmetry goes at the join, not on one arm.** go closed the
     provenance asymmetry in `map` and then re-opened it three codes wide by putting
     `isEvalLimitCode` on the minted arm only — so a stored `compute/error{code:"budget_exhausted"}`
     is contained there and propagated here. Same defect, same function, same commit that fixed it.
  Enforcement points: `tests/integration/test_compute_v327_closure_result_positions.py`
  (`TestFoldContainsTheAccumulator` — the CV-8d row, plus the CV-8c shape kept and **labelled as the
  non-discriminator** so nobody reintroduces it as coverage) and
  `tests/interop/test_go_peer_compute_v324.py::TestC8ClosureResultPositions`, whose two agreeing
  controls are what make the two divergent rows attributable.
  *Second instance of the deferral rule's forward half, recorded because it is still rare:* the §8.2
  arg-order row carried a written retirement condition in its `skip` reason, go discharged it at
  `ded9ea0`, and the row was armed and measured the same session — `coll_error` vs `idx_error`,
  confirmed. An `xfail` would have flipped to XPASS at `ded9ea0` and read as the claim confirming,
  which it was not.

- **Winning the conclusion is not winning the argument, and the corpus records which one you
  sent.** *Candidate, 2026-08-19 — SA-PY-21 Q1.* We implemented chain-scoped, then routed the
  strongest argument we could find *against our own reading*: a broad row naming `did-web` with no
  such chain entry **arms silently** when an operator later adds the backend. Arch ruled
  kind-scoped — our conclusion — and **recorded our argument as explicitly not the justification**:
  the harm we described is closed under *either* reading, because the paragraph one line up binds
  the configuration **as a whole**, so adding that chain entry is itself a write the check
  evaluates. The ruling rests on monotonicity instead (a distribution cannot be held to a property
  that depends on what a downstream operator adds later).
  **The check when you argue a harm — including, especially, against yourself:** name the state in
  which the harm is reachable, then read the *rest of the section* for a rule that already refuses
  that state. A hole that another MUST already plugs is not evidence for anything, and it costs
  the reviewing seat a real argument to write the refutation. Being right about the answer makes
  this easier to miss, not harder: nobody re-reads the reasoning behind a conclusion that landed.

- **"They read the spec differently" is the flattering hypothesis, and it needs the same
  evidence as any other.** *2026-08-18 — arch's SA-PY-9 ruling correcting us.* We routed the
  in-process resource gap to core-go as *"three implementations have silently split on the
  reading"* and asked arch to resolve an ambiguity. **§5.2 had no such axis**: its condition
  is `resource_target is not null` — a test on the **field**, not on the door. There was
  nothing to split on, and core-go's code computes `childResource`, installs it on the child
  context, and hands the check a literal that omits it *thirty lines earlier* — a **dropped
  field**, a materially stronger finding than the one we sent. **Before attributing a
  divergence to a reading, name the sentence that carries the axis.** If you cannot quote it,
  the disagreement is a defect in someone's code — possibly ours — and framing it as
  interpretation is a courtesy that costs the other seat an accurate report.

- **"The spec conflicts with itself" is the flattering hypothesis for a regression you just
  caused, and a real measurement will support it all the way to the filing.** ***RATIFIED
  2026-09-09*** *— the "'they read the spec differently' is the flattering hypothesis" law with a
  **conflict between two documents** as the subject instead of a sibling's code, and the first
  instance where the wrong diagnosis was written up, implemented, tested, committed, and
  withdrawn in one session.*
  Landing 0.8.2.17's outbound check took `convergence.rexec_delivered` FAIL against a
  **4359-green** tree. Traced to: §1.4 gives two authority arms (ambient / target-minted) and
  `EXTENSION-CONTINUATION` §4.2 case 3 authorizes a cross-peer advance with a capability
  *"authored by this host peer"* — **neither arm**. Filed as SA-PY-45, a **fold blocker**: PD-2 as
  written refuses every cross-peer continuation advance in the cohort. Implemented a named,
  retirement-conditioned hold on Dimension 4. All of it good procedure, and **the diagnosis was
  our own defect wearing a spec conflict's clothes.**
  **What refuted it: reading the sibling's FIXTURE, not either document.** `rexec_setup` mints
  `CreateChainedCapGrantedTo(b.CapEntity(), …, a.RemotePeerIdentityHash())` — the credential is
  `B (target) -> installer -> us`. Its **leaf** granter is the installer; its **root** is the
  target. §1.4's *"the capability's `granter` resolves to the target peer's identity"* read as the
  **leaf's** granter — the reading a careful implementer reaches first, and the one we shipped —
  refuses it. Read as the **chain's root** it is ordinary presented authority, there is no third
  case, and the hold had nothing to cover.
  **Where the wrong premise came from, and this is the part to carry: our own code comment.**
  `continuation.py` says the dispatch capability is *"authored by this host peer"*, paraphrasing
  §4.2 case 3. That sentence is true of one field and false as a description of the chain, and it
  was the entire evidence for a filing about the **corpus**. **A comment that paraphrases a spec
  is not evidence about the spec, and it is the last thing anyone re-reads** — it sits in the file
  you are already editing, in your own repo, written by someone who had read the section.
  **Why this branch is expensive in the same asymmetric way CE-1's was.** *"Two documents
  conflict"* terminates in a filing, a hold, a fold blocker and three seats' attention. *"We
  misread a sentence"* terminates in deleting six lines. The cheap branch has to be checked
  first, and *"I have a real measurement"* is not evidence for the expensive one — the measurement
  was real in both worlds.
  **The two checks, in order:**
  1. **When you are about to claim two documents conflict, drive the configuration the second one
     actually produces** — from the fixture or the sibling's constructor, never from its prose and
     never from your own paraphrase of its prose. One `grep` in the harness that failed.
  2. **Before filing a conflict, re-read your own sentence for a word that admits two readings**
     and ask which one your code took. Here it was `granter`: leaf or root. A one-word ambiguity
     in a ruling is indistinguishable from a gap in the corpus until you name it.
  **What survives:** the *measurement* (PD-2 breaks cross-peer continuation under the leaf
  reading) and the *ask* — §1.4 should say **"the chain's root granter"**, because go and rust
  will each reach this fork independently and the leaf reading is the one the sentence suggests.
  That is now SA-PY-42(c), a one-clause request rather than a fold blocker. Enforcement point:
  `test_outbound_sub_dispatch_authorization_pd2.py::TestThePresentedArm::
  test_a_capability_the_target_ROOTED_but_delegated_IS_presented_authority`, which asserted the
  **opposite** for one commit and carries the measured numbers (`1637 -> 1617`, convergence 30/30
  under the control) in its docstring.
  **And a corollary about holds, since one was built and removed here:** a hold is the right
  move when a ruling and a shipped behaviour genuinely collide, and it must be *named,
  single-dimension, retirement-conditioned, and paired with a teeth row proving the other
  dimensions still bind* — without that row a hold is indistinguishable from a bypass. But
  **build the hold last**, after the cheap branch is excluded, because a hold is a change to an
  authorization path and it made this defect *harder* to see: it explained why the check still
  failed as "the hold does not cover this shape" rather than "the reading is wrong".

- **A DRAFT ruling is a thing to build, not a thing to wait on — the fold ratifies what the
  seats built.** ***RATIFIED 2026-09-04*** *— second instance, a different shape, a different
  seat, and the same source sentence, which is what makes it structural rather than a habit.*
  `entity-core-go` classified a whole board of items as *"prepare-then-land, gated on an arch
  spec-fold"*, traced the idea to `AGENTS-STANDARD`'s *"implement against the landed spec, not
  in-flight proposals"* — **the same line we cited when we held** — and had the operator strike
  it. Two seats, three days apart, reached the identical wrong posture from one sentence in the
  file that is injected into every repo. **A leak in the shared standard does not present as a
  shared mistake; it presents as two independent seats each being cautious**, and neither one
  can see the other's reasoning to notice the common cause.
  **The half that is still open here, and it is a real hazard rather than a footnote.** go fixed
  the sentence **in their working copy**. `AGENTS-STANDARD.md` opens with *"This file is
  identical in every entity-core repo… Do not edit it in your repo"* — so their copy and ours
  now differ, and **nothing anywhere checks that the identical-everywhere file is identical**.
  This repo's copy still reads *"implement against the landed spec, not in-flight proposals"*,
  which by that file's own precedence rule (*"this file wins on ecosystem conventions"*)
  outranks the entry you are reading. Our behaviour is right because this charter is what a
  session actually reads first; that is luck, not a mechanism. **Until the meta sync lands,
  treat this entry as the operative rule and expect the shared file to disagree with it** — and
  do not fix it here, because a second local edit to an injected file is how "identical" becomes
  unrecoverable rather than merely stale.
  *(Original entry, 2026-09-01 — the first instance:)* Arch ruled §4.7 row 10 in
  `PROPOSAL-CONNECT-SURFACE-RECONCILIATION` (FM-2), whose
  §7 reads *"No seat implements ahead of the fold."* We held on that sentence plus
  `AGENTS-STANDARD`'s *"implement against the landed spec, not in-flight proposals"*, and
  reported the resulting gate FAIL red. **go and rust had both already built it.** The cohort's
  actual working order is: **build the ruling, report what building it finds, let the fold
  ratify** — and the feedback from three seats building it is *the input the fold wants*. A seat
  that waits contributes nothing to the ruling and holds the cohort at two-of-three.
  **The distinction that survives, and it is the only one:** `AGENTS-STANDARD`'s rule is about
  *inventing* wire semantics — do not implement a proposal **nobody has ruled on**, and do not
  invent one yourself. It is not about a ruling arch has derived and written down. **Ruled-but-
  not-folded is not the same as unruled**, and treating them the same is what turned a one-line
  change into a routed disagreement.
  **What still justifies a hold** — narrowly: you find something *in the building* that
  contradicts the ruling. That is a finding, and it goes back with the evidence. *"The document
  says DRAFT"* is not a finding.
  **And it changes what the gate means.** A sibling's wire check on a ruled-but-unfolded
  semantic is not *"discriminating on an unruled semantic"* — the standing rule is about
  **unruled**, and we cited it at a row arch had ruled. The check was correct and our FAIL was
  ours.

- **A cohort poll is ruling input, so a wrong answer moves a specification rather than failing a
  build — measure it, and then check whether your answer is a POSITION or an accident.**
  *Candidate, 2026-09-09 — F60/N-4, and both halves were wrong on the first pass.*
  `entity-core-go` polled the three seats: when a handler **is** registered, its operation **is**
  in the manifest, and **no body is bound to run**, what `code` do you emit? go spells it
  `no_handler_body`; the spec defines none; the question is whether an impl may mint one at all.
  **Half one — I answered from a source read and it was wrong.** The tree-walk resolver returns
  `None` when it can bind no implementation, which falls through to handler resolution, so: `404
  handler_not_found`. Measured: **`501 unsupported_operation`.** (The site's own log line says
  *"returning 501"* and returns `None`, so the comment was closer to the wire answer than my
  reading of the code was, for the wrong reason.)
  **Half two, and this is the part worth carrying.** The `501` is **not a decision about the
  bodyless handler**. Resolution falls through to the wildcard `*` handler a default peer
  registers, and *that* handler answers `501 unsupported_operation` because `ping` is not an
  operation **it** implements. Driven on a peer built without the `*` fallback, the identical
  input answers `404`. **So the code is a property of the deployment's handler table, not of the
  request** — and reporting it as py's answer, into a three-way comparison of spellings, would
  have contributed a number with no opinion behind it and let the ruling read it as one.
  **Why the standing laws do not cover this.** *"Verify with pytest, not inline scripts"* is about
  facts in our own tree; *"a routed report's claims about our repo are hearsay"* is about claims
  someone else makes. This is the inverse: **a claim WE make about ourselves, into someone else's
  ruling**, where the normal forcing function is absent in both directions — nothing fails if the
  answer is wrong, and nothing fails if the answer is meaningless.
  **The two checks, in order:**
  1. **Answer a poll with an assertion, not a paragraph.** A row that pins the measured pair is
     reproducible, survives a later refactor changing it, and costs one test.
  2. **Then ask whether a peer configured differently answers differently.** If yes, you have a
     coincidence of your handler table and you must say so — that fact is *more* useful to the
     ruling than the code is, because it says the row cannot be a conformance row until the
     code is pinned. Here it also supplied an argument *from the spec*: `501` asserts *this peer
     does not implement that operation* while the manifest in the tree says it does, and §6.6
     makes the tree the resolution surface — so a caller who reads then dispatches gets two
     contradicting answers. That is go's conclusion, reached from a different defect, which is
     worth more to arch than a third spelling.
  Enforcement point: `tests/integration/test_registered_handler_with_no_body.py` — the measured
  pair, and `test_the_answer_comes_from_the_wildcard_fallback_not_from_a_decision`, which builds
  a peer without the `*` handler and asserts the answer **changes**.

- **A filing posed as "which of these two readings" asserts that they are alternatives — check
  whether they are at different LAYERS before you make arch choose.** *Candidate, 2026-09-06 —
  SA-PY-41 ask 2, and the one ask of four that did not go either way we posed it.* We asked: is
  `put` a **wire-receipt** path (§1.8: validate the carried hash, never recompute) or an
  **authoring** path (§4.5a: the submitter chooses the format)? Both, and the corpus already said
  where: the peer's `system/tree:put` is receipt, the SDK's `put(path, type, data) → hash` is
  authoring, and they compose exactly — an SDK **cannot return a hash it did not compute**. The
  §4.5a half of the dichotomy was never an authoring *arm* at all; it governs which format an
  author uses and **presupposes** an author.
  **Why an either/or framing is worse than a bad answer:** it narrows the ruling's search space to
  the two branches you named, and both of ours were peer-side, so the whole SDK layer was outside
  the question. Arch went and looked anyway. Had it not, the ruling would have picked one of two
  wrong shapes and every seat would have implemented it.
  **The two checks, both cheap.** (1) When you cite two sections as opposed, **name the subject of
  each sentence** — ours were *a receiver* and *an author*, which is not a disagreement. (2) When
  an ambiguity is about **who does X**, enumerate the layers that could, including the ones above
  the wire: an SDK contract is normative here (`SDK-OPERATIONS`) and is the layer a peer-side
  reading structurally cannot see. *A dichotomy is a claim, and it is the claim in a filing that
  nobody checks, because the filing is framed as not knowing the answer.*

- **A cohort-consistency argument is only as good as the census behind it — and the generated
  family is the one a ground-up seat forgets it is in a cohort with.** ***RATIFIED 2026-09-04***
  *— second instance, and the missing seat was a **ground-up** one, which retires the comforting
  reading that the first instance was about keystone being invisible.*
  `entity-core-go`'s item-D ledger routes two 500 tokens to arch as cohort-consistency
  arguments: **bless** `storage_error` (*"a consistent, deliberate 14× convention"* for a
  durable tree-bind failure) and **keep** `backend_error`. The census behind both polled go and
  rust. Running the identical census here **splits the two recommendations apart**:
  `backend_error` and `remote_empty` are corroborated — one site each, in the subsystems go
  names, reached independently — while `storage_error` is ×1 here, and the same failure is
  spelled `io_error` ×7 in `local_files`, *the exact subsystem go spells `storage_error` ×4*,
  plus `bind_failed` in `identity`. **The token is not a cohort convention; it is a go
  convention**, and go's own warning (*"do NOT converge 2 of 14 — that manufactures the
  divergence"*) is measuring the wrong scope: the cross-**seat** divergence already exists, and
  nothing reports it because no probe reads a 500 code.
  **The reusable half, and it is what makes this different from a duplicate of the first
  instance:** a census of *your own tree* answers *"is this consistent here"*, and a
  consistency argument is a claim that it is consistent **everywhere**. Those are different
  sentences and one grep separates them. So when you recommend a **bless** — the branch where
  the spec ratifies what implementations already do — the evidence has to come from the seats
  that would be ratified, and *"14 sites"* is a count of one seat however large it gets.
  **And say which branch the recommendation actually is.** Blessing `storage_error` is a
  **convergence instruction to this implementation**, not the ratification of a shared practice. That is a
  perfectly good outcome; it is just the opposite of what the word *bless* implies, and the
  routing packet is where the difference has to be visible.
  Enforcement point: `tests/integration/test_undeclared_500_code_census.py` — a ledger of every
  undefined 500 spelling with its count, monotone in both directions, plus
  `TestTheTreeBindFamilyIsTheFindingGoCouldNotMake`, which fails if the family collapses so the
  packet's premise cannot go stale silently. *The gate corrected its author on its first run
  again (fourth instance): the `grep -E` census in the routing draft reported 36 sites and the
  AST walk found **40** — `invalid_blob` ×2 is split across lines. **A regex census of code
  emissions is a count of the token**, which is AP-21's own subject arriving inside the remedy
  for AP-21, exactly as SA-PY-37 did.*

  *(First instance, 2026-09-02 — SA-PY-31 ruled against the arm we shipped:)* §4.5 left the absent/empty `protocols` arm
  undefined; we picked reading 1 (unconstrained), **matching `entity-core-go` byte for byte**,
  and filed rather than settling — on the stated ground that *"a responder that refuses where
  its sibling accepts partitions the cohort, and inventing that out of a gap is the error this
  repo exists to find."* That reasoning is sound and the ruling went the other way, because
  **the cohort is not the ground-up seats**: keystone's generated `csharp` and `typescript`
  peers already **required** the field, so reading 1 would have made 46 peers non-conformant.
  We polled two of three families and called it the cohort.
  **And reading the third family first-hand — rather than through the relay that named it —
  found the second half.** The ruling's L16 cites those peers as *"already require the field
  and pass conformance."* Measured in `entity-core-keystone` (`ConnectHandler.cs:70`,
  `connect-handler.ts:80`, both `Ecf.require` → `EntityProtocolException(status=400)`):
  - **absent** → the exception is caught at the dispatcher's handler boundary and answered
    **`400 handler_error`** — a refusal, but not the ruled pair, and `handler_error` is in no
    §3.3 code set (their `request_error` / `internal_error` are the same class — SA-PY-33's
    shape at the conformance anchor).
  - **empty list** → passes `require`, fails the membership test, and answers **`400
    incompatible_protocol`** — **reading 3**, which 0.8.2.4 explicitly forecloses (*"row 1 is
    reserved for a non-empty set"*).
  So the peers the ruling cites as its evidence **do not implement the ruling**, on the arm the
  ruling names in its own sentence (*"no `protocols` field, **or an empty list**"*). The
  citation is right about the direction and wrong about the pair. **A ruling's justification is
  a claim about a peer, and it stays a claim when the peer is a third party's** — the standing
  law with the subject moved one seat over. Routed; `connect_absent_protocols` will FAIL against
  a keystone peer, and the tempting read of that FAIL is *"the check is wrong"*, because
  keystone is the conformance anchor.
  **Why the generated family is the one that gets dropped:** it has no `AGENTS.md`, files no
  SAs, routes nothing, and is invisible to the `git log`/`grep` sweep we run across
  `entity-core-{go,rust}` — the whole habit of *"read the source, not memory"* is pointed at the
  trees that talk back. It is nonetheless conformance-passing peers on the wire, and 46 of them.
  **This is the standing *"the conjunction of two readings bounds the disagreement, not the
  error"* law with a census as the subject** — both seats can be wrong in the same direction, and
  a cohort-consistency argument inherits that shared error *and dresses it as evidence*.
  **The check, and it is one grep in a tree we do not usually open:** before arguing "changing
  this partitions the cohort," grep `entity-core-keystone` for the field. If a generated peer
  already implements the arm you are declining to implement, your partition argument is
  backwards — **you are the partition.**
  **What this does NOT retract:** filing rather than inventing was still right, and our
  *argument* is what carried the ruling (arch adopted the remedy-selection reasoning verbatim).
  The defect was in the fallback, not the filing. Enforcement point:
  `test_connect_protocols_intersection_4_5.py::TestTheAbsentArmIsARuling`, whose retirement
  condition fired **as written** and which flipped rather than being deleted — the second
  recorded instance of a deferral's forward half executing, and the reason nobody had to
  re-litigate whether the arm was ever going to move.
