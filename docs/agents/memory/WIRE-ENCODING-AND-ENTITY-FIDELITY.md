# Wire encoding, entity fidelity and the constants we put on the wire

**When to open this:** Open this before touching ECF, hashing, the CBOR codec, framing, or any literal that reaches the wire.

ECF/CBOR determinism, §1.8 byte fidelity, the hash preimage, tag policy, and the class of bug where a value we chose reaches the wire with no call site to review it.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **A detector must name the class YOUR codec mints, and the public name is the wrong one.**
  *Candidate, 2026-09-16 — found by a discipline row, not by the wire rows.* `cbor2.CBORTag`
  **is** `_cbor2.CBORTag`, the C extension's class. `ecf_decode` deliberately goes through the
  **pure-Python** decoder (the C extension's tag dispatch cannot be intercepted), which mints
  `cbor2._types.CBORTag` — *a distinct class*. The first draft of `_CBOR_TAG_TYPES` read
  `(cbor2.CBORTag, _cext_types.CBORTag)`: **one class named twice**, blind on exactly the path
  it guards and correct-looking everywhere else.
  **What caught it is the entry.** Every wire row failed *identically to an unfixed peer*, so
  the behavioural evidence pointed at the check being absent rather than blind — and the
  diagnosis went to the wrong place. The row that separated them was the **two-derivations**
  row (byte-walker vs object-walker), written as a two-representations discipline and not
  expected to fail. *When a fix's rows fail exactly as the unfixed tree did, suspect the
  fix is present and blind before suspecting it is missing.*
  **The check:** when a guard tests `isinstance` against a library type, assert **structurally**
  that the class your own decoder returns is in the tuple — `type(decode(encode(x)))` — because
  no behavioural row can tell *"the detector is blind"* from *"the detector is absent"*.
  Enforcement point:
  `test_tag_policy_preadmission_5a.py::TestTheTwoDerivationsAgree::
  test_the_detector_names_the_class_OUR_DECODER_MINTS`. This is `_register_cext_type_adapters`'s
  own documented hazard, arriving from the decode side one function away from the comment
  describing it.

- **A STDLIB exception shared by two causes with opposite obligations is a ruling you did
  not make — and the discriminator is usually already on the object, unread.** *Candidate,
  2026-09-15 — fourth construct of the "a wire value with no call site to review it" law,
  after the `=` default, the status-named constructor and the `getattr` fallback.*
  `asyncio.readexactly` raises `IncompleteReadError` for **a peer hanging up cleanly between
  frames** and for **a frame whose declared payload never arrived**. §4.11 gives those
  opposite answers — silence is correct for the first (no frame was ever offered) and
  `400 invalid_request` is owed for the second. py caught the exception **one arm above** the
  refusal path and logged `reason=incomplete_read (peer hung up cleanly)` for both, so every
  truncated frame got a bare close.
  **What makes this construct worse than the other three.** You own a default argument and
  you own a constructor, so the fix is where the bug is. You do **not** own
  `IncompleteReadError`, so there is no place to attach the distinction and nothing to grep
  for — and the handler reads as correct, because *"the peer hung up"* is a true description
  of one of its two causes. The discriminator was already present and free: **`e.partial`** —
  empty means nothing was consumed at a frame boundary, non-empty means a frame was begun.
  One attribute, never read.
  **The check:** for every `except <StdlibError>` on a protocol boundary, enumerate the
  **causes** that raise it, not the situations you had in mind — and if two causes owe
  different answers, re-raise as your own type at the point where you still know which one
  it was. Doing it at the raise site is what makes the disposition a property of the frame
  rather than a guess at the catch site. Enforcement point: `FrameTruncatedError` /
  `PayloadTooLargeError` carrying `(status, code, stream_synchronized)`, plus
  `test_a_clean_EOF_AT_A_FRAME_BOUNDARY_is_still_silent` — the control a fix to the
  truncated arm breaks, which is how you learn you have started answering ordinary
  disconnects.

- **A matcher inside a hash-determining function is wire contract — and the obvious tool in
  your language is the trap.** *2026-08-18, implementing the SA-PY-8 ruling.*
  `EXTENSION-REVISION` §2.4 filters versioned bindings through `glob_match`, names it, and
  never defines it. The filter decides trie membership and **the trie root is the version's
  identity**, so the matcher is part of the hash. The fork is language-shaped: Go's
  `path.Match` `*` does **not** cross `/`; Python's `fnmatch` `*` **does**. Reaching for the
  obvious tool in each language yields two filters, two roots for identical content, and **no
  error at the call site** — two DAGs that will not converge and nothing that looks wrong.
  **The check:** when a helper feeds a value that gets hashed, its semantics are wire, not
  style — write it out and pin it, don't call a stdlib whose rules you did not read. Filed as
  SA-PY-11, because picking a sibling's implementation as the spec is what we are otherwise
  not allowed to do. Enforcement point: `tests/unit/test_revision_exclude_glob.py`, which
  keeps `fnmatch` as an explicit **control row** so the wrong tool fails loudly later.
  ***RULED 2026-08-18*** *(arch `ROUTING-2026-08-18-i` §1) — and the interim fix we shipped
  was wrong in three separate ways, which is the part that generalizes.*
  §2.4 is now **four closed forms** — `*` · `<literal>/*` (§5.4 subtree, crosses `/`) ·
  `*<literal>` (byte suffix) · `<literal>` exact — plus §4.4.17 **V6**, which *rejects*
  anything else at config write. Three corrections to carry:
  - **A correct finding does not make its proposed remedy correct.** The report was upheld and
    produced the ruling; the fix we proposed (doublestar) was retracted cohort-wide a packet
    later. We had measured against Go's `path.Match` as the reference — *which has no `**` at
    all*, so it was never a valid control. **State the finding and the remedy as separate
    claims, and check the remedy's control as hard as the finding's.**
  - **"Match the sibling exactly" is a defensible interim and an indefensible reference.** Our
    port faithfully inherited both `path.Match`'s segment scoping (wrong — form 2 crosses `/`)
    and a `**` the corpus never reserved. Copying an unruled matcher copies its unruled parts.
  - **Rejecting beats defining when the surface is hash-determining.** A spec that *omits* a
    token and one that *rejects* it are indistinguishable until a config carries one, and
    "each impl does something reasonable" is exactly how two stdlibs got in. Write-time
    rejection is the mechanism: an unrepresentable config cannot be stored, so no two
    conformant peers can hold patterns they read differently. **When you pin a grammar, ask
    what refuses the patterns outside it** — a matcher with no validator is half a pin.
  **And landing it found the second matcher, which is the older law with a new subject.**
  `auto_version.py` carried its own exclude matcher for §6.1's emission gate, where `/*` was
  *segment-scoped* — so `tmp/*` suppressed the version for `tmp/x` and not for `tmp/a/b`,
  while the trie filter kept both out. One peer disagreeing with itself, and the divergent
  half was the one no test drove past depth 1. **A concept with two implementations in one
  process is the two-representations bug; the second one is usually the "intentionally
  narrow" helper written before the rule existed.** Same pass: `_exclude_covers` accepted
  `system/revision/` as covering a subtree, which under form 4 excludes one path and nothing
  beneath it — V2 would have passed a config whose reentrancy exclusion does not exclude.
  **A validator built on the old matcher is wrong the moment the matcher is ruled; grep every
  caller, not just the one the ruling names.** Third instance, one surface over, filed as
  SA-PY-12: the merge-config path matcher was `fnmatch`, non-conformant under both candidate
  readings of §2.3.
  ***SA-PY-12 RULED 2026-08-18 in our favour*** *(arch `86d6b20`, REVISION 3.12)* — merge-config
  `pattern` **is** the four forms, decided by §5.1's own worked example (*"all `.lock` files use
  `source-wins`"* is form 3, the one form §5.4 cannot express). Two things to carry:
  - **A matcher moved to a new field without its validator is half a pin, and we shipped that
    for a day.** SA-PY-12's fix put merge-config on `_glob_match` while V6 still bound
    `exclude`/`exclude_types` only, so an unevaluable pattern was **storable** and then fell
    silently to form 4 — the accept-then-mismatch shape V6 exists to prevent, one field from
    where V6 was put. §4.4.18 **V7** closes it (`7e56047`). *When a matcher gains a call site,
    the rejection rule gains it in the same commit.*
  - **How arch made the scoping error, recorded because the method is one we use.** The "and
    nowhere else" clause was scoped by a **census of `*`-bearing patterns**, and
    `glob_match(config.data.pattern, …)` carries no `*` — so *the field that most needed
    scoping was structurally invisible to the measurement that set the scope.* **When a rule is
    scoped by an inventory, the inventory's unit must be the thing the rule binds.** That is the
    gate lesson in this file's fourth two-representations entry, arriving from the spec side.
  - **A filing can produce a larger finding than the one filed.** Verifying our report, core-go
    found `pattern_specificity` called by §5.1 and defined **nowhere** in the corpus — all three
    seats had invented one, ours byte-identical to go's, rust's counting the `*`. The surface
    decides which config wins, hence the merged bytes, hence the version root. Landed here as a
    four-key total order (`7e56047`). **Route the ambiguity even when you have a working local
    answer; the value is in what the other seats find while checking it.**

- **A default argument is a wire decision with no call site to review it.** ***RATIFIED
  2026-09-02*** *— the `entity-core/7.0` law (a constant we chose, on a wire surface, that no
  local test can see) in a third shape, with an **error code** as the constant and a **default
  parameter** as its hiding place. Found by walking §3.3's code SET after core-go walked the
  §4.7 row set.* `ExecuteResponse.bad_request(..., code: str = "bad_request")` and
  `ConnectError(..., code: str = "bad_request")`. **`bad_request` is in no spec code set** —
  §3.3's 400 row declares *"Default `code` = `invalid_request`"* (landed at the 0.8.2.2 PD-1
  fold) and 0.8.2.4 adds *"MUST NOT mint a synonym"*; the string appears in the corpus once, at
  §5.1's M3 rule, as the thing you must **not** surface. Twelve kernel sites inherited it.
  **The mechanism, and it is the whole entry.** The *same peer* emits the correct
  `invalid_params` from ~80 handler-tier sites and the synonym from 12 kernel sites — and the
  difference is not care, it is that the handler sites **state** their code and the kernel sites
  **inherit** one. A default is invisible to exactly the review that reads call sites: every
  call site is correct-looking, because the wrong value is not written at any of them. Same
  family as *"a binary operator with no arm for the absent case is a policy decision wearing a
  type guard"*, one construct over — there the ruling hid in an `if`, here in an `=`.
  **Three things made it survive a suite that names it.** (1) Six test files *mention*
  `bad_request`; **none asserted our emission of it** — our constant on both sides, the version
  string's exact configuration. (2) The §4.7 table file's own docstring states the default
  accurately, **one session earlier**, while fixing the rows a probe named: *a probe family
  names rows, and nobody was assigned the default.* (3) It is a **code**, not a status, so every
  refusal still refused — nothing observable was ever wrong for a caller who did not read the
  code, which is every caller in our own tests.
  **The checks, in the order they are cheap:**
  1. **Grep your defaults for wire values.** Any `= "…"` in a constructor signature that reaches
     `result.data.code`, a type name, a format byte, or a protocol string is a spec value with
     no reviewer. Pin it against the **spec's declared literal**, never against what you emit.
  2. **When a sibling's report makes you re-read a spec section, read the paragraphs around the
     rows, not just the rows.** The sentence that produced this finding sits directly under the
     §4.7 table and is about the *code set*, not about any row — so a reader who arrives via a
     row-numbered relay scrolls past it. The row-walk rule (*walk every row when N are reported*)
     has a set-walk sibling: **walk the enumeration the rows draw from.**
  Enforcement point: `tests/integration/test_generic_400_code_is_invalid_request.py` — the wire
  pair for a codeless refusal, a spread row that fails a peer which special-cases one raise,
  both constructor defaults pinned against §3.3's text, and an **AST ratchet at zero** on the
  literal. *The gate corrected its author on its first run* (the standing "a gate's first act
  should be able to correct its author" shape, fourth instance): it found `peer.py`'s
  `getattr(e, "code", "bad_request")` — a fallback on an exception that always carries a code,
  invisible to the read that fixed the constructor — and one site that is **not** ours to fix,
  `EXTENSION-SIGNALING` §9.2's closed enum, which pins `bad_request` for the same class core
  §4.7 forbids a synonym for. Filed as SA-PY-33 rather than changed: core-go carries the
  identical string at the matching site, so it is the corpus disagreeing with itself.
  **And one place the value must NOT become the right code:** `connect_refusal` reports what the
  **remote** said, so filling an absent code with the plausible generic would fabricate a claim
  about a peer that made none. It carries `""`. *A default is a decision; the correct decision
  is not always the correct value.*
  **Second construct, next day (2026-09-02, CE-1), and it generalizes the rule past `=`.** The
  pre-establishment refusal answered **`403 capability_denied`** where §4.2/§5.2a pin `401
  authentication_failed`, at both of its call sites, and neither site named a status or a code:
  both read `ExecuteResponse.forbidden(request_id, message)`, a **named constructor that
  hardcodes the whole pair**. So the general form is not *"grep your default arguments"* — it is
  **any construct that supplies a wire value the call site does not write**: a default argument,
  a status-named constructor, a `getattr` fallback. All three have now bitten in eight days, and
  all three are invisible to the same review, because reviewing call sites is how you find wrong
  values and none of these has a wrong value *at a call site*.
  **Two things this shape adds that the `=` shape could not.** (1) The wrong value was **a real
  code from a real table** — `capability_denied` is §5.2a's authz default — so nothing looked
  minted, which is the cover `bad_request` never had. A code is only right *relative to an
  input*, and a helper named for a status cannot know the input. (2) It carried the **status**
  too, and the status is what encodes §5.2a's auth/authz class, so the same construct that hid a
  code hid a *classification*. **When a helper is named for a status (`forbidden`,
  `not_found`, `conflict`), every caller has silently agreed with its class** — grep those
  helpers' call sites and ask, at each, which spec sentence assigns that class.
  Enforcement point: `test_pre_establishment_execute_ce1.py::TestBothBoundariesShareOneRefusal`
  — but note what it pins, because it is the opposite of the ratchet above: the fix is a
  **shared** refusal (`_pre_establishment_refusal`) reached from both boundaries, i.e. one more
  construct supplying a value no call site writes. That is deliberate and it is the trade: a
  value stated in one place is reviewable, a value stated in zero places is not. What makes the
  difference is that the helper is named for the **input** rather than for the status, and that
  the structural row asserts both gates reach it.

- **A field with no consumer *anywhere in the cohort* is not a converged field — it is an
  unmeasured one, and the first seat to implement it creates the divergence rather than
  finding it.** ***RATIFIED 2026-09-01*** *— the validator-vs-consumer law (§2.4 `exclude`, the
  `peers` dimension, the resolver ceiling) with the missing consumer in **all three trees at
  once**, which is the shape none of those instances could warn about. Cost: py could not dial a
  go peer, measured, and the tree was `4138 P` green on both sides of the break.*
  `entity-core-go` implemented V7 §4.7 row 1 (§4.5's `protocols` *"Intersection, must be
  non-empty"*) and relayed it as *"both siblings owe the `handleHello` intersection check."*
  True, complete as a description of the work, and **applying it verbatim would have partitioned
  the cohort**: this peer advertised **`entity-core/7.0`** while §8.4, go and rust all say
  **`entity-core/1.0`**. Measured against a live go peer at `7262f17`, before touching anything:
  `400 incompatible_protocol · initiator=[entity-core/7.0] responder=[entity-core/1.0]`.
  **The mechanism, and it is the reusable half.** Every previous instance of this law had a field
  with a producer and no *local* consumer, so a cross-impl run could catch it — someone else read
  the field. Here **nobody** read it, in any tree, for the life of the project. Three peers
  carried it on every hello and agreed perfectly on the *behaviour* (ignore it) while disagreeing
  on the *value*. **A dead field cannot diverge observably**, so the 358-vector corpus, the 1616
  wire checks and three green suites were all evidence about a field none of them could see.
  The divergence was *created* by the first conformant implementation.
  **Why the direction of the check hides it, and this is what to carry past this bug.** Row 1 is
  a **responder** obligation, and a peer that implements it against the wrong constant still
  passes every responder-side check anyone will ever write — ours and the cohort's — because a
  probe dialing *you* offers *your* string back to you. **A negotiated value is only testable
  from the seat that does not choose it.** So the row that found this had to dial **out**, and
  the general form is: for any field whose value your peer *asserts*, the discriminating test is
  one where the other end asserts it instead.
  **Two things this does NOT license.** It is not an argument against go's relay — their
  measurement, their site and their fix were all correct for their peer, and the relay could not
  have contained a fact neither seat had. And it is not "check the constant" — it is *find the
  field's consumer in the cohort, and if there is none, the field's value has never been tested
  by anything.*
  **And it repeats the versioning conflation this file already refuses, one layer down.** The
  `7` was read off the specification's **title** (`ENTITY-CORE-PROTOCOL-V7`, cited as v7.69
  throughout) while §8.4 pins the wire identifier two thousand lines away. The top of this file
  spends a section on *"our release version is not the protocol version"*; the same mistake
  reached the wire because **a document's version and the identifier it pins are two numbers,
  and one of them is a string a peer compares byte for byte.** Filed as SA-PY-32 asking for the
  one cross-reference that would have prevented it: §4.5's row names §8.4's literal.
  Enforcement points: `test_connect_protocols_intersection_4_5.py` —
  `TestTheVersionStringItself::test_the_advertised_version_is_the_one_8_4_pins` (pinned to what
  **§8.4 declares**, not to what we emit, per the `PINNED_ROOT_HASH` lesson), the **AST-based**
  zero-ratchet against a second literal, and the `system/peer/info`-vs-hello row that compares the
  two surfaces a peer states its version on — they were separate literals, so each surface's suite
  asserted its own and neither could see the other. Seven mutations, seven correct predictions;
  the one that matters is that reverting the constant to `entity-core/7.0` turns **only** the
  version row red — every behavioural row passes, because both sides of a local test use the same
  constant. *That is the entry, restated as a measurement.*
  **Corollary, earned in the same pass: a rejection probe malformed in a second dimension is a
  harness defect that only surfaces when someone implements the rule it violates.** Landing the
  intersection turned go's `format_agility.agility_unknown_1` red — its hello encodes key_type
  `0xFD` *and* advertises `entity-core/v7`, a **third** spelling in no spec and no tree. This is
  the D11 rule (*"when two rules gate one write, every rejection test must satisfy the rule it is
  not about"*) with a **sibling's probe** as the subject. The right response was **not** to
  reorder our checks to suit it: tracing it (A1) found that §4.5 names hello *"the canonical
  earliest reject point for an unsupported `key_type`"* and we rejected only at `authenticate` —
  a real gap that `AGILITY-UNKNOWN-1` tolerated because it is satisfied *"at any handshake
  surface"*. **A vector written to accept any of several surfaces cannot tell you that you are on
  the wrong one**, so the gap read green until an earlier check took the surface away. Fix the
  spec's rule, not the probe's expectation — and keep the probe's own malformed frame as a test
  row, because the tidy frame your fixtures would have written cannot discriminate the ordering.

- **A new wire field has THREE homes and only two of them have a test that fails when you miss
  one.** *Candidate, 2026-09-01, building RELAY v1.3 — the two-representations law with the
  **declared type** as the representation nobody enumerated.* Adding `forward-request.
  expires_at` and `limits.max_retention_ms` touched the constructor (`make_*`), the handler
  that reads them, and `types/definitions.py`. The first two are exercised by every behavioural
  row you write *because you are writing them to test the behaviour*; the third is a separate
  file nothing in the feature's own test set imports. So the field shipped, worked, was
  mutation-verified — and was **undeclared**.
  **The only thing that saw it was a sibling's type census**, reporting `field "expires_at":
  optional locally, missing remotely`. Open-type-tolerable, hence a WARN rather than a FAIL, and
  still a real defect: a peer type-checking against our published `system/type` rejects a
  request *we ourselves send*. A WARN in a 446-row category is also the least-read line in the
  run.
  **The check:** after adding a wire field, grep `types/definitions.py` for it before you
  commit. And build the gate against the **constructors**, not against a field list — a
  hand-maintained list is the artifact that goes stale, and the constructor already knows every
  key it can emit. Enforcement point:
  `test_relay_store_bounds_v13.py::TestTheDeclaredTypesCarryTheNewFields`, which asserts
  `set(make_forward_request(...).data) - set(declared_fields)` is empty, so the *next* field is
  caught here rather than by whoever reads our types next. Mutation-verified.
  *And the mutation cost the work twice: it was run against an **uncommitted** type edit, so the
  `git checkout --` restore took the fix out with the mutation. The "mutate a committed file"
  rule below, hit in exactly the shape it describes — it is a rule about the restore step, and
  the restore step is the one you run on autopilot.*
