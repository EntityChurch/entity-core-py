# What a sibling's packet can and cannot tell you about this repo

**When to open this:** A routing packet, ruling, fold or cohort report arrived and you are about to do the work it asks for. Read this first.

Every entry here is one law: **a routed report's claims about *our* repo are hearsay.** The axes that have actually bitten are our architecture, our coverage, our version, our behaviour, our filing record, the remedy, our build state, the schedule, a count, a citation, an absence of work, a per-seat column, a compliment, and an exculpation.

**The expensive direction is the flattering one.** A claim that we are broken sends you to the tree, which corrects it. A claim that we already comply produces no task at all — so it ships.

**The check is the same two seconds every time:** grep our own tree for the identifier, the mechanism or the protocol level before reading the packet's argument. Do it *especially* when the sentence is complimentary.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **An exculpation names a COMPONENT, and you have two — the one it names and the one that
  makes the artifact everyone else blesses against.** ***RATIFIED 2026-09-16*** *— fourteenth
  axis of the hearsay law, and the second time a premise saying **you already comply** shipped
  a live defect here (the first was §8.3's `_EVAL_LIMIT_CODES`). The new part is that the
  premise was **true**, about the component it named.* `CQ-22` ruled the signature message is
  the target's **full `content_hash`**, and arch's packet exculpates this implementation: *"Your peer is
  already right… **the sole implementation of the losing reading is the conformance
  fixture.**"* Measured: py has **two** homes for that rule and they disagreed.
  `auth.create_signature_entity` signs `target_hash` — §7.3, correct, which is why 8 of 8 live
  peers handshake. **`conformance.emit._emit_signature` signed `ecf_encode(entity)`** — the
  withdrawn reading, in the one component whose entire job is producing bytes other seats bless
  against.
  **Why that direction is the expensive one.** `S-1` item 4 asks for *"a second independent
  codec"* to cross-bless the regenerated vectors, and py is an obvious candidate — independent
  decoder, independent ECF encoder, RFC 8032 Ed25519. Offered as that codec, py would have
  **confirmed the wrong bytes**, and *two independent codecs agreeing* is the strongest green
  the cohort has. The exculpation removes the one prompt that would have sent anyone looking.
  ⭐ **And the corpus's own defect had the identical shape in our source.** Arch's finding —
  *"the artifact contains its own correct input one category above; the `signature` category
  three rows down does not use it"* — was true of `emit.py`: `_emit_content_hash` sat
  **directly above** `_emit_signature`, unused. *A defect you are reading about in someone
  else's artifact is worth one grep in your own, in the same shape, before you file it as
  theirs.*
  **The check:** when a ruling exculpates *"your peer"*, enumerate every component in the repo
  that implements the same rule — peer, SDK, conformance emitter, fixture builder, CLI — and
  assert they produce the **same bytes**. Enforcement point:
  `tests/unit/test_signature_message_is_the_content_hash_cq22.py::TestThePeerAndTheEmitterAGREE`,
  whose oracle is §7.3 written out as code rather than a call to the function under test.
  One mutation, one correct prediction (3 of 5 rows).

- **A per-delta "does your tree move?" column is scoped by the ADDRESSEE'S MECHANISM, and the
  delta written ABOUT your mechanism is the one it scores "no".** ***RATIFIED 2026-09-16***
  *— thirteenth axis of the "a routed report's claims about our repo are hearsay" law, and the
  second where the carrier is a table of `—`/`no` rows. The twelfth axis was a **compliment**
  (a sibling saying we already conform); this is a **blessing** (a ruling deciding in our
  favour), and it is the same terminates-in-no-work shape one step further from suspicion.*
  0.8.2.26 blesses two mechanisms for §1.8's mis-keyed `included` entry. **`DR-4` rules in py's
  favour** — our `included` is a **list**, wire keys discarded, so the probe's input does not
  exist in our decoded form — and go's relay leads with it as a win. **`DR-5`, in the same
  revision, is the COST of that same choice**: *"(a) is one check at one site and cannot be
  partially adopted; (b) is a check at **N ingresses**, and **N−1 of N is wire-indistinguishable
  from N of N**… an implementation adopting (b) SHOULD enumerate its ingresses and assert the
  validation pass at each."*
  **Both routing artifacts score `DR-5` "no".** arch's fold table is *correct for its addressee*
  — go is mechanism (a), for which `DR-5` is not applicable — and go's relay §5 to py lists
  `DR-2`/`DR-8`/`DR-9`/`DR-4` and **does not mention `DR-5` at all**, reasonably, since its own
  column said no. So the one delta in the round written about the mechanism py chose arrived
  marked as costing nothing.
  **Measured: it cost three ingresses.** The census `DR-5` asks for — run over the inventory a
  defect cannot edit, every `ecf_decode` call site — found `framing.recv_envelope` (TCP),
  `http_server._decode_envelope_body` and `http_client._body_to_envelope`, and **both HTTP ones
  were hand-rolled copies that had drifted twice**: no 0.8.2.25 non-map arm, no 0.8.2.26 tag
  policy, under the docstring *"Validates hashes the same way `recv_envelope` does."* True when
  written. ⭐ **And they are the boundary no cohort probe reaches** — every prober in this
  ecosystem dials TCP — so `DR-5`'s *"wire-indistinguishable"* was the measured state of this
  tree, not a hypothesis.
  **The check:** when a ruling blesses a **choice** rather than fixing a defect, read the whole
  round for the delta that prices that choice, and **do not read your own row's verdict as the
  answer** — a per-seat column is computed from the addressee's implementation, and yours is the
  one it cannot see. Remedy is the standing `F68` one: **one derivation, not N agreeing ones**.
  Enforcement point: `tests/integration/test_included_ingress_census_dr5.py`, which enumerates
  the ingresses from the call graph, asserts none keeps a private copy of the admission checks,
  and is **monotone in both directions** — a ledgered exemption that stops decoding fails too.

- **A sibling's "you already do this" is scoped to the MEMBER they measured, and they will
  write it about the CLASS.** ***RATIFIED 2026-09-15*** *— twelfth axis of the "a routed
  report's claims about our repo are hearsay" law, and the first where the claim is that we
  are **already conformant**. The tenth axis (a citation scoped by a surface they have) and
  the sixth (a wrong remedy) both fail when you look; this one is TRUE, about one of three
  members, and terminates in no work.* the packet that closed the §4.11 framing split
  with *"go was the bare-close seat (not rust, which silent-drops, and **not py, which
  already emits a coded frame**)."* Measured here before any edit, across §4.11's five
  causes: **un-parseable-but-whole CBOR** did emit a coded frame (SA-PY-61, ruled in our
  shape the same day, so the flattering half was genuinely earned); **truncated payload**
  was a bare close; **oversize** answered `400 invalid_request` where §4.10(a) has always
  said `413 payload_too_large`, with `payload_too_large` at **zero occurrences** in the
  tree; and **arm (f)**, multiplex survival, failed on every cause because we emitted the
  frame and then closed.
  **The mechanism is that a sibling measures the arm THEY just fixed.** go's edit sits at
  their decode-error branch, so *"does py emit a coded frame here"* is a question about one
  input, and the answer generalizes in the writing rather than in the measuring — *"emits a
  coded frame"* is a sentence about a peer, and what was measured was a frame. Nothing in
  the packet is wrong; the scope quietly widened from an input to a class.
  **Why it is the expensive direction:** a claim that you are *broken* sends you to the
  tree, which corrects it. A claim that you are *already fine* produces **no task**, and it
  arrives attached to a ruling you were about to absorb — so the absorption reads as
  "nothing owed here" and the two members nobody measured ship. Same terminates-in-no-work
  shape as a premise saying you already comply, with a **sibling's measurement** as the
  premise instead of arch's prose.
  **The check, and §4.11 hands it to you:** when a ruling states its class as a **table of
  causes**, walk the table and drive **one input per row** before accepting any seat's
  summary — including the row a sibling says you pass. One row per cause is the same read
  either way, and it is the row-walk law (*walk every row when N are reported*) with
  **causes** as the rows and a **compliment** as the trigger. Enforcement point:
  `tests/integration/test_preadmission_refusal_4_11.py::TestTheTeeth::
  test_the_three_causes_do_not_collapse_to_one_answer`, which asserts three causes give
  three distinct `(status, code)` pairs — a peer with one code for the class passes every
  individual row that only asserts *"a frame arrived"*.

- **A RETRACTION round's cost table is the one nobody checks, because a withdrawal reads as
  free — and the seat that BUILT the withdrawn rule is the only one it costs.** ***RATIFIED
  2026-09-14*** *— eleventh axis of the "a routed report's claims about our repo are hearsay"
  law, and the first where the claim is an **absence of work**. Four of 0.8.2.24's six deltas
  showed `—` for py and **three of them were owed here.*** Arch's §5 table reads
  `N1 — · N2 — · N3 — · N4 —` for this implementation. Measured before touching anything: **N1** was live
  at four grant loops (we shipped clause 2 as SA-PY-60 three commits earlier, which is *why* the
  withdrawal costs us and nobody else); **N2** was live at four call sites; **N4** was a bare
  socket close at the serve loop, byte-identical to the go behaviour the packet contrasts py
  with.
  **Why a retraction inverts every instinct the law was built on.** Every prior axis —
  architecture, coverage, version, behaviour, filing record, remedy, build state, schedule,
  count, citation — is a claim you check because you are *about to do work*. A `—` in a
  withdrawal column says *you have nothing to undo*, which terminates in no task, no diff and no
  test, and it is **most likely to be wrong precisely at the seat that implemented the withdrawn
  rule** — because arch's premise is *"it removes an obligation none could satisfy"* and our
  satisfying it is the thing that premise cannot see. The seat that did the most work on a
  ruling is the seat its retraction is most expensive for, and the table is sorted the other way.
  **The check is the same two seconds as every other axis and has to be run on the `—` rows,
  which is the part that is new:** for each delta, grep for the *mechanism* the delta withdraws
  or narrows (`grant_declares_a_contradicting_scope_type`, `NEVER_MATCH`, the serve loop's
  `break`) before reading the column. And when a fold is announced as *"mostly a retraction"*,
  read the **whole** table rather than your own row — a retraction round is where a `—` is
  cheapest to write and most expensive to believe. Enforcement points: one test file per delta,
  each carrying the measured pre-state in its module docstring, plus
  `test_scope_type_is_a_dimension_property_j4.py`, **inverted rather than deleted** so a later
  reader can learn the refusal was built, driven and taken back — and a *structural* row pinning
  that the helper is gone, because no behavioural row can tell *"we removed the refusal"* from
  *"this input does not reach it."*

- **A cohort blocked on building a fixture is worth one grep before it is worth a cross-repo
  build — the thing may already be shipped, twice.** *Candidate, 2026-09-14 — 0.8.2.24 N5 /
  `KB-16`.* Arch: N5's ceiling, `K4`/`K5`'s owner-frame arm and rust's frame vector *"all need
  the same thing: a peer where the executing handler's own grant is NARROWER than the caller's.
  **Nobody ships one.**"* keystone reached that from a 45-peer wire census (*"a core peer has
  one path-resource handler, so owner and runner coincide at every reachable site"*); go from
  161 cross-impl rows. Both measurements are correct **about the generated lineage**, and the
  conclusion was generalized to the cohort.
  **py ships one and so does go.** `system/validate/dispatch-outbound` is registered with a
  narrow `max_scope` — handlers, operations **and** resources all narrowed, `peers` omitted —
  per GUIDE-CONFORMANCE §7a.1's scaffold contract, and our own call-site comment records it as
  byte-parallel with go's `DispatchOutboundHandler.Manifest().InternalScope`. The premise is
  the hearsay law on its architecture axis, in the **expensive** direction: *"the fixture does
  not exist"* terminates in a cross-repo build of a thing already built, at two seats, for a
  documented reason.
  **Why nobody looked:** the fixture is in the **conformance scaffold**, not in the handler set
  a census enumerates — it exists to make §1.4's compose-vs-bypass discriminator constructible,
  which is a *different* finding, so no search for *"a narrow handler grant"* was ever run
  against it. **A fixture built for one ruling is invisible to the next one unless somebody
  greps for the shape rather than the purpose.** Enforcement point:
  `test_handler_grant_ceiling_n5.py::TestTheFixtureTheCohortIsBlockedOn`, which asserts the
  registration rather than describing it — the claim is being routed, so it must fail here if it
  ever stops being true.

- **A routed item's STATUS is a claim about a question; the behaviour under it is a separate
  claim — and "already routed" is the disposition that terminates in no work.** *Candidate,
  2026-09-13 — auditing `entity-core-go`'s three-way survey, where the one real bug on the whole
  board was the row filed as not-a-defect.* The survey classified 32 non-PASSes across three peers
  and got 31 right. The one it got wrong was `include_payload_overlapping_exclude`, filed as *"the
  already-routed Q2 divergence… WARN, not FAIL, because py's control is inconclusive."* Every
  clause true; the conclusion — *"no new defect"* — wrong, because a question can be open upstream
  while the behaviour underneath it is an ordinary bug at one seat.
  **Why this classification is the attractive one:** it is *verifiable* (the item really was
  routed), it costs nothing to apply, and it reads as diligence rather than as a shortcut. It is
  the *"a premise saying you already comply"* shape with **our own ledger** as the premise.
  **The check, and the survey was one step away from it:** *an inconclusive control is a reason to
  investigate, not a reason to classify.* When an arm's own message says it cannot attribute its
  refusal, the board cannot disposition that row at all — it needs a source read at the failing
  seat or an ask routed to it. Corollary for the seat being surveyed: **when a sibling reports your
  column as conformant-but-divergent, that is a claim about your code** (the standing hearsay law),
  and the cheap move is to drive their exact capability shape in your own tree before agreeing with
  the disposition. Here it was one test file and the "spec question" evaporated.

- **A sibling's CITATION is scoped by a surface THEY have — and the seat the citation does not
  reach is the seat with the defect.** ***RATIFIED 2026-09-12*** *— tenth axis of the "a routed
  report's claims about our repo are hearsay" law (after our architecture, coverage, version,
  behaviour, filing record, remedy, build state, schedule and count), and the first where the
  routed claim is **entirely true** and still routes you to the wrong disposition.*
  `entity-core-go` and `entity-core-rust` both closed the bulk-read disclosure — *"listings and
  extracts shipped every entry under a folder regardless of the exclude"* — citing
  **`EXTENSION-TREE` §8.2 (View Trees, Read Behavior)**. §8.2 says exactly what they say it says.
  It is also scoped by **§12.2**, which files view trees under **SHOULD**: *"View trees for
  handler isolation (§8). **When view trees are implemented**, the following are MUST."* This
  peer implements none — `view_tree` has **zero** occurrences in the tree — so read through that
  citation the obligation does not bind us at all, and a seat that checks the citation before the
  behaviour closes the item as out of scope in one grep.
  **`ENTITY-CORE-PROTOCOL` §6.3 states it unconditionally**, about *the tree handler* rather than
  about a projection: *"each entry MUST be individually checked… `count` MUST reflect the filtered
  entry count… Pagination applies to the filtered result set."* Three MUSTs, none of which this
  peer did.
  **Why this axis is worse than the nine before it.** Every other axis fails the moment you look —
  the tree disagrees with the claim. Here the claim is *correct*, the section exists, the quote is
  accurate, and the only thing wrong is that the obligation has **two homes** and the sibling cited
  the one their own architecture made salient. go has view trees in view; we do not; the sentence
  that binds us is in the document neither of us was reading. And the disposition it produces is
  *"not applicable"*, which terminates in **no work** — the same flattering-direction failure as a
  premise saying you already comply.
  **The check, and it is one grep:** when a routed finding names the section, **grep the CORE
  protocol for the behaviour**, not for the section — here `grep -n "listing" ENTITY-CORE-PROTOCOL.md`
  lands on the paragraph directly. A conditional section (`SHOULD`, "when X is implemented",
  "for peers that offer Y") is the tell: an obligation that real is rarely *only* conditional, and
  if it is, ask why the unconditional peer is exempt from a disclosure rule. Enforcement point:
  `tests/integration/test_bulk_read_per_entry_filter_6_3.py`, whose module docstring states the
  citation correction first and the behaviour second, because a later reader arriving from go's
  packet will otherwise re-derive the out-of-scope conclusion.

- **An ENUMERATION of the sites a rule binds is a claim about YOUR call graph, and the ruling
  that writes it cannot see yours.** ***RATIFIED 2026-09-11*** *— eighth axis of the "a routed
  report's claims about our repo are hearsay" law (after our architecture, coverage, version,
  behaviour, filing record, remedy, build state and schedule), and the first where the carrier is
  a **count**. Cost: none, because the count was checked — which is the only reason this reads as
  a discipline rather than as an incident.*
  0.8.2.21's `H1` fixes the fail-OPEN exclude and says *"measured here it is **THREE** sites, not
  the one filed — `matches_scope`'s exclude loop, `check_resource_scope`'s concrete arm, and the
  pattern arm."* All three were live here. **`check_path_permission` (§6.3) is a fourth**, with
  its own `resources.exclude` loop, fail-open identically — measured: a grant excluding
  `*/secret` granted `get` on `/{peer}/secret` through it.
  **Why the fourth site is the one that matters, which is the part that generalizes.** 0.8.2.20
  **withdrew** the *"defense-in-depth"* characterization of that check and made it *the
  enforcement* for any subject derived after dispatch. So a peer that fixes the three enumerated
  sites has closed the fail-open on the dispatch path and **left it live on the path that carries
  the guarantee when the dispatch path has been made vacuous** — the exact composition `F68`
  established is reachable. The two rulings are four days apart and the second does not cite the
  first.
  **A count is more persuasive than a list and carries less information.** *"Three sites"* reads
  as a completed census; it is a census of the **routing seat's** tree, and *"measured here"* says
  so outright while reading as thoroughness. A list of names at least invites you to check whether
  yours are on it — a number invites you to stop at three. **So: when a ruling enumerates sites,
  grep your own tree for the CONCEPT (an `exclude` loop, a traversal, a validator) and reconcile
  the count before implementing.** One grep; it found a fourth here and the fourth was the
  load-bearing one. Enforcement point:
  `test_exclude_unmatchable_and_params_path_total_82221.py::TestTheFourthSiteArchDidNotEnumerate`,
  mutation-verified RED with **no other row in the file covering it** — which is the measurement
  that says it is an independent site rather than one rule reached three ways. Routed as SA-PY-52.

- **A ruling routed to you carries an assumed baseline, and the baseline is the claim to check
  first.** ***RATIFIED 2026-08-21*** *— second instance of "a routed report's claims about our repo
  are hearsay", and the first where the wrong claim was about our **version** rather than our
  architecture or our coverage.*
  **Fourth instance, 2026-09-09, and the assumed baseline was in a section written TO US, by ARCH,
  that says it is scoped by a diff.** that round's relay is addressed to `entity-core-go` and
  carries *"For `entity-core-rust` and `entity-core-py` — relay this section"*, opening with
  **"Scoped by the diff, not by what you shipped."** That sentence reads as a guarantee of
  completeness and is one — **for go**, whose baseline was 0.8.2.14. This repo was on **0.8.2.11**,
  so `.12`/`.13`/`.14` were never in anyone's diff and were never routed here at all. `0.8.2.13`
  had live work in it: the `system/*` registration reservation is **withdrawn**, and this peer was
  still enforcing it with a hardcoded prefix match ahead of authorization. Nothing in the relay
  mentions it, correctly, because go had absorbed it a revision earlier.
  **Why this axis is worse than the sibling-relay shapes above.** A sibling's packet is obviously
  written from a sibling's seat, and *"a routed report's claims about our repo are hearsay"* is
  already the reflex. This one is **arch's**, it is addressed to us by name, and its scoping
  sentence is *about* completeness — so the one place you would look for the caveat is the place
  that reassures you. A relay's per-seat worklist is scoped by **the routing seat's** diff, and no
  amount of care in writing it can make it scoped by yours.
  **The check, and it is the same two seconds as every other instance:** before working a routed
  worklist, `grep` your own tree for the protocol level you last absorbed and diff it against the
  ruling's. Here `grep -o "0\.8\.2\.[0-9]\+" ... | sort -V | uniq -c` answered it — 36 hits at
  `.11`, none above — and reframed a four-item worklist into a six-item one. **Then state your
  corrected baseline in the reply**, because the relaying seat's board is tracking you against the
  version it assumed. Enforcement point: the version census is the first command of any
  catch-up pass, and `0.8.2.13`'s withdrawal is recorded at the site it was removed from
  (`entity_handlers/handlers.py`) as an argument against re-adding it — a withdrawn rule leaves no
  failing test behind, so the comment is the only thing that stops it coming back.
 The packet routing COMPUTE **v3.26** carried the sentence
  *"rust and py are not yet on v3.26."* True and useless: **this repo was on v3.23.** v3.24 and
  v3.25 were never routed here at all, so §3.5's three contained positions — `assoc`'s `value`,
  `concat`'s elements, `group-by`'s `members` — **did not exist to carve out.** The ruling's entire
  content is a carve-out at a site we did not have.
  **Why this shape is worse than the other two, and it is the reusable half:** a wrong claim about
  our *shape* or our *coverage* fails loudly the moment you look. A wrong claim about our *version*
  fails **silently and in the flattering direction** — the diff is small, it applies cleanly, the
  suite is green, and you have shipped a carve-out guarding nothing while reporting the ruling
  absorbed. Nothing in the routed report is wrong; it is written by a seat whose own baseline is
  three versions ahead, and *the delta it names is the delta from **its** last state.*
  **The check, and it is one command:** before implementing a routed ruling, grep your own tree for
  the identifiers the ruling's *premise* depends on — not the ones it introduces. Here
  `git log --all -S assoc -- packages/` is empty, which is a two-second answer and reframes the
  whole task. State the corrected baseline in the reply, because the sibling's board is tracking
  you against the version it assumed.
  **And the version gap is scope, not an excuse to narrow.** The deliverable for C-6 is *"py builds
  v3.26"*, which here means three versions; landing the carve-out alone would have been a green diff
  that unblocks nothing and reads as done. Enforcement point:
  `tests/integration/test_compute_v324_collection_primitives.py`, whose module docstring records the
  measured baseline and the search that established it.
  **Second instance, 2026-08-22, and the assumed premise was a claim about our *behaviour*, made by
  the *ruling itself*, in the flattering direction.** Arch's §8 eval-limit ruling opens by stating
  what each seat does: *"rust and py short-circuit `budget_exhausted` and `cascade_limit` and
  **contain** `depth_exceeded`."* §5.3 concludes *"your `depth_exceeded` containment stands. Nothing
  owed,"* and core-go relayed it as *"C-14 — you were right."* **py short-circuited all three** —
  `_EVAL_LIMIT_CODES` at `f09ae70` — and **our own SA-PY-25 says so in its second paragraph**, which
  is where the mis-read came from: the filing argued for a *code-based* discriminator against go's
  provenance-based one, arch read that as agreeing with rust's *criterion*, and the criterion and the
  code set are different things. So the ruling arbitrated against go on one row and shipped a
  premise that excused the seat with the same defect.
  **Why this direction is the dangerous one, and it is the reusable half.** The other three shapes of
  this law (our architecture, our coverage, our version) all fail *loudly the moment you look* — you
  go to do the work and the tree disagrees. A wrong premise saying **you already comply** produces
  **no task at all**. It is the *"a ruling you already satisfy produces no diff"* trap with the
  compliance itself fabricated: the normal forcing function is absent, the board reads closed at
  three seats, and the row sits green because nobody was assigned to look. Ours would have shipped
  into a release, and the two sibling reports would have been the evidence it was fine.
  **The check, and it costs one grep:** when a routed ruling states what your seat does, **grep for
  the identifier before reading the ruling's argument** — `_EVAL_LIMIT_CODES` here, two seconds, and
  the whole packet reframes. Do it *especially* when the sentence is complimentary, because that is
  the one branch of the read that terminates in no work. And when the premise came from your own
  filing, check what the filing actually claimed: **an SA is read by someone reconciling three seats,
  and a paragraph arguing about a *discriminator* will be summarized as a position on the *outcome*.**
  Enforcement point:
  `test_compute_v327_closure_result_positions.py::TestDepthExceededContains` — CV-9a, the value-form
  depth row, and the fold-recovery row, each mutation-verified RED against the shipped set, plus
  `test_the_premise_of_8_3_holds_at_this_peer_depth_is_restored_on_unwind`, which is the one that
  would have caught it **unaided**: it asserts the *property the ruling reasons from* (§5.1's `depth`
  restored on unwind) in our tree rather than the conclusion the ruling drew. **When a ruling derives
  your behaviour from a property of your implementation, assert the property.** That row's first
  draft was driven through `map` and failed under the carve-out mutation too — i.e. it was measuring
  containment a second time and not the premise; driven bare it is orthogonal, which is the only way
  it can tell the two failures apart. *A row that fails for two reasons is a row that has told you
  nothing about either.*
  ***RATIFIED 2026-09-01 — second instance, and the property was asserted by the ruling's own
  justification rather than assumed by its premise.*** Filed as SA-PY-29. §6.2 (0.8.2.3) pins the
  default per-handler self-grant with `peers` omitted and justifies the shape behaviourally: *"A
  default-scope handler consequently **cannot** dispatch at a foreign peer, which is the escalation
  that matters."* Asserted here, that is false on **both** paths — inbound, PD-1h now refuses before
  `check_permission`; in-process, `_dispatch_local_execute` returns at `_remote_execute` **before**
  `_resolve_for_dispatch`, and `target_peer` is computed *below* that return, so the only value that
  can reach the four-dimension check is the local peer. Measured: a handler holding exactly the ruled
  grant, sub-dispatching at a foreign uri, gets **502 "No live transport profile"** — it went looking
  for a *route*, i.e. it had already decided the dispatch was permitted. **The ruled shape is inert.**
  **Two things this adds to the law.** First, the tell moved: in the §8.3 instance the unasserted
  property sat in the ruling's *premise* (what it said we do), and the check was to grep for the
  identifier. Here it sits in the ruling's *justification* (why the shape is right), which nobody
  greps because it reads as motivation rather than as a claim. **A justification is a claim about
  your peer whenever it contains a verb your peer is the subject of** — `cannot`, `is still checked`,
  `defaults to and is enforced`. Second: **a ruling can absorb a filing and answer a different
  question than the one filed.** 0.8.2.3 absorbed `entity-core-go`'s `2026-08-23-a`, which asked
  *where does the check bind*, and ruled *what shape the grant has* — while resting that ruling on
  the check binding. Both seats' boards read the item closed. **When a ruling names your filing as
  absorbed, re-read what the filing asked, not what the ruling settled.**
  Enforcement point: `tests/integration/test_peers_dimension_outbound_gap.py` — rows that **fail
  when the enforcement point lands**, each carrying its retirement condition in the assertion
  message, including a structural row asserting `target_peer` is still read *after* the remote
  branch. That row is the one worth copying: the missing check is not a missing `if` but an argument
  that cannot be anything except the local peer, and **a reviewer reading a correct-looking call
  site cannot see that one of its arguments is a constant** — so the row reads the source and pins
  the *order*, not the behaviour.

- **A sibling's summary of your board is a claim about your filings — check it the same way
  you check a claim about your code.** *Candidate, 2026-08-19.* Arch's ruling §3
  reads *"Cohort board: closed. Every routed registry item is ruled."* **SA-PY-15 is a routed
  registry item and is unaddressed** — the resolver-side ceiling is still `[MUST when present]`
  with no declared site, and arch's tree carries **zero** occurrences of the identifier while
  citing SA-PY-14 and SA-PY-17 five times each. It was dropped in handling, not decided. The
  existing rule (*a routed report's claims about our repo are hearsay*) covers claims about our
  **code**; this is the same rule with our **filing record** as the subject, and it is the
  cheaper one to check — grep the other tree for the identifier. Cost of not checking: an open
  security-relevant gap gets closed on someone else's summary, and the next cohort member reads
  a board that says it is done.
  ***Vindicated and ruled the next day.*** SA-PY-15 was **ruled in our shape** at REGISTRY 1.16
  (`resolver_chain[].hints.max_ttl`, per chain entry, read at resolution) once the pushback
  reached arch inside core-go's cohort sweep, and the class became arch's **L17**. Two things to
  carry: the fix is structural, not diligence — arch now keeps `docs/COHORT-OPEN-ITEMS.md`, one
  reconciled ledger where *"closed"* means zero open on the **shared** view and only an owner's
  in-tree confirmation at a named commit closes a row; and **"ruled" is not "closed" for us
  either**, which is why the ceiling work below shipped with a test per row rather than a note
  saying we already did it.

- **Cross-impl reports lag — ground truth is a live run.** Go's `validate-peer` cross-impl
  reports live under `entity-core-go/docs/validation/reports/` (`CROSS-IMPL-*-PYTHON-*.md`,
  dated) and go stale: fixes land without a new report and runs can be flaky. Don't
  treat a dated report as current status — run the validator live against HEAD. `local_files`
  is a Go-only extension; Python failing it is an expected scope gap, not breakage.

- **A routed report's claims about *our* repo are hearsay — verify them here before acting.**
  **Ratified 2026-08-15** (twice in two shapes, one session apart). The claim to check is
  never the gap they found in themselves; it is the sentence about *us*.
  - *Wrong about our architecture.* The `reflection_endpoints` routing said "py serves both
    the wrapped and unwrapped surfaces — apply on each," so §2.2's both-surfaces MUST would
    bind twice. It does not: this repo serves **only the wrapped surface** — the §9.2
    raw-CBOR listener and §9.3 reflector are unbuilt (`create_datagram_endpoint` has zero
    hits; the only `advertise` handlers are `signaling/node.py` and the unrelated
    `relay.py`). Cost of believing it: a surface built against nothing, or a §2.2
    conformance claim on a listener we do not have.
  - *Wrong about our verification state.* The CONTINUATION v1.23 routing listed py's NETWORK
    §5.4.1 no-write-on-success as "unverified — no per-tick status write surfaced in a grep,
    but that is not proof of the negative." It has been proof-carrying since before that
    HEAD: `test_keepalive_no_cadence_writes` drives ≥2 real pong-driven freshness advances
    and asserts the status binding's content hash never moves. Cost of believing it: we
    "verify" something already locked, or worse, treat a green discipline as an open risk.
  - **The rule.** A sibling reads our tree from outside; it can be right about the gap and
    wrong about our shape or our coverage. Absence-of-a-grep-hit is their weakest evidence
    and it is usually what these claims rest on — so answer it with a named exhaustive
    search and a test run, the same standard AGENTS-STANDARD sets for claims we make about
    *them*. Then route the correction back: an uncorrected report is what the next cohort
    member reads.
  - **Sixth shape, 2026-09-01, and the wrong claim was about the *remedy* — the one axis where
    every previous instance's defence does not fire.** The five above are wrong about our
    architecture, our coverage, our version, our behaviour, or our filing record; all five fail
    the moment you look at the tree, because the tree disagrees. `entity-core-go`'s FM-1d relay
    was **right about everything it measured** — our defect (`400 bad_request`), our site
    (`handle_connect_authenticate`'s opening phase check, one frame above the nonce comparison),
    and a correction to a census that had us down as conformant. Then it prescribed the fix:
    *"set `code="invalid_nonce"` on that raise (it carries a 401), exactly as the
    unsupported-key-type call sites already do."* **The parenthetical is false here.** Our wire
    boundary called `ExecuteResponse.bad_request(…, code=…)`, which hardcodes `status=400`, so
    the relay applied verbatim yields **`400 invalid_nonce`** — a pair in no §4.7 row either, on
    the one surface whose entire defect was a pair in no §4.7 row. The cited precedent held
    because those rows *are* 400s, which is exactly why it read as the same shape.
    **Why this axis is the dangerous one:** a wrong claim about our code sends you to the tree,
    which corrects it. A wrong *remedy* sends you to an **edit**, and a one-line edit backed by
    a sibling's measurement is the least-audited change there is — it is short, it is authorized,
    the defect it names is real, and the diff looks complete. Nothing surfaces afterwards: the
    code assertion passes, and status alone cannot separate this from a post-hello nonce
    mismatch. **The check, and it is one read:** when a relay names the fix, open the function
    the fix lands in and confirm it does what the relay says it does — especially when the relay
    cites a precedent, because a precedent is a claim that two call sites are the same shape and
    that is a claim about *your* code, not theirs. And when a spec row is a `(status, code)`
    pair, mutate each half separately: a half-fix that satisfies the assertion you wrote is how
    a non-conformant peer ships wearing a green diff.
  - **And a relay's *strike* is a claim too.** The same packet struck an item as *"their standing
    change, which is the `2026-08-23-a` item"* — a spec-issue whose own file still reads
    `Status: open — measured divergence, routed. go is NOT converging by count.` It had been
    **ruled**, in go's shape, in the same protocol commit that produced the packet. Read as a
    standing divergence the correct answer is *refuse* (GUIDE-CONFORMANCE §4: one-differs → the
    spec arbitrates, two seats do not vote a third into line); read as a ruling it is ours to
    implement. **Same word, opposite obligations** — so resolve which it is from the spec text,
    never from the routing sentence, and grep the normative section for the field before
    deciding you owe nothing.

- **A REMEDY names a layer, and the layer is the claim to check — a fix at the consumer can be
  correct at every site it reaches and still leave the class open.** ***RATIFIED 2026-09-10*** *—
  second instance of the "a routed report's claims about our repo are hearsay" law on its **remedy**
  axis (the first was `FM-1d`'s `bad_request` precedent), and the first where the remedy was not
  merely wrong about a call site but **not implementable at the layer it named**. F68.*
  Arch read the resources-dimension bypass at three trees and prescribed: *"the `_common.py` helper
  counts `len(targets)`; add the caller-`exclude` reduction **in the helper**, which is why the
  helper exists."* Correct about the defect, correct about the site it names, and **the helper takes
  a `HandlerContext`, which carries no `resource_exclude` at all** — the field is read into a local
  in `_handle_execute`, handed to `check_resource_scope`, and dropped. Applying the remedy as
  written means plumbing it into every handler, i.e. **two derivations of one set with an
  authorization decision on one side**, which is the defect restated.
  **And the count was the tell nobody was looking at.** The helper covers 13 sites; **~20 sites
  across 8 modules read `ctx.resource_targets` directly** — `tree.py` first among them, the
  most-dispatched handler in the peer, unnamed in the census. A helper-only fix passes the routed
  vector, greens the suite, and leaves the largest consumer open.
  **The two checks, in order:**
  1. **When a relay names the layer to fix at, open the function and confirm it can see the value.**
     A remedy is a claim about *your* call graph, and the routing seat cannot see it. One read.
  2. **When a rule says two parties must derive the same set, the enforcement is ONE derivation, not
     two agreeing ones.** Narrow at the gate and install the narrowed value; then the consumer
     cannot re-widen it, the rule becomes structural rather than a per-site obligation, and the next
     handler inherits it without knowing it exists. Measured: zero handler edits, and the routed
     `path_required`/`ambiguous_resource` table fell out of the **existing** arity checks.
  **Corollary — a census keyed on the wrong operation misses a whole kind of site.** The class was
  censused by *indexes `targets[0]`* and the second py site is a **forwarder**: `compute/apply`'s
  `sync_dispatch` accepted and dropped `resource_exclude` and passed the raw targets on, so the
  handler-grant ceiling check was vacuous while the dispatch still carried the target. **The unit is
  *reads the field or forwards the field*, and an index-keyed grep cannot see a forwarder.**
  Enforcement point: `effective_resource_targets` (one function, both callers) plus
  `tests/integration/test_effective_resource_target_set_f68.py::
  TestTheReductionIsAtTheAuthorizerAndNotInEachConsumer`, whose first assertion pins that
  `HandlerContext` never gains the field — because the tempting "improvement" is to hand consumers
  the exclude so they can be careful with it.

- **A ruling with two halves can arrive split across a sequencing plan's phases, and the seat
  holding the first half is the only one who can find out.** *Candidate, 2026-09-10 — arch's
  Subscription Phase 1/Phase 2, and the standing hearsay law with a **schedule** as the subject
  rather than our code, coverage, version, behaviour, filing record, remedy or build state.*
  §1.4 rules autonomous delivery in two clauses that are one behaviour: *Dimensions 1-3 on the
  handler's own grant* **and** *Dimension 4 relaxed by the recipient-minted token.* Arch's
  sequencing splits the work into **Phase 1** (*every seat MINTS a conformant `deliver_token`; no
  seat gates*) and **Phase 2** (*present-and-gate, only after all three mint*), and files py's
  half — *"stop minting `peers:["*"]`"* — in the **Phase 1** column, under the heading *"Phase 1
  is independently correct and breaks nothing."*
  **Measured here, it is a Phase 2 change.** `extension_execute` passes no
  `dispatch_capability_entity`, so nothing on that path can supply the second clause; switching
  it to a peers-omitted grant fails the cross-peer subscription suite with `403 … §5.2
  Dimension 4 (peers)`. Narrowing the grant and presenting the token are **one** change, and
  presenting is what Phase 2 *is*.
  **Why a schedule is a worse carrier than a claim.** Every other axis of the hearsay law fails
  the moment you open your tree — the tree disagrees. A phase assignment makes no claim your tree
  can contradict; it asserts that a piece of work is *independent*, and independence is a property
  of **your** call graph, which the scheduling seat cannot see. The heading even supplies the
  reassurance (*breaks nothing*), so the branch that terminates in *"just do it, it's mechanical"*
  is the one the packet argues for.
  **The check:** when a routed plan assigns your half of a two-clause ruling to a phase, **drive
  the change and run the suite before accepting the phase** — the question is not *"is this small?"*
  but *"does my code contain the other clause yet?"*. Then route the sequencing finding rather
  than absorbing it: a seat that quietly defers reads as behind, and a seat that complies breaks
  its own wire. Enforcement point: SA-PY-46's 2026-09-10 update and
  `test_autonomous_origination_dimension_4.py`, whose rubric was **re-pointed** rather than
  deleted — the hold is still right and its *reason* changed, which is the thing a later reader
  would otherwise re-derive wrong.

- **A routed report's claims about our repo are hearsay — seventh axis: our BUILD STATE, and it
  is the flattering direction.** *Candidate, 2026-09-03.*
  `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §1 records *"`entity-core-go` and `entity-core-py`
  have not built these handlers, searched at the commits above"*, §4 concludes *"rust has the
  only implementation"*, and the relay asked us whether §2 matches what we **would** build.
  **We had built all six**, at `system/type`, against `EXTENSION-TYPE` v1.1 §7.1 — so the fold
  was sized on one build when it has two, and the ask was a hypothetical about a tree that
  already answers it.
  Same terminates-in-no-work direction as the §8.3 instance (*a premise saying you already
  comply*), one axis over: **a premise saying you have nothing to check produces no task at
  all.** Same one-grep check. And it changes what you can send back — an intention becomes a
  **measurement**, which is exactly what §4 says the fold needs (*"a derived failure set is a
  claim about what these operations can fail on — the kind of claim that is checked in a tree,
  not in a document"*).
  **What the measurement found:** §2 holds here unprompted (third seat); row 4's `validate` arm
  was already implemented and derived independently; row 4's `compare`/`compatible` arm
  diverged, and worse than the row says — an unresolvable type resolved to an **empty field
  set**, so `compatible("no/such/a","no/such/b")` reported two nonexistent types **compatible**.
  Fixed rather than held for the fold: the ruling decides whether the refusal is a `404`, and
  never licensed inventing an empty type. Enforcement point:
  `tests/integration/test_type_operation_error_taxonomy.py`, whose first class asserts the
  premise itself against the handler's source.
