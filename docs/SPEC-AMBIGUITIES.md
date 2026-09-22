# SPEC-AMBIGUITIES

Gaps and contradictions found while implementing against the landed spec, logged here and
routed upstream rather than papered over locally (`AGENTS-STANDARD.md`, "Working across the
polyrepo"). **The spec is upstream; this repo implements it.** Each entry records what we
did in the meantime so the local behaviour is traceable to a decision rather than to a
guess.

Format: newest first. An entry stays until upstream rules, then records the ruling and the
commit that adopted it.

---

## SA-PY-66 — §4.11 row (5a) says *"in a data-field position"*; ECF §6.3 forbids tags **at any depth**, and the two widths differ on a real input

**Status:** 🟡 **Open — routed with 0.8.2.26's absorption. py implements the WIDER refusal
(any depth) and says so at the call site.**

**Sections:** `ENTITY-CORE-PROTOCOL` §4.11's new tag-policy row (0.8.2.26 `DR-3`) vs
`ENTITY-CBOR-ENCODING` §5.4 / §6.3

**The ask, in one sentence:** `.26`'s new row is scoped *"a CBOR major-type-6 item in **a
data-field position**, in bytes that DO decode"*, while ECF §6.3 forbids tags **at any
depth** — and a tag wrapping the envelope itself, or sitting on a structural key, is inside
one width and outside the other.

### The input that separates them

**Tag 55799**, the CBOR self-describe marker, wrapping the whole payload. It is the one tag
a real encoder emits by accident — several CBOR libraries offer it as a flag — and it is
*not* in a data-field position by any natural reading: it wraps the envelope, above `root`.

This is not hypothetical for this seat. `ecf_decode`'s own docstring records that cbor2
silently strips tag-55799 and that the strip *"broke hash check on any entity whose `data`
field carries that marker, surfaced by `tag_reject.4` in the v1 conformance corpus."* So the
corpus already has an opinion about 55799 and §4.11's new row does not obviously reach it.

### Why the width matters rather than being a nit

The two widths give **different codes for the same bytes**, which is the exact failure `DR-3`
was written to fix one row over:

* narrow reading — a 55799-wrapped envelope is **not** row (5a), so it falls to the framing
  row: `400 invalid_request`, *"your bytes are un-parseable"*, which is false (they parse).
* wide reading — it is `400 non_canonical_ecf`, *"re-encode without the tag"*, which is the
  caller's actual remedy.

`DR-3`'s own justification is *"the code selects the caller's remedy, so a code that is
merely in the right family is still wrong."* Under the narrow reading that argument is
violated by the row the argument produced.

### What py does in the meantime

Refuses **at any depth** — `contains_cbor_tag` walks values *and map keys* — on the wide
reading, because ECF §6.3 is unconditional and because the narrow reading is the one that
re-creates the wrong-remedy defect. Documented at the call site
(`entity_core/utils/ecf.py::contains_cbor_tag`, *"Scope"* rubric) so the choice is findable
rather than inferred.

⛔ **And that sentence was false when this entry was first drafted, which is why the entry
is worth reading.** The first draft of this filing asserted the wide reading as *what py
does*. Checked against the tree before routing: a 55799-wrapped envelope decoded to a
`CBORTag`, **which is not a dict**, so the non-map arm fired **first** and answered `400
invalid_request`. py was on the **narrow** reading — not by choice, but by the order of two
adjacent checks, with no line anywhere stating a position.

The ordering is now explicit and structural (`admit_decoded_frame`: tag arm, then non-map
arm, then hashes), with the `\xf6` control pinning that an ordinary non-map payload still
takes the framing code. *A filing is a claim about your own tree, and it is the claim in a
filing nobody checks — because the filing is framed as not knowing the answer.*

**Deliberately NOT extended past the tag arm.** The other five canonical-form rules
(indefinite lengths, non-minimal arguments, float minimization, map-key order, `undefined`)
are *not* enforced on receipt here: §1.8 requires storing and forwarding the **original
bytes**, and no corpus row tells a peer which code to use for those. Adding an arm is a wire
decision and needs its own §4.11 row first.

**Requested:** row (5a) states its width explicitly — either *"at any depth, per
`ENTITY-CBOR-ENCODING` §6.3"* (which we believe is right and is what §6.3 already says), or
an explicit carve-out saying a structural tag is the framing row after all, with the remedy
argument addressed.

⚠ **Cross-impl question worth asking with it:** go and rust get this refusal from a **typed
decoder**, which errors on a tag wherever it appears — so both are almost certainly on the
**wide** reading already, without having chosen it. If so the narrow wording describes no
implementation, and this is the `SA-PY-41` shape again: a row whose scope is set by what a
typed language does for free, written as though it were a scoping decision.

---

## SA-PY-65 — `EXTENSION-TREE` §2.2a's `resource`-required column contradicts §4.2, and §3.3's own test

**Status:** 🟡 **Open — routed with 0.8.2.25's absorption. py has NOT changed behaviour on
the contradicted rows and pins today's answer with this filing named.**

**Sections:** `EXTENSION-TREE` v4.11 §2.2a (new) vs §4.2, §5.2, the `create`/`destroy`
operation bodies, and `ENTITY-CORE-PROTOCOL` §3.3

**The ask, in one sentence:** §2.2a declares `diff`, `merge`, `create` and `destroy` as
`resource` **required**, and for three of those four the operation's own section says or
implies otherwise — while §3.3 delegates authority to *"each operation's own
specification"*, so the two normative statements disagree about which one that is.

§2.2a is exactly the right fix for the right problem: *"the field is not inferable from a
handler's source, and three independent implementations inferred three different answers
from this paragraph alone."* py was the seat that inferred **13**. The table closes that.
The `get` / `snapshot` / `extract` rows are unambiguous and are implemented here.

**The four required rows are where it does not hold:**

- **`diff` — §4.2 says the opposite, in words.** *"Diff operates on stored snapshots — no
  path-level authorization. **The `resource` field is optional**; when omitted,
  handler-scope authorization (§11) suffices."* Its parameters are two `system/hash`
  values. §11's own table also still reads *"`diff` — operates on stored snapshots; no
  path-level check."* §2.2a says `required`.
- **`create` / `destroy` — nothing for a target to name.** Their params are a
  `system/tree/config` carrying `tree_id` and a bare `primitive/string` tree id; neither
  operation body shows a `resource` at all. §3.3's own test excludes them: *"an operation
  that **targets no entity binding** carries no requirement: `system/quorum:verify` takes
  both operands in `params` and binds nothing, so a `resource` would have nothing to
  name."* A tree id is not a path binding.
- **`merge` — this one is fine.** §5.2's EXECUTE line is
  `resource: {targets: [<target_prefix or paths>]}`, so `required` is a coherent
  tightening (it removes the `target_prefix` params fallback). No objection.

**Why this is worth a filing rather than a local reading.** The rows are not cosmetic: under
§2.2a's column an **absent** `resource` on `diff` MUST be `400 path_required`, so a peer
implementing the table refuses `diff(base, target)` — the only call shape §4.2 documents.
Two conformant peers reading the two sections reach opposite answers on a request that
appears in the extension's own examples.

**And it is the standing summary-table-drift law with the two documents merged into one.**
`SDK-EXTENSION-OPERATIONS` drifted from the extensions it summarized (SA-PY-2/-3/-4/-5/-6,
ruled). Here the summary and the normative sections are in the **same file**, on the very
field the summary was added to declare — which removes the one cue that made the SDK
instances findable, because nobody diffs a document against itself.

**What py does in the meantime:** nothing. The three BROAD rows are implemented and driven
across a socket. `diff`/`create`/`destroy` keep their current resource-optional behaviour,
pinned by `TestTheRequiredColumnIsFiledNotImplemented` with this filing in the assertion
message, because refusing a call shape `entity-core-go` accepts would manufacture a
cross-impl divergence out of a contradiction — the error this repo exists to find.

**Requested:** either (a) §2.2a's `diff`/`create`/`destroy` rows move to `optional` +
`n/a` (and §3.3's "targets no entity binding" carve-out is cited there), or (b) §4.2 and
§11's sentences are withdrawn and the `create`/`destroy` bodies grow a `resource`. Also a
sentence saying which of §2.2a and an operation's own section wins, since §3.3 currently
names the latter.

---

## SA-PY-64 — `CORE-RESOURCE-TWO-EMPTIES-1`'s CONTAINS assertion is not expressible at `snapshot`

**Status:** ✅ **RULED 2026-09-16 in py's shape, 0.8.2.26 `DR-9`. Adopted as measured; no
behaviour change owed.**

`CORE-RESOURCE-TWO-EMPTIES-1` arm (a) is now **stated per RESULT TYPE**: a listing or
envelope result (`get`, `extract`) MUST assert the result CONTAINS a seeded binding; a
**digest** result (`snapshot`) MUST assert that *"the absent-case root of a SEEDED prefix
DIFFERS from the root of an EMPTY one"* — the exact discriminator this seat proposed, with
arch's own note that *"a check set MUST assert the form its result type admits and MUST NOT
require the CONTAINS form of an operation that returns a digest."*

Arm **(c)** was also closed in the same delta and it is worth carrying: it is
**DECLARED-NOT-YET-DRIVABLE** — zero operations in any tier declare `OPTIONAL-FILTER`, so a
check set MUST report it not-applicable **with the condition named**, never as passing and
never silently omitted.

Enforcement point (already present, unchanged):
`tests/integration/test_two_empties_across_the_socket_2_2a.py::
TestTheAbsentResourceStillGetsItsBroadAnswer::test_snapshot_absent_case_is_a_NON_EMPTY_snapshot`.

*(Original filing below, kept verbatim.)*

**Sections:** `ENTITY-CORE-PROTOCOL` §9 `CORE-RESOURCE-TWO-EMPTIES-1` arm (a) vs
`EXTENSION-TREE` §3

**The ask, in one sentence:** arm (a) requires that the absent-case assertion *"MUST be
that the result CONTAINS a seeded binding"*, and `snapshot`'s result is a single content
hash, so no conformant peer can satisfy the assertion as written.

The requirement's reasoning is right and worth keeping: *"a prefix with nothing under it
returns `count: 0`, which a peer that never reached the branch also produces."* That is a
real hole in a status-only row, and it is why this seat's rows read the payload.

It is expressible at **`get`** (a listing of names) and at **`extract`** (an envelope of
the entities themselves). It is not expressible at **`snapshot`**: §3 — *"A snapshot
captures tree state as a content-addressable entity"* — so the result is
`{root: <hash>}`, and a seeded path appears nowhere in it by design. Measured here: the
absent-case `snapshot` answers `200 {root: 0x44e0ee…}` and contains no path at any
conformance level.

**This is the standing *a prescribed vector is a claim that it discriminates* law**, with
the prescription written from the shape of the other two rows in the same table. The three
BROAD operations have three different result types, and one assertion was specified for
all three.

**What py does in the meantime:** drives the property in the representation `snapshot`
has — the absent-case root of a seeded prefix MUST differ from the root of an empty one.
Same property (*the branch was actually reached*), same failure excluded (*an empty
answer*), expressible at this operation.

**Requested:** arm (a)'s assertion is stated per result type — *contains a seeded binding
where the result enumerates bindings; differs from the empty-prefix result where the
result is a root hash.*

---

## SA-PY-63 — §3.3's non-lossy-projection rule states a MECHANISM where the invariant is the discriminator

**Status:** ✅ **RULED 2026-09-16 in py's shape, 0.8.2.26 `DR-8`. py's mechanism is named
PREFERRED; no behaviour change owed.**

§3.3 now states the **invariant** as the `[MUST]` — *"that projection MUST preserve the
discriminator between a genuinely ABSENT `resource` and a `resource` that was PRESENT and
narrowed to empty"* — and demotes the retain-the-raw-pair sentence to one of **two
sufficient mechanisms**:

> ① retain the raw pair … or ② **encode the distinction in the SHAPE of the narrowed
> value** … ⚠ **② is preferred wherever the representation admits it**, because ① hands
> every downstream consumer a second derivation of the effective set, which is the shape
> `F68` was landed to close.

② is what this seat shipped (`None` absent, `[]` present-and-emptied). Arch's own note
records the defect the filing named: *"an implementation that preserves the distinction by
shape satisfied the property and failed the letter, and obeying the letter would have
reintroduced the second-derivation defect."*

*(Original filing below, kept verbatim.)*

**Sections:** `ENTITY-CORE-PROTOCOL` §3.3 (the 0.8.2.25 non-lossy-projection `[MUST]`)

**The ask, in one sentence:** the rule's imperative is *"**retain the raw pair** when
narrowing would empty it"*, and its next sentence gives the actual property — *"what
survives is the discriminator"* — which a seat can satisfy without retaining the raw pair
at all.

py narrows at the gate (F68) and preserves the discriminator in the **shape of the
narrowed value**: `None` when `EXECUTE.resource` was absent, `[]` when it was present and
narrowing emptied it. The effective set is identical either way, no consumer needs the raw
pair, and no subject changes — the invariant the sentence names is met exactly.

**Why the mechanism form is the wrong one to state as the `[MUST]`.** Retaining `targets`
and `exclude` past the authorizer hands every downstream consumer a **second derivation**
of the effective set, which is the defect F68 was landed to close (*"when a rule says two
parties must derive the same set, the enforcement is ONE derivation, not two agreeing
ones"*). So a seat reading the imperative literally would be instructed to reintroduce
F68's shape in order to comply with a rule it already satisfies — and a seat auditing us
against the literal sentence would file a false finding.

**This is the standing *a remedy names a layer, and the layer is the claim to check* law**
(F68's own entry, and `FM-1d`'s `bad_request` precedent), arriving inside a `[MUST]` rather
than inside a routing packet. The distinction matters more here than usual because the
rule is *about* a structural property, so implementers will read it structurally.

**What py does in the meantime:** preserves `[]` vs `None` at all three seams, driven
across a socket for the inbound one and pinned structurally for the two outbound ones.

**Requested:** the `[MUST]` is stated as the invariant — *the projection MUST preserve the
distinction between an absent `resource` and a present one whose effective set is empty* —
with "retain the raw pair" demoted to one sufficient implementation, beside "carry the
emptiness in the projected value".

---

## SA-PY-62 — `CORE-PREADMISSION-REFUSAL-1` arm (f) asks arm (a) for a property only half of arm (a) can deliver

**Status:** ✅ **RULED 2026-09-16 in py's shape, 0.8.2.26 `DR-2`. Adopted as described; no
behaviour change owed — py already carried the split as `stream_synchronized`.**

Arm (a) is **split into `(a1)` / `(a2)`**: whole-but-undecodable leaves the stream
**synchronized** and *"the close afterwards is the peer's own choice"*; truncated leaves it
**desynchronized** and *"the close is FORCED, not chosen"*. §9 arm **(f)** now binds **only
the members whose frame was consumed whole** — `(a1)`, `(b)`, `(c)`, `(d)`, `(e)` — and
**`(a2)` is EXEMPT, structurally**, with *"a check set MUST NOT assert (f) over (a2)"*.

Filed independently by this seat and by `entity-core-rust`; arch's note records that *"all
three ground-up implementations already carry the split in code; the text did not."*

⚠ **The check-set half was verified here rather than assumed:** py's arm-(f) class is
`TestArmFTheConnectionSurvivesASYNCHRONIZEDRefusal` and its truncated class asserts no
multiplex property, so this tree does not assert (f) over (a2) and needs no retraction.

*(Original filing below, kept verbatim.)*

**Sections:** `ENTITY-CORE-PROTOCOL` §4.11, §4.10(a), §9 `CORE-PREADMISSION-REFUSAL-1`

**The ask, in one sentence:** §4.11 says *"whether the peer closes the connection
afterwards is its own choice"* and §9 arm **(f)** requires that arm **(a)** — *"a truncated
/ un-parseable CBOR frame"* — not cost an admitted in-flight request its response, and
those two can only both hold where the refusal left the stream **synchronized**.

§4.11 is right, and the class it names is real — this seat was one of the three
implementations that answered the framing arm differently. The gap is that arm (a) bundles
two frames with opposite stream dispositions:

- **un-parseable CBOR, payload whole** — a complete length-prefixed frame was consumed, so
  the next read starts on a frame boundary. The connection can survive; arm (f) applies and
  py now satisfies it.
- **truncated** — the sender declared `length` and sent fewer bytes. There is no next
  boundary to find, so a peer that kept reading would parse the following frame's head as
  this frame's tail. **The close is forced, not chosen**, and arm (f) is unsatisfiable on
  this half at any conformant peer.

**Arm (c) has the same shape and is worse**, because §4.10(a) is the section that makes it
so: oversize is detected **at the length prefix** with `length` bytes still in the socket,
and draining them to resynchronize is exactly the unbounded read §4.10(a) exists to refuse.
So a peer cannot both answer `413` and keep the connection usable.

**Why this is not a quibble.** Arm (f) is the arm §9 marks *"nothing else implies … MUST be
driven on its own"*, so it will be built as a portable oracle, and a harness that drives it
with a **truncated** frame scores a conformant peer red. `entity-core-go` reached the same
distinction independently from the implementation side — their packet separates *"a
whole-but-undecodable frame … `continue`, the stream is synchronized on the next
boundary"* from *"a genuine transport break (truncated payload, reset) still closes"* — so
two seats have now derived a split the arm does not carry.

**What py does in the meantime:** `FramingError` carries
`(status, code, stream_synchronized)`; the serve loop stays on a synchronized refusal and
closes on a desynchronized one, and each disposition is driven over a socket.

**Requested:** arm (a) is split into (a1) whole-but-undecodable and (a2)
truncated/incomplete-prefix, with arm (f) scoped to (a1) and to the wrong-root-type and
resolution-integrity arms — every member whose frame was consumed whole. And §4.11's *"the
close is its own choice"* gains the qualifier it needs: the choice exists where the frame
was consumed whole, and is forced otherwise.

---

## SA-PY-61 — N4's decode boundary has one arm and a real one has two

**Status:** ✅ **CLOSED 2026-09-15 — RULED IN THIS SEAT'S SHAPE at 0.8.2.25 (§5.2a).**

> *"⚠ **The code above is THIS arm's, not the class's `[MUST]`** (0.8.2.25). `400
> hash_mismatch` answers a **resolution-integrity** refusal — a `included` key that does
> not bind to its entity. It is the wrong answer for bytes that were never hashed: a frame
> that does not decode into an Envelope at all is **`400 invalid_request`** (§4.7,
> §4.11). … Answering `hash_mismatch` to a truncated payload is the same
> code-under-the-wrong-reason defect this revision corrected when it refused
> `non_canonical_ecf`, arriving one boundary earlier inside the correction itself."*

The ruling adopts this filing's argument verbatim, including the
`non_canonical_ecf`-parallel it was built on. py's interim behaviour was the ruled
behaviour, so no code changed; `test_a_framing_failure_is_not_reported_as_a_hash_problem`'s
"if arch rules otherwise this row flips" caveat is discharged, and §4.11 is now the
normative home for the whole class (see `test_preadmission_refusal_4_11.py`).

**Original filing, for the record:**

**Sections:** `ENTITY-CORE-PROTOCOL` §5.2a (the `N4` block, 0.8.2.24)

**The ask, in one sentence:** N4 says a peer refusing at the decode boundary *"MUST emit the
coded response above"*, and the response above is **`400 hash_mismatch`** — but a real decode
boundary refuses for two different reasons, and only one of them is a hash-binding failure.

py's `recv_envelope` raises for (a) **undecodable CBOR** — a truncated or malformed payload —
and (b) **a false hash binding** (`validate_entity_hash`). Read literally, N4 answers
`hash_mismatch` to a caller whose bytes were truncated. **That is the defect arch corrected in
this same delta when it refused `non_canonical_ecf`:** *"the remedy the code selects sends an
honest caller to the wrong layer."* *Check your hashes* is the wrong instruction for *your
bytes are malformed*, and it is wrong in the same direction and for the same reason.

**`entity-core-go` does not face the choice**, which is why it did not surface there: their
edit is at `validateRecv → ValidateAll`, the hash step alone, and their own note says *"every
`ValidateAll` failure is a hash-binding failure."* True of that function. py's boundary is one
function earlier and carries both.

**What py does in the meantime:** `hash_mismatch` for the hash-binding arm (N3's actual
subject), **§3.3's declared 400 default `invalid_request`** for the framing arm. Pinned at
today's answer with this filing named in the assertion message
(`test_decode_boundary_refusal_n4.py::TestTheFramingArm`), so a ruling flips a row rather than
looking like a regression. Not settled locally: the N4 half is not in doubt either way — a
coded frame is owed and a bare close is not one — so only the *code* on the framing arm is
open, and inventing a divergence on it would be the error this repo exists to find.

**Suggested shape:** one clause distinguishing the two, e.g. *"a refusal whose cause is a false
hash binding answers `hash_mismatch`; a refusal whose cause is that the frame did not decode
answers §3.3's generic `invalid_request`."* Both remain decode-boundary refusals and both remain
subject to N4's emit-and-correlate obligation.

---

## SA-PY-60 — §5.2's scope-type ruling has two clauses, and "drop the field" discharges only the first

**Status:** ✅ **CLOSED 2026-09-14 — clause 2 WITHDRAWN at 0.8.2.24 (`N1`). The filing was
answered against us, for a reason worth keeping: a peer that does not read `scope.type` cannot
observe a contradiction in it, so the refusal obliged re-introducing the exact field whose
absence is the safety property. `entity-core-go`'s "CONFORMS, no code change" was right and
py's refusal was the change owed — removed at `411e093`. Three parties reached the withdrawal
independently (keystone's 45-peer wire census: `403` on zero of 40 driven; go's three-way
source read; arch's own line-reads). The work is not wasted: building the refusal is what
reached the real boundaries — absent ≠ contradiction, and the unit of malformedness is the
token — and it is what showed the clause was mechanism-shaped from the inside.**

*Original filing below, kept as written.*

**Status (at filing):** 🟡 **Open — py refuses (`e3e247f`); `entity-core-go` drops and filed J4 as
"CONFORMS, no code change". One of the two seats owes a change and the text decides which.**

**Sections:** `ENTITY-CORE-PROTOCOL` §5.2 "Scope types" (0.8.2.22, the J4 delta)

### The two clauses

> **The scope type is a property of the DIMENSION and is supplied by the call site `[MUST]`**
> … An implementation MUST NOT take the dispatch type from a received entity's `scope.type`
> field. **A received `scope` whose declared `type` contradicts its dimension is a malformed
> token and MUST be refused `403 capability_denied` `[MUST]`**

Clause 1 forbids *reading* the field. Clause 2 requires *refusing* a token that carries a
contradicting one. They are different obligations and only clause 1 has a mechanism attached.

### What each seat did, and why both look conformant from inside

| seat | mechanism | clause 1 | clause 2 |
|---|---|---|---|
| `entity-core-py` (before `e3e247f`) | type derived from the dimension name (`_SCOPE_TYPE_BY_DIMENSION`) | ✅ structurally | ❌ silently ignored |
| `entity-core-go` | `types.CapabilityScope` has no `Type` field; dropped at decode | ✅ structurally | ❌ silently ignored |

Both seats satisfy clause 1 **by never having built the defect**, and a seat that satisfies a
rule structurally has nothing to write — so the natural disposition is *"conforms, no code
change"*, which is exactly what go filed. The reading is not careless: it is what you reach
if the first clause is the one you can act on.

**Dropping is not refusing.** A peer that ignores a contradicting `type` accepts a token the
specification calls malformed. Nothing about clause 1's mechanism produces clause 2's
`(403, capability_denied)` pair.

### What we did

Refused, per the standing posture of building the ruling and reporting what building it finds.
`grant_declares_a_contradicting_scope_type` fails the grant closed in all four grant loops, so
no grant matches and the existing refusal path answers `403 capability_denied` — the ruling's
pair, with no second error path to maintain.

Two boundaries the implementation has to get right, and both are places a "be stricter" fix
errs:

- **An absent `type` is not a contradiction.** Every capability this cohort mints omits the
  field. A guard treating absence as malformed refuses the entire ecosystem while reading as
  strict.
- **The unit is the token, not the axis — and not the capability.** A mistyped `peers`
  dimension must refuse a *resource* read too (else the refusal is scoped to the axis rather
  than to the token, which is not what "malformed token" means). But a sound grant beside a
  malformed one still authorizes, or one bad entry silently revokes every other grant a caller
  holds.

### What upstream could rule

1. **Clause 2 binds as written** — go owes the refusal, py is conformant, and the check set
   gains a vector (a grant with a contradicting `type` on each of the four dimensions).
2. **Dropping discharges it** — then clause 2 is describing what a peer that *does* read the
   field owes, and it should say so, because as written it is addressed to every peer and two
   of two ground-up seats read it as addressed to none.

We have no stake in which; (2) costs us a revert of one guard. What matters is that the two
seats currently disagree on the wire for a token either could receive, and neither seat's
suite can see it — this is not observable without a vector that *sends* a contradicting type,
and nobody sends one by accident.

### Why no instrument found it

The field is absent from every minted capability in all three trees, so there is nothing to
observe: a dimension nobody populates cannot diverge, and a rule about it is tested only by a
probe written against the sentence. Same shape as the `protocols` field before 0.8.2.x — *a
field with no producer anywhere in the cohort is not a converged field, it is an unmeasured
one, and the first seat to implement it creates the divergence rather than finding it.*

**Enforcement point:** `tests/integration/test_scope_type_is_a_dimension_property_j4.py` —
both clauses, all four dimensions, the absent-type rows, and the two unit boundaries.
Mutation (return `False` instead of `True`, i.e. go's disposition) reddens exactly the six
clause-2 rows.

---

## SA-PY-59 — `EXTENSION-REVISION` never says which of its nineteen operations are path-authorized, and both ground-up seats derived the same 16

**Status:** 🟡 **Open — py moved 8 → 16 to match go (`8d920c4`); the residual three are
pinned at today's answer, not closed.**

**Sections:** `EXTENSION-REVISION` (all of §4) · `ENTITY-CORE-PROTOCOL` §5.2 / §6.3 / §6.8

Revision's nineteen handler operations all take their prefix from **`params.prefix`**. The
module reads `ctx.resource_targets` **zero times** (measured, and asserted structurally), so
§5.2's resource arm — conditioned on `resource_target is not null` — never runs for a caller
that simply omits the `resource` field. `check_path_permission` on the params prefix is
therefore *the only* thing authorizing a path, and **the corpus never enumerates which
operations must perform it.**

Both ground-up seats derived the set operation by operation, and both arrived at **16 of 19**,
with the same three absent:

| unchecked at BOTH seats | what an unauthorized call does |
|---|---|
| `find-ancestor` | discloses DAG structure across prefixes |
| `config` | writes the revision configuration of any prefix |
| `merge-config` | writes the §5.1 `pattern` → strategy map of any prefix |

`merge-config` is the one that is not merely a disclosure: the strategy map decides which
side wins a merge, which decides the merged bytes, which decides the **version root**. An
unauthorized write there changes what a later `merge` computes.

**Two seats converging is evidence about implementers, not about the text.** Neither seat has
a sentence to point at; both have a list they built by reading nineteen functions. What is
owed is one table in §4 naming, per operation, the permission and the subject — the same shape
`EXTENSION-TREE` §11 already carries for the tree handler (*"`diff` — operates on stored
snapshots; no path-level check"*), which is exactly the artifact that let 0.8.2.21's sweep
reason about `diff`'s exemption at all.

**Not unilaterally closed here.** Refusing where `entity-core-go` accepts manufactures a
cross-impl divergence out of a corpus gap. Pinned at today's measured answer by
`test_revision_unchecked_operations.py::TestTheThreeBOTH_SEATS_LEAVE_UNCHECKED`, whose
assertion message carries the retirement condition (*check go still agrees before shipping a
17th*) so the row fails loudly if a later seat drifts rather than decides.

**What py fixed in the meantime** (`8d920c4`): the eight it was missing relative to go —
`log`, `status`, `diff`, `fetch`, `fetch-entities`, `branch`, `tag`, `push`. `diff` was the
widest: it returns every changed path **and content hash** between two versions, the same
disclosure shape as the `snapshot` + `diff`-against-empty composition 0.8.2.21's H1 sweep
exists for, reached through a handler that sweep does not touch and **without needing an
exclude at all**.

---

## SA-PY-58 — §6.3's `handler_pattern` is a per-call-site LITERAL, the corpus writes two of them, and the census models it as one cell

**Status:** 🟡 **Open — the three sites the corpus names explicitly are landed
(`fdc6085`); the QUERY divergence (SA-PY-57) and the census axis are routed.**

**Sections:** `ENTITY-CORE-PROTOCOL` §6.3 · `EXTENSION-SUBSCRIPTION` §2.3 ·
`EXTENSION-HISTORY` §4.2 · `EXTENSION-COMPUTE` §7.2 · `EXTENSION-QUERY` §5.2 step 6b

§6.3's signature filters the caller's grants by `handler_pattern` **before** their
`resources` scope is read, so a grant scoped to a different handler is discarded without
ever being consulted. **The argument is not derivable from the dispatch — it is written as
a literal at each call site, and the corpus does not write the same literal:**

| site | literal | subject being authorized |
|---|---|---|
| SUBSCRIPTION §2.3 | `"system/tree"` | the tree read `include_payload` would push |
| HISTORY §4.2 | `"system/tree"` | the target path |
| COMPUTE §7.2 (`compute/lookup/tree`) | `"system/tree"` | the impure read |
| QUERY §5.2 step 6b | `"system/query"` | the per-result read filter |

**What is owed:** §6.3 documents the parameter and never says *who chooses it*. It reads as
a property of the dispatch (and every implementation will supply the dispatching handler if
it is not told otherwise — this one did, at three of four sites). The sentence owed is that
**the handler frame is the handler that OWNS the operation being authorized, not the handler
running the check**, with the four call sites above as the worked examples. Without it, the
argument is a per-extension convention discoverable only by reading four extensions.

**Why it matters more than a wrong constant:** the frame runs *upstream of every dimension*.
A peer with a perfect matcher and the wrong frame answers DENY on a conformant caller and
has no dimension to attribute it to — which is exactly how it was mis-diagnosed
(see the "how it was found" note below).

**Measured here** (`tests/integration/test_handler_frame_of_the_6_3_check.py`): a caller
holding §2.3's own described shape — `{system/subscription: subscribe}` **plus**
`{system/tree: get}`, separate grants, which is the only shape under which §2.3's argument
(*"a caller may legitimately hold `subscribe` without `get`"*) has any content — was refused
`403 payload_unauthorized`. History `query` refused the same shape `403 access_denied`. And
`compute/lookup/tree` omitted the argument entirely, which passes `None` and disables handler
filtering: the **widening** direction, where a grant scoped to any handler at all authorized a
tree read.

**How it was found, and this is the routable half.** `entity-core-go`'s
`include_payload_overlapping_exclude` arm measured go 403/200 · rust 403/200 · **py 403/403**
and routed the divergence to arch as an open question about §2.3's *pattern-subject*
semantics (their **Q2**), offering two candidate causes: py denies any non-concrete subject,
or py qualifies the resource differently. **Neither.** It is this argument, and §2.3 already
names it. The arm is the only one of the cohort's nine narrow-cap vectors that mints a
**split** capability; the other eight mint a single grant whose `handlers` scope covers the
dispatching handler, so they match under either frame and are structurally blind to it.

**Census consequence (→ `entity-core-keystone`).** `tools/scope-cell-table.py` models
**L2** (`check_path_permission`) with `subject: "value"` and
`polarities() -> ("include", "grant-exclude")`. Two corrections fall out:

1. **L2's `handlers` subject is a spec literal, not a request value.** `L2-HAN-IN` is one
   cell standing for four call sites that do not agree on it. Driving a check against one
   credits the cell and says nothing about the other three — and F73(a)'s
   *"driven, never name-mapped"* rule does not help, because the problem is not the mapping.
2. **L2's subject is not always concrete.** §2.3 hands it a pattern (§3.1), so L2 needs
   L1-`resources`' `grant-exclude/pattern` polarity. It does not have it, which means the
   cell SA-PY-56's defect lives in **is not in the 640 product at all** — an absent cell,
   invisible to the instrument that counts cells, which is the absent-arm law one level up.

---

## SA-PY-57 — QUERY §5.2's pseudocode and §747's prose name different handler frames, and go and py each implemented one

**Status:** 🟡 **Open — pinned at today's answer, deliberately NOT swept.**

**Sections:** `EXTENSION-QUERY` §5.2 step 6b vs §747 · `ENTITY-CORE-PROTOCOL` §6.3

§5.2's pseudocode writes the per-result path filter as
`check_path_permission("get", candidate.path, ctx.capability, "system/query", ...)` — the
**own-handler** frame, and the corpus's only instance of one at a per-entry read filter.
§747 describes the same filter as *"same pattern as tree listing"*, which is the
`"system/tree"` frame every other extension writes (SA-PY-58).

- **`entity-core-py`** implements §5.2's pseudocode: `"system/query"`.
- **`entity-core-go`** implements §747's prose: `"system/tree"`
  (`ext/query/handler.go`, `CheckPathPermission("get", path, capData, "system/tree", …)`).

Both are faithful to a sentence of QUERY. The observable difference: a caller whose `get`
lives in a `system/tree`-scoped grant gets results from go and **none** from py; a caller
whose `get` lives in a `system/query`-scoped grant gets the reverse. Neither is a defect
against its chosen reading, so **nothing was changed here** — inventing a convergence out of
a corpus contradiction is the error this repo exists to find, and the direction of the fix is
arch's call.

**No vector can see it.** `entity-core-go`'s `query_bulk_read_cap_filter` mints one grant
whose `handlers` scope names **both** `system/query` and `system/tree`, so it matches under
either frame — the *"the two vectors a row's author writes are the two on which the readings
agree"* shape, with a single grant covering both arms at once.

**Pinned** by `test_handler_frame_of_the_6_3_check.py::
TestQueryIsTheOneSiteTheCorpusFramesDIFFERENTLY`, whose rows assert the measurement rather
than the correctness and name this entry in the assertion message, so a later sweep that
"fixes the class everywhere" has to argue for moving it.

---

## SA-PY-56 — §6.3's `check_path_permission` has no pattern arm, and §2.3 routes a pattern into it

**Status:** 🟡 **Open — behaviour landed (fail-closed, a transcription of §5.2's arm), the
sentence is owed.**

**Where:** `ENTITY-CORE-PROTOCOL` §6.3 `check_path_permission` pseudocode ·
`EXTENSION-SUBSCRIPTION` §2.3 (v3.13) · `ENTITY-CORE-PROTOCOL` §5.2's `is_pattern(ct)` branch.

### The gap

0.8.2.21's `H1`/`G-4` gave §5.2's `check_resource_scope` a **pattern arm**: a pattern target
overlapping a grant `exclude` must be carved out by the caller too, else DENY. §6.3's
`check_path_permission` did not get one, in any seat, and the reason is written into §6.3
itself — its subject is *"the path this handler is ABOUT TO TOUCH"*, which reads as concrete
by construction. Its pseudocode calls `matches_scope(canonical_path, grant.resources, …)`,
whose exclude loop is a pattern-against-value test.

**`EXTENSION-SUBSCRIPTION` §2.3 is a normative call site that supplies a pattern**, verbatim:

> when `include_payload` is set, the subscribe handler MUST additionally verify the caller's
> capability covers the tree read — `check_path_permission("get", resource_path,
> caller_capability, "system/tree", local_peer_id)` — and MUST reject the subscribe with
> **403 `payload_unauthorized`** if it does not.

The subscribe resource *is* a pattern (§3.1). So the exclude loop evaluates
`matches_pattern(concrete_exclude, pattern_string)` — an exact-string comparison no concrete
path can satisfy — and the exclusion carves out nothing.

### Measured here

A grant `resources: {include: ["data/*"], exclude: ["data/secret"]}` subscribed with
`include_payload: true` on pattern `data/*` and was **accepted**. Delivery performs no second
check (§2.3's subscribe-time check is the only gate, by design), so from then on the excluded
entity's **body** is pushed to the subscriber on every write to it. Worse than a read leak on
two axes: it is a **push** channel, and it carries the body rather than a name and a hash.

### Why no seat's vector reaches it

`entity-core-go`'s `include_payload_unauthorized` mints a **subscribe-only** capability with
no `system/tree` grant at all and asserts 403 — the *neither* arm. The *both* arm (a full
`get` grant → accept) is the other one everyone writes. The discriminating vector is the one
where the two authorities **disagree** — include covers the pattern, exclude carves a child
out of it — and it belongs to both arms at once, so neither arm's author writes it.

### What we did

Transcribed §5.2's arm to §6.3. **No rule is invented**: §5.2's arm is *for each grant exclude
overlapping the target, the caller must also exclude it (or a superset), else DENY*; §6.3 has
no caller-exclude channel, so `is_covered_by(cge, [])` is vacuously false and the arm reduces
to **overlap → DENY**. Enforcement point:
`tests/integration/test_pattern_subject_at_the_handler_level_check.py`, five mutation-verified
rows including a labelled non-discriminator and an over-refusal control.

### What upstream could rule

1. **Give §6.3 the pattern arm explicitly**, reduced as above. Cheapest, and it is what all
   three seats will otherwise each derive independently — or not derive, which is the current
   state.
2. **Or rule that §6.3's subject MUST be concrete**, and fix §2.3 to check something else (the
   pattern's *include* coverage plus a per-event check at delivery). This is the larger change
   and it moves an enforcement point, so it wants to be deliberate rather than implied.

Either way the corpus should say which, because *"authorize a pattern"* and *"authorize a
path"* are different questions and §6.3's parameter is named for the second.

### Owed to the cohort

Neither sibling has the arm at this site. Whether either is *reachable* depends on their own
call graph — go's subscribe path is the one to check first, since §2.3 binds every seat.

---

## SA-PY-55 — the listing filter's authority: §6.3/§6.7 say the caller's capability, §6.8's table says the handler's grant

**Status:** 🟡 **Open — implemented as the caller's capability, which is the only reading with
a security purpose.**

**Where:** `ENTITY-CORE-PROTOCOL` §6.3 (the *Listing filter* paragraph) · §6.7's
no-read-carve-out argument · §6.8's authority table (0.8.2.21).

### The contradiction

§6.3's filter paragraph: *"each entry MUST be individually checked against **the request's
capability**"*. §6.7 leans on exactly that when it refuses a read carve-out: *"The listing
filter already checks every returned entry individually against the request's capability,
which is the read path at its highest volume."*

§6.8's table, landed at 0.8.2.21 as a `[MUST]`, assigns authority by **who named the path**:

| the handler is about to touch | the authority is |
|---|---|
| a path **the handler derived** … a merge expansion, **a listing entry**, an autonomous write | **the executing handler's own grant** |

A listing entry is named, explicitly, in the handler-derived row.

### Why it is not merely editorial

The two readings are not close. The tree handler's own grant covers what it serves, so
filtering a listing against it **removes nothing** — a seat implementing §6.8's table
literally ships a filter that is vacuous by construction, passes every teeth control a
filter-exists test can carry, and discloses exactly what the filter exists to hide.

### The reading that reconciles them, offered rather than asserted

The two sections plausibly answer *different questions*: §6.8 governs the authority under
which the handler may **touch** a derived path, and the listing filter governs what the caller
may **see**. Both then bind, with different authorities, and neither paragraph is wrong — but
§6.3's pseudocode calls one function with one `capability` parameter, so the distinction has
nowhere to live in the code as specified.

### What we did

Implemented against **the caller's capability**: it is stated twice, §6.7's argument depends
on it, and it is the only reading under which the filter does anything. Pinned by
`test_bulk_read_per_entry_filter_6_3.py::TestTheAuthorityIsTheCallers`, which holds the
handler grant **open** so the row fails on a seat that reads §6.8's table literally.

### What upstream could rule

Say in §6.8 that the listing-entry row governs the handler's own read authority and that the
**disclosure** bound is separately the caller's capability per §6.3 — or strike *"a listing
entry"* from that row. One clause either way.

---

## SA-PY-54 — §5.2's pattern arm is normative pseudocode that three helpers exist only inside, and this seat had none of them

**Status:** 🟢 **Implemented as the spec writes it. Routed as a cross-impl census request, not
as an ambiguity — the text is clear and we were simply wrong.**

**Where:** `ENTITY-CORE-PROTOCOL` §5.2 `check_resource_scope`, the `is_pattern(ct)` branch,
plus `patterns_overlap` / `strip_wildcard` / `is_covered_by`.

### What we found

§5.2's own opening comment states two arms: *"For concrete targets: check grant include
coverage + not in grant exclude. For pattern targets: check grant include coverage + every
overlapping grant exclude must be covered by a caller exclude."* We implemented the first
and fell through to it for patterns. Measured, against
`include: ["/{p}/*"], exclude: ["/{p}/data/secret"]`:

| target | measured | §5.2 |
|---|---|---|
| `/{p}/data/secret` (concrete) | DENY | DENY |
| `/{p}/data/*` (pattern, spans the exclude) | **ALLOW** | DENY |

A caller neutralizes a grant exclude by **re-spelling its own target**, needing no authority
it does not already have. `F68`'s law with the spelling of the target as the vacuum-inducing
input.

### Why it stayed invisible

`patterns_overlap`, `strip_wildcard` and `is_covered_by` had **zero occurrences** in this
repo. The arm was not weak, it was **absent** — and an absent arm has no call site for a
reviewer to find, no code for a mutation to disable, and no grep token for a census to count.
Landing it broke **no existing test** among 4580, which is the same fact from the other side.

### The ask

**Not a ruling — a census.** This is exactly the shape that a wire probe cannot see unless
someone writes a *pattern* target, and nobody writes one by accident. `CORE-RESOURCE-
EFFECTIVE-1` arm (e) drives a single pattern target at a resource-**requiring** operation,
where §3.3 answers `malformed_resource` **before** this arm is reached — so the existing
vector set cannot discriminate a peer that has this arm from one that does not.

1. **Do `entity-core-go` and `entity-core-rust` implement the pattern arm?** A grep for
   `patterns_overlap` in each tree answers it in one command.
2. **If any seat does not, a conformance vector is owed** — a pattern target spanning a grant
   exclude, at a non-resource-requiring operation, with the caller-excludes-it-too row beside
   it as the discriminating control.

### What we did

Implemented `strip_wildcard` / `patterns_overlap` / `is_covered_by` verbatim from §5.2 and
wired the arm. Enforcement point:
`tests/integration/test_resource_scope_pattern_arm.py` — the bypass, the concrete-form
control that shows it was a divergence between two spellings of one request, both allow-arms,
the non-overlapping teeth row, and the row where the caller supplies *an* exclude but not the
overlapping one. Mutation-verified RED on exactly the two predicted rows.

*Noted in passing: §5.2 writes `matches_pattern(path, pattern)` and this module writes
`matches_pattern(pattern, uri)` — reversed, consistently, at every call site here. Not a
defect and not worth a ruling; recorded because transcribing the pseudocode literally into
this tree would invert every call.*

---

## SA-PY-53 — an id-scope `exclude` can match nothing too, and 0.8.2.21's rule cannot reach it

**Status:** 🟡 **Open — deliberately NOT invented locally.**

**Where:** `ENTITY-CORE-PROTOCOL` §5.4's 0.8.2.21 unmatchable-pattern MUST, against §5.2's
two scope types.

### The gap

0.8.2.21 rules that *"a capability any of whose scope patterns **canonicalizes to
`NEVER_MATCH`** MUST be refused"*, and that an unmatchable `exclude` excludes everything.
Both are written in terms of `canonicalize`.

**`canonicalize` is never applied to an id-scope dimension.** §5.2 says in terms that *"an id
dimension canonicalized is a conformance defect"*, and 0.8.2.16 corrected the pseudocode that
did it. So `operations` and `peers` — half the grant dimensions — are outside the rule's
reach as written.

**They have the same hazard.** `id_scope_pattern_matches` admits exactly `*`, a trailing
`/*` literal segment-prefix, and string equality. So an `operations` exclude of `*/foo`, or
`/*/*`, is a literal **no operation name can ever equal** — it carves out nothing, and the
grant is silently wider than its author wrote. That is H1's sentence with `operations`
substituted for `resources`.

### Why we did not just extend it

An unmatchable id-scope pattern is not `NEVER_MATCH`; it is an ordinary literal that happens
to be unsatisfiable. Refusing it at authoring would refuse capabilities `entity-core-go` and
`entity-core-rust` mint today, manufacturing a cross-impl divergence out of a spec gap —
the error this repo exists to find in other people's stacks.

### The ask

Rule whether the H1 obligation extends to id-scope dimensions, and if so **on what
predicate** — "canonicalizes to `NEVER_MATCH`" cannot be it. The candidate is *a pattern no
value in the dimension's domain can match*, which for id-scope is decidable: any pattern
containing `*` other than as a bare `*` or a trailing `/*`.

### What we did

`_PATH_SCOPE_DIMENSIONS` in `entity_core.capability.checking` scopes the authoring refusal to
`handlers` and `resources` and says why, naming this entry. Pinned at today's answer by
`TestTheIdScopeDimensionsAreNotCovered`, whose assertion message says the row flips together
with the constant when this rules.

---

## SA-PY-52 — 0.8.2.21 enumerates three fail-open exclude sites; the handler-level check is a fourth

**Status:** 🟢 **Fixed locally. Routed so the other seats census their own fourth site.**

**Where:** `ENTITY-CORE-PROTOCOL` §5.4's 0.8.2.21 `H1`, against §6.3 `check_path_permission`.

### What we found

0.8.2.21 names three sites: *"`matches_scope`'s exclude loop (every dimension of every
grant), `check_resource_scope`'s concrete arm, and the pattern arm which is fail-closed BY
ACCIDENT via a negated test."* All three were live here.

**`check_path_permission` (§6.3) is a fourth**, with its own `resources.exclude` loop, and it
was fail-open in exactly the same way. Measured: a grant excluding `*/secret` granted `get`
on `/{peer}/secret` through the handler-level check.

### Why the fourth site is not a footnote

0.8.2.20 **withdrew** the "defense-in-depth" characterization of this check and made it *the
enforcement* for any subject derived after dispatch — *"where the dispatch-level check can be
made vacuous by caller-controlled input it is not a primary check, and the handler-level
check is the enforcement."*

So a peer that fixes the three enumerated sites has fixed the fail-open on the dispatch path
and **left it live on the path that carries the guarantee when the dispatch path has been
made vacuous** — which is precisely the composition `F68` established is reachable. The two
rulings are four days apart and the second does not cite the first.

### The ask

1. **Add §6.3's exclude loop to `H1`'s enumeration**, so a seat working from the list
   censuses it.
2. **`CORE-EXCLUDE-UNMATCHABLE-1` should drive a handler-level path**, not only the dispatch
   check — otherwise a peer with the partial fix passes the vector.

### What we did

Fixed it, at the site, with the reason at the call site rather than in a commit message.
Enforcement point:
`tests/integration/test_exclude_unmatchable_and_params_path_total_82221.py::
TestTheFourthSiteArchDidNotEnumerate`, mutation-verified RED — and **no other row in the file
covers it**, which is the measurement that says it is an independent site rather than one
rule reached three ways.

---

## SA-PY-51 — the 403 code slot has twelve spellings the corpus defines nowhere, and no row to put them in

**Status:** 🟡 **Open — routed to arch as a census. No local invention; the twelve are
ledgered at their current counts and left alone.**

**Where:** `ENTITY-CORE-PROTOCOL` §3.3's 403 row, against the owning extension tables.

### What was measured

Every §3.3 slot census this repo has run was triggered by something external naming a status
— 501 (0.8.2.7), 500 (0.8.2.8), 404 and 400 (`entity-core-go` probe families). **Nothing has
ever named 403.** Asking §3.3's own question of it — *which codes does this peer emit at this
status, and does the corpus define them?* — found **thirteen** spellings absent from both
corpora, across eight handlers.

One was a synonym and is swept (see below). The other twelve name **conditions**:

| code | × | owing |
|---|---|---|
| `no_identity` | 5 | COMPUTE — the impure-op signer check |
| `delegate_excluded` | 2 | ROLE |
| `builtin_override_prohibited` | 1 | core §6.2 |
| `identity_verification_failed` | 1 | IDENTITY |
| `quorum_publish_validation_failed` | 1 | IDENTITY |
| `quorum_update_validation_failed` | 1 | IDENTITY |
| `stale_request` | 1 | REGISTRY §6a.9 |
| `replay_detected` | 1 | REGISTRY §6a.9 |
| `registration_disabled` | 1 | REGISTRY |
| `invalid_snapshot` | 1 | REVISION (also a status smell — reads as a 400) |
| `delegation_authority_insufficient` | 1 | ROLE |
| `token_expired` | 1 | SUBSCRIPTION |

### What we did NOT do

Sweep them. §3.3's remedy for a *specific but undeclared* code is a row in the owning
extension's table — the disposition arch gave the held 500 spellings under §3a — and
inventing a per-token answer locally is where `bad_request` came from. They are ledgered
monotone in both directions (`tests/integration/test_undeclared_403_code_census.py`) so the
count cannot drift while the question is open.

### What we DID sweep, and why it is the other case

`403 forbidden`, ten sites in `tree.py` and `revision.py`, every one carrying *"Capability
doesn't grant {op} on {path}"* — **§5.2a's authz condition verbatim**. `EXTENSION-TREE` §8
and Appendix A spell that answer `capability_denied`; `EXTENSION-REVISION` §8 likewise; and
`forbidden` occurs three times in the whole corpus, all prose. §3.3 (0.8.2.4) forbids minting
a synonym for a row that has a code.

**It is ours alone, and the first version of this paragraph said it was not** — recorded
because the error is the entry's most useful half. A `grep -c '"forbidden"'` reported go 1 /
rust 4 and that reads as a cohort spelling; **walking the sites** shows go's single hit is a
test fixture (`ext/content/sequencer_test.go`, a `denyingDispatcher` stub) and rust's four are
two prose comments, one comment and one test fixture
(`extensions/content/tests/closure_integration.rs`). **Neither sibling emits it in
production.** That is AP-21's own law — *a count of the token is not a census of the slot* —
arriving inside a census written to apply it, and in the flattering direction: "everyone does
this" would have converted a local defect into a cohort convergence question and left it
open.

Worth routing anyway, smaller: **both siblings have a test fixture asserting a code the
corpus does not define.** A fixture that mints a non-conformant code is the *"our constant
against our constant"* shape one layer out — it cannot fail, and it teaches the next reader
that the spelling is available.

### What upstream could rule

For the twelve: a row each in the owning table, or the default. For the class: the 403 slot
has never had a probe family, and `capability_denied` is the one code in it a cross-impl
check would notice — **a status whose refusals are all "expected" is where an undeclared code
lives longest**, because every row that reads it is asserting the status.

---

## SA-PY-50 — §5.2's `effective_targets` returns canonical paths, and no seat implements that

**Status:** 🟡 **Open — routed. Two of three seats depart from the pseudocode identically,
independently, and for a reason the corpus itself supplies.**

**Where:** `ENTITY-CORE-PROTOCOL` §5.2's `effective_targets` pseudocode against §6.13 and
§5.4.

### The disagreement

§5.2's pseudocode canonicalizes each target and appends **the canonical form**:

```
ct = canonicalize(target, local_peer_id)
if is_covered_by(ct, caller_exclude, local_peer_id): continue
out.append(ct)
```

§6.13 then derives the register/unregister pattern from `effective_targets(...)[0]` and its
own worked example is `resource: {targets: ["system/handler/local/files"]}` — a
**peer-relative** target, against a handler whose stated derivation is the `system/handler/`
prefix. Under the pseudocode's return the value is `/{peer}/system/handler/local/files` and
that derivation does not fire.

### What both ground-up seats did

Return the **raw** survivor, decide the skip on canonical forms. `entity-core-go`
(`core/capability/check.go`, `EffectiveTargets`) says so in a comment — *"the RAW survivor is
returned so a handler retains its existing path semantics… canonicalizing the return would
double-qualify a bare target through the non-idempotent QualifyPath"* — and this repo reached
the same shape for the same reason (`normalize_uri`). **Neither seat implements the literal
`[MUST]`, and the departure is invisible to every check** because the security property is
unaffected: the skip is decided canonically, so both layers agree on *which* targets survive,
and the canonical form of the raw survivor is a member of the canonical effective set —
`subject ⊆ effective_targets` holds either way.

### What upstream could rule

Say which. Either the return is the raw survivor (and §5.2's pseudocode says so), or it is
canonical (and §6.13's example and derivation are restated in canonical form). It is a
one-line difference that nothing can currently detect, which is exactly the shape that
becomes a cross-impl divergence the first time a third seat reads the pseudocode literally —
and a seat that does will pass every vector in the F68 set.

---

## SA-PY-49 — `msp_2of3_verifier_signed_ALLOW` cannot answer the question it was prescribed for

**Status:** 🟡 **Open — routed as a check-set refinement. No local defect claimed.**

**Where:** arch `ROUTING-2026-09-10-d` §3 / the `GUIDE-CONFORMANCE` §7a.1 multi-sig note,
against `ENTITY-CORE-PROTOCOL` §1.4.

### The concern, which is correct

*"If your chain walk refuses every multi-sig root a layer earlier, your `E3` says nothing
about §1.4 — the peer is not applying the rule, it cannot verify the credential form at
all."* **True at this seat**, and this repo filed the same thing against itself on
2026-09-10 (`AGENTS.md`, *"a rule can be CORRECT and UNREACHABLE"*): the outbound gate
`_presented_credential_relaxes_peers` passes no `find_signature_by_signer`, so the chain walk
refuses every multi-signature root one layer before §1.4's root-granter rule is consulted.

### Why the prescribed diagnostic cannot detect it

`msp_2of3_verifier_signed_ALLOW` **PASSES at py**, and passing it says nothing about the
concern. Measured: `verify_capability_chain` accepts a 2-of-3 root with the verifier among
the signers (`tests/unit/test_multisig.py::test_vector2_2of3_local_signed`, green), and the
**inbound** authentication path wires the finder in (`protocol/auth.py`, `find_signature_by_
signer` passed to `verify_capability_chain`). The blindness is not "this peer cannot verify
multi-sig"; it is **one call site out of two that does not pass the finder** — and the ALLOW
row runs on the other one.

This is the §2.4b critique one axis over, and arch made it in the same packet: *"the control
is single-signature; it establishes the credential family is valid, never that the peer can
verify a multi-signature root."* A peer-wide ALLOW row establishes the peer can verify a
multi-signature root, never that **the gate under test** consults one. Both controls prove a
capability of the peer; neither proves reachability at the site.

### What we did

Nothing to build — the reachability row already exists
(`TestTheMultiGranterRootIsFailClosed::test_the_rule_is_unreachable_today_and_this_is_why`),
asserts the mechanism (the gate's source carries no `find_signature_by_signer`), and goes RED
the day a seat wires one in.

### What upstream could rule

**Make the check-set requirement a REACHABILITY assertion rather than a capability one.**
For any rule whose enforcement site can be short-circuited by an earlier refusal, the set
owes a row asserting *the rule's site is reached on the input the rule decides* — not a row
elsewhere in the peer showing the input form is supported. A capability row is satisfiable by
a peer in which the rule is inert, which is the state this note exists to detect.

---

## SA-PY-48 — §7a.1a's normalization is stated for the authorization status, and a §1.4 outbound refusal is not always one

**Status:** 🟡 **Open — routed. Local behaviour PINNED at today's answer, not settled.**

**Where:** `GUIDE-CONFORMANCE` §7a.1a (folded 2026-09-10, arch `ROUTING-2026-09-10-d` §1)
against `ENTITY-CORE-PROTOCOL` §1.4 and §3.3.

### The rule as folded

*"A handler that wraps every unsuccessful sub-dispatch in one generic failure launders an
authorization verdict into a transport fault… A §1.4 outbound refusal is an authorization
DENY whichever dimension raised it → `capability_denied`."* Implemented here at `f2bb3f1`:
`_relay_outbound_refusal` relays `403` from both arms of `system/validate/dispatch-outbound`.

### The gap

The fold's reasoning is *"regardless of which pipeline layer detected the rejection"* — a
statement about **layers** — and its remedy is keyed on **one status**. Those are not the
same set at this seat. `PD-1h` moved the foreign-namespace refusal from §5.2 authorization
(403) to §1.4 canonicalization (**400**), so a §1.4 outbound refusal can surface as a 400,
and the scaffold still wraps that as `502 reentry_dispatch_failed` — laundered in exactly
the way §7a.1a forbids, one status over, on the same gate, in the same function.

So the fold closes the arm it was measured on and leaves the arm the same seat created three
weeks earlier. This is the standing *"a fix that moves a refusal earlier retires the seam an
existing rule was standing on"* shape, arriving as a **ruling** rather than as a test.

### What we did

Relayed `403` only, and pinned the neighbouring arm with the filing named in the docstring.
Deliberately **not** widened: deciding which downstream statuses are verdicts and which are
transport is wire semantics, and inventing it locally is what this repo exists to catch other
people doing. A scaffold guessing that classification would also make two conformant peers
disagree on the same input for a reason no document names.

### What upstream could rule (either is implementable same-day)

1. **The relay is keyed on the LAYER, not the status** — any refusal produced by the §1.4
   outbound gate relays with its own `(status, code)`; `502` is reserved for *there was no
   route*. This matches the fold's own reasoning and needs one sentence.
2. **The relay is keyed on the status set** — enumerate which statuses relay. Then say what a
   400 from §1.4 becomes, because today it has no answer.

**Retirement condition:** arch states whether §7a.1a binds the outbound gate's whole refusal
set or only its 403 arm. Enforcement point:
`_relay_outbound_refusal`'s docstring + `TestTheNarrowGrantDiscriminator`'s `(403,
capability_denied)` pair.

---

## SA-PY-47 — §3.3's resource split has no owning table in `DOMAIN-LOCAL-FILES`, and two seats already agree on a spelling the corpus does not define

**Status:** 🟡 **Open — routed, deliberately NOT converged locally.**

**Found by** censusing §3.3's 400 row by the row's **input** (*an operation whose own
specification requires a resource*) after arch's 0.8.2.19 sweep generalized its scope. That
census closed nine sites in `role`/`quorum`/`attestation` and two in `system/content`; it also
reached `local/files`, and there it stops.

**The gap.** `DOMAIN-LOCAL-FILES` v1.2 requires a resource at all four operations — its
pseudocode for `read` (§4.1), `list` (§4.2), `write` (§4.3) and `delete` (§4.4) each opens
`tree_path = ctx.resource.targets[0]` — but the domain spec defines **no error table at all**,
so there is no owning-table entry for the absent case or the more-than-one case. Under §3.3's
own escape clause (*defined … in the owning domain handler's own table*) the defaults should
therefore bind: `path_required` and `ambiguous_resource`.

**What both seats emit instead:** `400 invalid_resource`, at all four sites, in
`entity-core-py` (`local_files/operations.py`) **and** `entity-core-go`
(`ext/localfiles/operations.go`). The spelling is in no §3.3 code set. And neither seat refuses
the more-than-one case at all — both take `targets[0]`.

**Why this is filed rather than fixed, and the distinction matters.** This is the SA-PY-24
shape: converging unilaterally would make our peer refuse where its sibling accepts, and
manufacture a cross-impl divergence out of a **corpus gap** — which is the error this repo
exists to find in other people's stacks. We match go byte for byte here **on purpose**, and per
the standing rule that must be *said* rather than recorded as convergence: this is two seats not
making the surface worse while a ruling is pending. It is **cohort-consistent, not conformant**,
and the agreement is evidence about two implementations rather than about the text.

**The ask, in one clause:** does §3.3's resource split bind a **domain** spec that requires a
resource and defines no error table? If yes, `DOMAIN-LOCAL-FILES` owes the two rows and both
seats owe a sweep. If a domain spec is out of §3.3's scope, say so — `invalid_resource` then
needs to be *defined* somewhere, because at the moment it is minted.

**Pinned, not left to prose:** `test_path_required_is_raised_by_the_handler.py::
TestLocalFilesIsNotInTheSetAndThisIsWhy` asserts today's answer with the filing named in the
message, so a later seat "completing the census" changes it deliberately rather than by
tidiness.

---

## SA-PY-46 — autonomous origination is IN scope per D4, and our extension pathway exempts the whole class by minting itself `peers: ["*"]`

**Status:** 🔴 **Open — measured defect in OUR tree, disclosed rather than fixed in the same
pass.** Not a spec gap: §1.4 (0.8.2.19) rules it plainly. Logged here because the fix is a
design change to a shared pathway, it is the item `entity-core-go` deliberately scoped to its
own session, and landing our own answer to *"which grant does a delivery engine spend"* ahead
of the cohort is how a divergence gets manufactured out of a ruling everyone agrees with.

**The rule.** §1.4, *What the check binds is decided by AUTHORITY PROVENANCE, not by timing
`[MUST]`*: *"a delivery engine running unattended looks like a peer acting as itself, and it is
not: an engine delivering under a credential the recipient minted is a handler spending its
grant — Dimensions 1-3 gate on that grant, and the recipient-minted credential relaxes
Dimension 4 to that recipient. **A peer MUST NOT exempt the class on the ground that no caller
was on the stack.**"* And: *"Where a delivery credential is already required to root at the
recipient — `EXTENSION-SUBSCRIPTION` §1.2's `deliver_token` — that requirement is exactly what
makes it presented authority here."*

**What we do, measured.** `Peer.build`'s `extension_execute` (`peer/peer.py`) is the pathway
every autonomous origination uses — subscription notification delivery, continuation advance,
timer poke, network retry re-arm. It hands `_dispatch_local_execute` a **self-minted
`create_full_access_grant()`** as the `caller_capability`. Both of that grant's entries carry
`peers: {include: ["*"]}` — measured, `grant_allows_peer(entry, <any foreign peer>, local)` is
`True` for both.

So the class is not *exempted by a carve-out*; it is exempted **by the value of the grant it
spends**, which is worse in exactly one way: the outbound gate runs, reads a grant, and passes.
There is no branch to find, nothing reads as skipped, and the §1.4 enforcement point we landed
this session is fully armed and measuring a wildcard. `grant.py`'s own docstring already quotes
the spec calling `peers: ["*"]` *"specifically wrong … the one direction that must not be
widened"* — for a different site, and the delivery pathway kept it.

**Note what this is NOT.** It is not go's defect. `entity-core-go` mints its `deliver_token`
**B-rooted** (rooted at the delivering peer) against `EXTENSION-SUBSCRIPTION` §1.2's A-rooted
`[MUST]`. Ours is caller-supplied by the subscriber and chain-validated against the subscriber's
identity (`subscription.py`, *"otherwise an actor could embed someone else's deliver_token"*), so
the token's **rooting** looks conformant here. The divergence go flagged for us is the wildcard,
and it is a different defect at the same seam — **the same wire symptom (Dimension 4 unenforced
on delivery) reached from opposite ends.** Three seats, three different mechanisms, one class:
go bypasses, rust is `PeerRoot`-exempt, we mint a wildcard.

**The design question, which is why this is filed and not fixed.** §1.4 says Dimensions 1-3
gate on *the handler's grant*. `extension_execute` is **one pathway serving four extensions**,
so *"the handler's grant"* is four different grants, and the pathway currently holds none of
them — it holds a peer-level system grant. Deciding what each extension's delivery grant is, and
threading the persisted `deliver_token` in as `dispatch_capability_entity`, is the work; picking
an answer unilaterally is what the *"do not invent"* rule forbids while two sibling seats are
about to answer the same question. **What is NOT in doubt and is stated as our position:** the
wildcard is wrong under any of the candidate answers, so this is a defect regardless of how the
grant question rules.

**Pinned, not left to prose.** `tests/integration/test_autonomous_origination_dimension_4.py`
asserts today's behaviour with the retirement condition in each assertion message, so the rows
**fail when the fix lands** — the SA-PY-29 shape. Nothing here is a `xfail`: an `xfail` would
flip to XPASS on the day the pathway changes for an unrelated reason and read as the claim
confirming.

**Routed to** `entity-core-go` in the 0.8.2.19 reply, with the measurement, so their three-way
board records py's mechanism rather than assuming it is theirs.

### Update 2026-09-10 — the design question is RULED, and the fix is PHASE 2, measured

**The question this entry was filed on has been answered.** Arch's
`ROUTING-2026-09-10-b` §3: *"which grant does a delivery engine spend — already ruled at
0.8.2.19 §1.4: **Dimensions 1-3 on the subscription handler's own grant; Dimension 4 relaxed by
the recipient-minted token.**"* So the hold above is retired on its own terms: we were waiting
for the cohort to answer, and it answered.

**But the ruling has two halves and only the second one supplies Dimension 4.** Arch's per-seat
worklist puts py's half — *"stop minting `peers:["*"]`"* — in the **Phase 1** column, under the
heading *"Phase 1 is independently correct and breaks nothing."* **At this seat that is false,
and it is measured rather than argued.** With `extension_execute` switched from
`create_full_access_grant()` to a peers-omitted handler-shaped grant, the cross-peer subscription
suite fails:

```
403 Outbound sub-dispatch refused: the executing handler's grant does not authorize
receive on system/inbox/http-xpeer-… in peer 2KJHcQ…'s namespace
(§1.4 PD-2, §5.2 Dimension 4 (peers), or 1-2)
```

`extension_execute` passes **no** `dispatch_capability_entity`, so there is nothing on that path
that can relax Dimension 4. Supplying it means **presenting** the persisted `deliver_token` on
the outbound delivery — which is arch's **Phase 2** (*"present-and-gate"*), and arch's own
sequencing says *"no seat presents before all three mint."* So py's cell as written is a Phase 2
change filed under Phase 1, and landing it in Phase 1 order refuses every cross-peer delivery.

**Position:** the wildcard is still wrong, we still own it, and it is **not landable until Phase
2** — narrowing the grant and presenting the token are one change, not two. Stated as a finding
about the *sequencing* of arch's table, not as a request for relief.

**Phase 1 IS landed** (`b3bcff7`): `mint_deliver_token` produces the §1.2 shape — A-rooted,
`grantee` = the delivering engine — and refuses the inert self-grant at the mint. Two premise
corrections went back with it: py had **no production mint site at all** (the only mint-shaped
surface, `create_inbox_token`, had zero callers and sat in tier 1 where the SDK cannot reach
it), and every fixture in this repo minted the **self-grant** shape that arch's table attributes
to rust.

**Retirement condition:** all three seats minting conformantly → Phase 2 opens → `peers: ["*"]`
goes, `extension_execute` spends the originating handler's grant, and the `deliver_token` is
threaded in as `dispatch_capability_entity`. `test_autonomous_origination_dimension_4.py` fails
on that day, which is the point of it.

---

## SA-PY-45 — WITHDRAWN: there is no third authority case; our reading of §1.4's granter was wrong

**Status:** ⛔ **WITHDRAWN by us, same session, before routing.** Kept rather than deleted
because the withdrawal is the useful part: *a filing is a claim, and this one was a claim about
the corpus that a trace refuted.* ·

### What it claimed, and why it was wrong

It claimed `EXTENSION-CONTINUATION` §4.2 case 3 was a **third** authority case §1.4 has no arm
for, and that PD-2 as written refuses every cross-peer continuation advance in the cohort. The
second half was true and measured. **The first half was our own defect wearing a spec
conflict's clothes.**

§1.4 says *"the capability's `granter` resolves to the target peer's identity"*. We read that as
the **leaf's** granter and implemented it. Reading `entity-core-go`'s `rexec_setup` — which is
what the failing check drives — shows the shipped shape is:

```
B (target) grants the installer   ->   the installer grants A (us)
```

`CreateChainedCapGrantedTo(b.CapEntity(), …, a.RemotePeerIdentityHash())`: the leaf's granter is
the **installer**, and only the **root** is the target. So the credential *is* presented
authority, and what refused it was our leaf reading — not a gap in §1.4.

Once the granter requirement is read as **rooted at the target** (which
`verify_capability_chain` already enforces when run in the target's frame), the case lands
squarely in the presented arm and the hold this SA proposed has nothing to cover. **It was
removed with the reading that made it necessary** — a carve-out that stops matching anything is
cover for nothing while reading as a live exception.

### The two things worth keeping

**The root reading is the safe one, not a concession.** §5.5's attenuation walk binds every
link, so a leaf can only carry what the target granted the installer. The target decided what
could be sub-delegated, at mint time. A leaf-granter check adds nothing and subtracts a shipped
conformant flow.

**How close this came to being routed as a spec conflict.** The filing was written, the hold was
implemented, tested and committed, and the argument was good enough to survive its own review —
*because the measurement it rested on was real*. What broke it was reading the sibling's check
source instead of reasoning further about our own. `A source reading gives you the site; only a
trace gives you the extent` — here the trace was of **someone else's fixture**, and it is the
thing that separated "the spec has a gap" from "we have a bug".

**The 3-way question this leaves for arch is smaller but still real**, and is folded into
SA-PY-42(c): §1.4's granter sentence admits both readings, and the leaf reading is the one a
careful implementer reaches first. One clause — *"the chain's root granter"* — closes it. go and
rust will each pick one when they land the check.

<details><summary>Original filing, for the record</summary>

**Status (as filed):** open — **fold blocker**. **Dimension 4 HELD** for the one shape. ·
**Found while:** landing PD-2 and running the cohort validator — `convergence.rexec_delivered`
went FAIL on the first run after the check landed. ·
**Spec:** `ENTITY-CORE-PROTOCOL` **0.8.2.17** §1.4 (*"The enforcement point, and the authority it
runs against"*); §5.2 Dimension 4 and its absent-field default; `EXTENSION-CONTINUATION` §4.2
case 3 and §4.3.

### The conflict, in three sentences

§1.4 defines two authorities a sub-dispatch can spend. **Ambient** — *"the sub-dispatch presents
no capability of its own and proceeds on the executing handler's grant"*. **Presented** — *"a
distinct credential minted **by the target peer**, naming **this peer** as `grantee`"*.

`EXTENSION-CONTINUATION` §4.2 case 3 ships a **third**: a cross-peer continuation advance is
authorized by a scoped `dispatch_capability` **authored by the host peer**, supplied at *install*
time by the installer and carried in the dispatched envelope's `included` per §4.3.

It is not ambient — a capability of its own is presented, and it is passed as the authority. It is
not target-minted, so the presented arm refuses it. **Both arms therefore decline it, and the
ambient arm's refusal is total**: that capability carries no `peers` scope, §5.2's absent-field
default is `{include: [local_peer_id]}`, and the dispatch is by definition at a foreign peer.

### This is measured, not predicted

First cohort-validator run after landing PD-2, against a py peer:

```
PASS convergence.rexec_setup        REMOTE §2
PASS convergence.rexec_trigger      REMOTE §2
FAIL convergence.rexec_delivered    REMOTE §3
    no delivery at result inbox after 6s (cont_inbox=0 entries)
```

The two local steps pass; the step that crosses the peer boundary does not. **18 further
`convergence` checks declare `rexec` a prerequisite and skip behind it.**

Note the shape of the evidence: our own suite was **4359 green** across the same change, because
every continuation cross-peer test in it drives a stub dispatcher — the standing *"a test that
substitutes the dispatcher cannot be evidence about the dispatcher"* hazard, hit again at the
same seam it was ratified on.

### Why we did not resolve it locally, in either direction

**We cannot mint around it.** The capability is `params.get("dispatch_capability")` — the
*installer's*, resolved from the content store at advance time. Authoring a `peers` scope into
someone else's credential is forging it.

**Refusing partitions the cohort.** go and rust had not built the outbound check when this was
written, so their peers still deliver. Taking py red on a shipped, ruled extension behaviour out
of a gap between two documents is the trade SA-PY-24 and SA-PY-29 both declined.

**Silently dropping Dimension 4 is worse than either** — a dimension that stops binding with no
record is how an enforcement point dies.

### What we did

Dimension 4 is **held** for exactly one shape: an explicitly-supplied
`dispatch_capability_entity` whose `granter` resolves to **this** peer. Dimensions 1-3 bind
normally. The negative arm is untouched — a sub-dispatch presenting nothing never reaches the
hold, and `entity-core-go`'s `dispatch_outbound_ambient_refused` passes against this peer.

`Peer._authorize_outbound_sub_dispatch` carries the reasoning;
`test_outbound_sub_dispatch_authorization_pd2.py::TestTheThirdCase` carries three rows — the hold
(which **fails when the SA is ruled either way**), a teeth row proving Dimensions 1-3 still bind
(scoped to `put`, driving `get` → 403), and a row proving the hold does not reach a
third-party-authored capability.

### What upstream could rule

1. **§4.2 case 3's `dispatch_capability` MUST carry a `peers` scope naming the target.** Cleanest
   — Dimension 4 then binds with nothing held, and the scope is minted by the party that already
   chose the target. Cost: every installer re-mints, and a stored continuation installed before
   the ruling stops advancing. Wants a migration sentence.
2. **§1.4 gains a third arm.** A locally-authored, explicitly-supplied dispatch credential is its
   own authority class, and the confused-deputy question it answers was already answered **at
   install time** — the installer's own authority was checked when the continuation was stored,
   and the target was fixed then, by them, not by a later caller. **This is the argument we find
   strongest**, and it is not special pleading for continuations: it generalizes to any credential
   whose target was bound at authorization time rather than chosen at dispatch time.
3. **Rule that §4.2 case 3 is ambient after all**, and say what its absent `peers` defaults to.

We would adopt any of the three same-day. What we would most like is for **(2)'s question to be
answered explicitly even if the answer is (1)**, because *"which authority is this?"* is now a
question with three answers in the corpus and two in the section that enumerates them.

### The cohort question that goes with it

**go and rust: you will hit this the moment you land the outbound check**, and `rexec_delivered`
is the check that will tell you. It is worth all three of us landing PD-2 before anyone rules,
because the third case is invisible from the text — both of us read §1.4's two arms as exhaustive
until a two-peer check said otherwise.

</details>

---

## SA-PY-44 — §6.3's `system/tree` examples all carry a `resource`, and no sentence says one is required

**Status:** open — filed with the 0.8.2.17 `path_required` audit. **No local change**; today's
behaviour is pinned so a ruling arriving is a visible change. ·
**Found while:** censusing the §3.3 `path_required` slot **by the row's input** after 0.8.2.17
moved the raising site into the handler. ·
**Spec:** `ENTITY-CORE-PROTOCOL` §6.3 (System Tree Handler), §3.2 path-as-resource, §3.3's
`path_required` row, §9.5a `CORE-TREE-PATH-FLEX-1`.

### The gap

0.8.2.17 says `path_required` is raised by the handler for **an operation whose own
specification requires a `resource`**. That makes each operation's own spec the authority, so
the audit is a census: for every operation, does its spec require one?

For most of the surface the answer is written down — `EXTENSION-CONTENT` §6.2/§6.3,
`EXTENSION-ATTESTATION` §6, `EXTENSION-QUORUM` §6 and core §6.2 (`register`/`unregister`) all
say so in a sentence, several of them as an explicit `MUST return 400 path_required`.

**§6.3 does not.** Every worked example in it carries `resource: {targets: [...]}`, and no
sentence requires one. Meanwhile §9.5a's `CORE-TREE-PATH-FLEX-1` speaks of *"caller-supplied
paths"*, which reads as sanctioning `params.data.path` as a path source.

### Why we did not decide it locally

`system/tree:get`/`:put` is the widest-blast-radius operation in the protocol. Requiring a
resource would refuse requests every other peer accepts, and *inventing a wire semantic out of a
gap is the error this repo exists to find in other people's stacks* — the same trade SA-PY-24
declined. Adding it "to be safe" is the direction that partitions the cohort.

This peer therefore still takes the path from `ctx.resource_targets[0]` when present and falls
back to `params.data.path` when absent, and
`test_path_required_is_raised_by_the_handler.py::TestTreeIsDeliberatelyOutOfTheSet` pins that,
with the retirement condition in the assertion message.

### What upstream could rule

1. **§6.3 requires a resource** — then both tree ops join the `path_required` set, and the
   ruling needs to say what happens to `params.data.path` (ignored? a 400?). This is a
   behaviour change at every seat and wants a cohort measurement first.
2. **§6.3 does not require one, and says so** — one sentence, and the census stops being
   ambiguous. `CORE-TREE-PATH-FLEX-1`'s *"caller-supplied paths"* already leans this way.

We have no stake in which. **(2) is what the corpus currently implies and we would adopt it as
a no-op.** What we would like either way is the sentence, because *a requirement stated only by
example is one three seats will read three ways* — and the two of us who read it the same way
would never find out.

### The cohort question worth asking with it

go and rust: does your tree handler accept `params.data.path` with no resource? If all three
accept, (2) is ratifying what the cohort does. If one refuses, that is a live divergence on the
most-dispatched operation there is, and nothing in the conformance corpus would surface it —
every vector we have carries a resource, because every example does.

---

## SA-PY-43 — `attestation:supersede`/`:revoke` satisfy their resource MUST by delegation, so the check runs after their own validation

**Status:** open — filed with the 0.8.2.17 `path_required` audit. **No local change**; the
ordering is pinned at today's answer. ·
**Spec:** `EXTENSION-ATTESTATION` §6 (*"Calling `system/attestation:create` (or `:supersede` /
`:revoke`) without a resource MUST return 400 `path_required`"*), `ENTITY-CORE-PROTOCOL` §3.3.

### The gap

`:supersede` and `:revoke` are convenience wrappers that build an attestation and delegate to
`:create`, which is where the resource check lives. So the MUST is satisfied — for a request
whose *only* fault is the missing resource.

An input faulty in **two** ways answers the other fault. `:supersede` with no resource and no
`previous_hash` answers `400 invalid_params`; with a `previous_hash` that resolves to nothing it
answers `404 previous_not_found`. Both are defensible and neither is written down.

### Why this is a spec question rather than a local one

This is the shape `EXTENSION-TREE` Appendix A's two `put` rows had (SA-PY-41's sibling finding):
a table that is **individually satisfiable and jointly ambiguous**, whose discriminating input is
the one no row-scoped author writes, because it belongs to two rows at once. There the answer was
a ruled order. Here there is not yet a question on the board.

Reordering on our own authority would make this peer refuse in an order two conformant siblings
do not, on an extension whose error table is otherwise fully pinned — manufacturing a divergence
out of an unstated ordering.

### What upstream could rule

Either order, stated. Our weak lean is **resource first**: it is the cheapest check, it needs no
store lookup, and *supply a resource* is actionable without the caller having to fix anything
else first. But the opposite (validate what you were given, then check how it is addressed) is
equally coherent, and the value is in the sentence, not in which way it goes.

---

## SA-PY-42 — PD-2's presented-authority arm leaves two values undefined that an implementation must supply

**Status:** open — filed on landing 0.8.2.17. **Both calls are implemented**, fail-closed, and
each is pinned by a row that fails if the ruling goes the other way. ·
**Found while:** building §1.4's outbound sub-dispatch check (PD-2). ·
**Spec:** `ENTITY-CORE-PROTOCOL` **0.8.2.17** §1.4 *"The enforcement point, and the authority it
runs against"*; §5.2 `check_permission` / Dimension 4; §5.5 root-authority rule.

### The gap

§1.4 requires `check_permission` to run **before a locally-originated sub-dispatch leaves the
peer**, *"with all four dimensions applied"*. `check_permission(execute, capability,
handler_pattern, local_peer_id)` takes two values that an **outbound** call site cannot get the
way the local one does.

**(a) Which `handler_pattern`?** On the local arm it is the *resolved* pattern from the §6.6 tree
walk. A remote peer's handler table is not resolvable from here — that is the whole point of the
dispatch being outbound — so there is nothing to resolve and the spec does not say what to
substitute.

**(b) In whose frame is the presented capability evaluated?** §5.2's Dimension 4 default for an
absent `peers` field is `{include: [local_peer_id]}`. A target-minted credential normally carries
no `peers` field at all. Evaluated in the **dispatcher's** frame that default is `{include: [us]}`
tested against a target of `them`, so **the presented arm would refuse every credential it exists
to accept** — including the one `t1_2_concurrent_reentry` drives. The arm is unimplementable
under the reading that comes first.

**(c) Leaf granter or chain root?** §1.4 says *"the capability's `granter` resolves to the target
peer's identity"*. Read as **the leaf's own granter**, a capability the target *delegated* through
a third party is not presented authority. Read as **the chain's root**, it is.

**We took the leaf reading, shipped it, and it was wrong — measured, not argued.** It is the
reading a careful implementer reaches first, and it refuses the shape the cohort has shipped all
along: `EXTENSION-CONTINUATION` §4.2 case 3's cross-peer dispatch capability is minted
`B (target) -> installer -> us`, so its **leaf** granter is the installer and only its **root** is
the target. Under the leaf reading, every cross-peer continuation advance in the cohort is
refused. Measured as `convergence.rexec_delivered` FAIL against a live two-peer harness, which
additionally skipped the ~20 checks declaring it a prerequisite (pass 1 total `1637 -> 1617`), and
confirmed by a control run with the check disabled (`PASS`, `convergence` 30/30).

**Now implemented as the root reading**, which `verify_capability_chain` already enforces when run
in the target's frame. It is also the safe one: §5.5's attenuation walk binds every link, so a leaf
can only carry what the target granted the installer. *(This retires SA-PY-45, which we filed and
withdrew in the same session on the strength of the trace — see that entry; the withdrawal is
recorded because the filing was persuasive and wrong.)*

**What we still want ruled:** one clause. *"the chain's root granter"* in §1.4 closes it. **go and
rust have not landed the outbound check yet and will each reach this fork independently** — the
leaf reading is the one that reads naturally from the sentence, so the likely outcome without a
clause is that at least one seat ships it and discovers it exactly as we did.

### What we did

Fail-closed on all three, each with the reasoning at the call site
(`Peer._authorize_outbound_sub_dispatch`, `Peer._presented_authority`):

1. **`handler_pattern` = the peer-relative path the uri names** (`extract_handler_path`). It is
   the only value available locally; it is what a grant author writes into a `handlers` scope;
   and it errs toward **refusal** — a grant naming exactly `system/tree` covers a uri naming
   exactly that handler, while a deeper path needs a `/*` scope.
2. **The presented capability is evaluated in the TARGET's frame** (`local_peer_id =
   target_peer`), which is the same frame the chain is verified in and the same answer the
   credential gets when it arrives at the target and is checked there. This is §1.4's own
   reasoning restated as a frame: the question the arm asks is *would the target authorize
   this?*, and the target answered by minting it.
3. **`granter` is the leaf's own granter.**

Rows: `tests/integration/test_outbound_sub_dispatch_authorization_pd2.py` —
`TestThePresentedArm::test_a_capability_the_target_DELEGATED_is_not_presented_authority` is (3)
and is the row that changes if arch rules the other way; the frame call (2) is what
`test_a_target_minted_capability_authorizes_what_the_grant_refuses` measures, and reverting it
turns that row **and** the §7a reentry probe red.

### What upstream could rule

- **(a)** name the substitute explicitly. A sentence in §1.4 is enough. Our reading is the
  conservative one but three seats picking three substitutes is a silent ALLOW divergence, and it
  is invisible to any probe: an over-permissive substitute passes every check anyone writes,
  because a check that dispatches successfully cannot tell you the grant was read too loosely.
- **(b)** say the presented arm evaluates in the target's frame — or, if not, say what the
  absent-`peers` default means for a credential minted by a peer other than the evaluator.
  **Something has to give here; the arm does not work otherwise**, so this is less a preference
  than a gap that every seat will close the same way and none will write down.
- **(c)** leaf-granter or chain-root — **and this one is no longer a preference**: the leaf
  reading is measurably wrong against the shipped corpus, so what is wanted is the clause that
  stops the next seat implementing it.

### The cohort question worth asking with it

**Neither go nor rust had built the outbound check when this was written** (go's `local.go`
returns at `RemoteExecute` with no check in front of it, read at their HEAD), so all three seats
are about to make these three choices independently, from a text that does not contain them.
That is the cheapest possible moment to rule: nobody has shipped a divergence yet.

---

## SA-PY-41 — `EXTENSION-TREE` Appendix A row 1 tabulates *"does not decode"* and no document defines the predicate

**Status:** ✅ **RULED and CLOSED 2026-09-06** — `ENTITY-CORE-PROTOCOL` **0.8.2.11** §6.3 ·
`EXTENSION-TREE` **v4.5** Appendix A · `SDK-OPERATIONS` §3.2 · `ENTITY-NATIVE-TYPE-SYSTEM` §2.8.
Adopted here; see *"How it was ruled"* below. Filed and ruled inside one day. ·
**Found while:** fixing the row-1 defect `entity-core-go` drove and measured
(`tree_put_error_codes.go`, report `2026-09-05-b`), then walking the row as a **predicate**
rather than as the one input their probe seeds. ·
**Spec:** `EXTENSION-TREE` **Appendix A** `put`/`set` rows (v4.4); V7 §3.3's 400 default; V7 §1.8 /
v7.69 §4.5a (authored `content_hash`) ·
**Read at:** arch `HEAD` (EXTENSION-TREE v4.4) · go `core/tree/handler.go` + `core/entity/entity.go`
+ `core/hash/hash.go` · rust `core/tree/src/lib.rs` (`decode_entity_from_cbor`) ·
**every go column below is DRIVEN against a live `entity-core-go` peer at `69ec9e2`**
(`tests/interop/test_go_peer_tree_put_decode_predicate.py`, 6/6), not read — *a source reading
gives you the site; only a trace gives you the extent*, and a claim about a sibling's behaviour
routed on a source read is what that law forbids. The reading and the trace agreed here, which is
worth stating because it usually does not.

### The gap

v4.4 gave `put` its first error rows and row 1 reads:

> The submitted entity does not decode. The generic structurally-invalid case.

**Nothing in the corpus says what decoding is.** In Go and Rust it is a language event — a typed
decode into `Entity { type: string, data, content_hash }` — so each seat's *type system* answers
the question, and the two type systems answer it differently. In Python `cbor2` returns a native
mapping and there is no event at all, which is why this seat had to write the predicate down as a
function and discovered there was nothing to write it *from*.

The result is that the three seats agree on the row's **code** and disagree on its **extension**.
Measured, first-hand, in all three trees:

| Submitted `entity` | go | rust | py (before) | py (now) |
|---|---|---|---|---|
| not a map | `400 invalid_request` | `400 invalid_request` | **`500`** | `400 invalid_request` |
| `type` absent | `400 invalid_request` | `400 invalid_request` | **`500`** | `400 invalid_request` |
| `data` absent | `400 invalid_request` | `400 invalid_request` | **`500`** | `400 invalid_request` |
| `type` not a text string | `400 invalid_request` | `400 invalid_request` | **`200` — stored** | `400 invalid_request` |
| `content_hash` unparseable | `400 invalid_request` | `400 invalid_request` | `400 hash_mismatch` | `400 invalid_request` |
| **`content_hash` absent** | **`400 hash_mismatch`** | `200` — authored | `200` — authored | `200` — authored |
| **`type` is `""`** | **`400 invalid_request`** | `200` | `200` | `200` |
| `data` is `null` | `200` | `200` | `200` | `200` |

The first five rows are ours and are fixed (see below). **The two bold rows are the filing**, and
the last row is the control that keeps the guard from over-reaching.

### Why the `content_hash`-absent row is not a curiosity

It is a live cohort break, and it breaks *our SDK against a go peer*. `EntityClient._put` sends
`{"type": …, "data": …}` with no `content_hash` — which rust names as a supported, deliberate case:

> `content_hash` absent stays supported and computes under the local format: that is an entity
> being authored here, not one being carried.

go has no such arm. A missing `content_hash` decodes to the zero `Hash`; `hash.Validate` recomputes
under format `0x00`, compares against zero, and reports `ErrHashMismatch` → `400 hash_mismatch`.

**Driven, not inferred, and at two levels.** Against a live go peer at `69ec9e2`: the bare payload
answers `400 hash_mismatch`, *and* `EntityClient.put(...)` — the real SDK over a real connection —
raises a `400`. Both rows are asserted, because a payload-shape row alone leaves open that some SDK
layer adds the hash on the way out, and reading `_put` to check would be the source read the trace
exists to replace.

**Nothing in the cohort measured it, and the reason generalizes.** Every probe on every seat builds
its entity through a constructor that computes a hash (`entity.NewEntity`, `Entity::new`,
`Entity.from_dict(...).compute_hash()`), so the absent arm is *unreachable from the harness* — the
standing *"a field with no consumer anywhere in the cohort is an unmeasured field"* shape, with a
field that is present everywhere and **omitted** nowhere a test looks. go's own row-1 vector
(`entity = 42`) cannot reach it either, because an integer has no fields at all.

There is a real question under it, which is why this is a filing and not a bug report: **is `put`
a wire-receipt path (§1.8: validate the carried hash, never recompute) or an authoring path
(§4.5a: the submitter chooses the format)?** rust's comment answers *both, decided by presence*.
go's code answers *receipt only*. The spec says neither, and the two answers are not reconcilable
by being careful.

### The `type: ""` row

go refuses it — but not as a decode failure. An empty string decodes into `type: string` perfectly
well; go reaches the refusal through `entity.Validate`'s separate emptiness check and maps that
onto row 1's code. rust's `decode_entity_from_cbor` accepts it (`v.as_text()` → `Some("")` survives
the `ok_or_else`). No sentence in the corpus requires a non-empty type.

### What we did

**Fixed the five rows where both siblings already agree, and changed nothing on the two where they
do not.** `validate_entity_structure` (`entity_core/protocol/framing.py`) is deliberately the
**intersection** of what go and rust refuse, so adopting it cannot make this seat the outlier on
any shape. The two divergent rows are pinned at today's answer with the filing named in the
assertion message, so a later seat cannot tidy one closed without a ruling
(`tests/integration/test_tree_put_error_rows_appendix_a.py::TestTheDivergencesAreRoutedNotSettled`).

Two of the fixed rows are worth naming separately because they are not what was routed:

- **`type` not a text string was a `200`.** The entity was stored and bound under an integer type
  — a value no typed peer can decode, published into the tree by the peer that accepted it. A
  status-keyed census cannot see this row, because it is not an error at all; only the drive finds
  it. This is the *code slot vs. the row's input* law (AP-21's next turn) with a **success** as the
  hiding place.
- **The ORDER between Appendix A's two 400s is the split they exist to express.** A malformed
  entity carrying a hash satisfies both row descriptions. py validated the hash first and answered
  `hash_mismatch`; both siblings decide structure first. go recorded this same finding about their
  own tree in cycle 4 (*"`Validate` checks structure before hash — flipping wholesale to
  `hash_mismatch`, as the worklist prose read, would mis-code the structural case"*), and it is
  reached here independently. **Row 1 and row 2 are ordered, and Appendix A does not say so.**

### What upstream could rule

1. **Define the predicate**, once, in the row or beside it: *an entity decodes when it is a map
   carrying a text-string `type` and a present `data`.* That is the intersection three seats
   already share and it costs one sentence.
2. **Rule the `content_hash`-absent arm** — receipt-only (go) or presence-decided (rust, py). This
   is the one with a caller-visible consequence today: a py or rust SDK cannot `put` to a go peer.
3. **Rule `type: ""`** — either it is structurally invalid (go) or it is a legal type name (rust,
   py). Either answer is fine; the current state is that one seat refuses a write the other two
   commit.
4. **State the ordering in Appendix A**: structure is decided before the hash, so a submission that
   is both malformed and mis-hashed is row 1. Without it, the two rows are individually
   satisfiable and jointly ambiguous, and every seat has to rediscover the order from the failure
   mode of getting it wrong.

### How it was ruled — all four asks, and the one that did not go either way it was posed

`ENTITY-CORE-PROTOCOL` **0.8.2.11** §6.3 · `EXTENSION-TREE` **v4.5** Appendix A ·
`SDK-OPERATIONS` §3.2 · `ENTITY-NATIVE-TYPE-SYSTEM` §2.8. Adopted here at this commit.

**The predicate was never missing.** §3.9 types `put-request.entity` as `core/entity`, and
`ENTITY-NATIVE-TYPE-SYSTEM` §8.1 declares that type with **three fields and no `optional` marker
on any of them** — so *"does not decode"* means *"is not a `core/entity`"*, and that one sentence
answers asks 1, 2 and 3 together. Six homes in the corpus carry the strong form. §2.8 — *the only
table in either repo describing what is on the wire at a `core/entity` slot*, i.e. exactly this
surface — carried `content_hash?`, and was corrected in the same fold with an added sentence
naming §8.1 as its authority. **A restatement that does not name its authority is invisible from
the authority**, which is why the fix was two edits.

**Ask 2 (the `content_hash`-absent arm) is where the filing was wrong, and instructively so.** We
posed it as *receipt path **or** authoring path — pick one*. Both exist; they are at **different
layers**, and the corpus already said where. `SDK-OPERATIONS` §3.2 is `put(path, type, data) →
hash`: an unhashed payload in, a content hash out, and **the SDK cannot return a hash it did not
compute**. That construction *is* the authoring step; the wire operation it dispatches to is a
receipt path (§1.8 item 1); the two compose exactly. §4.5a, which we cited as the authoring
authority, governs *which format an author uses* and presupposes an author — it says nothing about
whether a receiver may become one.

So the ruling is not go's answer or ours. **Every seat was non-conformant, in three different
places:** go refused correctly with the wrong code (`hash_mismatch` where an absent required field
is step 1's `invalid_request`); rust and py authored on the wire; **and both rust's and py's SDKs
stripped the hash** — rust's `build_put_params` holds a non-optional `content_hash` on the
`Entity` it is handed and drops it. At each of the two seats the lenient peer and the stripping
SDK sit **in the same tree**, so the round-trip is perfect and neither suite can see it. That is
why the filing's own table has `200 — authored` in both the rust and py columns and reads as
agreement: it was a compensating pair, twice.

**Asks 3 and 4 landed as filed.** `type: ""` is `400 invalid_request`, derived from §2.7 (*"the
name is the interop contract"*) plus 0.8.2.4's precedent that a present-but-empty `protocols` is
*"a malformed request"* — an empty interop contract is not a contract. The ordering is stated, and
better than we asked: it is a **data dependency, not a convention** — step 2's inputs are exactly
what step 1 establishes, so the order was never available to choose. §9.1's lowest-numbered-
failing-step discipline for the §4.6 ladder is the same rule one section over.

**And a row nobody asked for.** v4.5 adds a fourth `put` row — `400
unsupported_content_hash_format` for a hash that is well-formed but names a format code the peer
cannot verify — restated from §4.7 row 5 *"because `put` is one of its ingest surfaces"*. It
**corrects a row this filing got wrong**: our table above puts *"`content_hash` unparseable"*
entirely in row 1, and an unallocated format code belongs in row 4. §4.7 row 5's own note says so
(*"reachable on any frame carrying an unallocated format code"*).

### What we did on the ruling

- **SDK first, peer second** — the flag-day order arch names, because landing peer strictness
  first breaks our own round-trip mid-change. `EntityClient._put` constructs the entity and
  computes the hash; `system/tree:put` gained step 1b and **lost its authoring arm**.
- **Two in-tree submitters that are not the SDK** had to construct too, and neither is reachable
  from `entity_sdk`: compute's `store` builtin, and every test that hand-built a payload.
  `system/storage:write` is a pass-through and correctly now forwards a refusal — though a
  codeless one, which is SA-PY-34's known `ExecuteResult` gap made reachable.
- **10 of 4289 tests armed the newly-invalid form**, and one asserted it as the contract
  (`test_put_authors_a_hash_when_none_is_carried`). That is the standing *"count how many existing
  tests construct the newly-invalid form — a large number is evidence about your fixtures, not
  about the rule"* measurement, and the inverted row now carries the old docstring and why every
  clause of it was true about `Entity` and false about `put`.
- **Driven across the boundary**, which is the only place the SDK half is observable:
  `tests/interop/test_go_peer_tree_put_decode_predicate.py` against a live go peer at `b353351` —
  the row that asserted *our SDK cannot `put` to a go peer* now asserts that it **can**, and that
  the hash the go peer binds is the one we authored.

### One row still open, routed rather than absorbed — v4.5 row 4 at go

Measured at go `b353351`: a `content_hash` of `0x02‖64 bytes` (allocated ECFv1-SHA-512, outside
both peers' supported set) and one of `0x7f‖32 bytes` (unallocated) both answer **`400
invalid_request`** where v4.5 row 4 pins `unsupported_content_hash_format`. Traced, not read off
the source: `core/tree/handler.go:464-467` branches on `errors.Is(err, hash.ErrHashMismatch)` and
sends everything else from `entity.Validate()` to `invalid_request`, while `hash.Validate` →
`ComputeFormat` → `OfBytes`'s `default:` arm already returns `ErrUnsupportedContentHashFormat`.
The code go mints is reached and then flattened one frame later by a catch-all.

**This is not a defect go was told about** — `bed12bb` implements the arm their worklist named, and
row 4 landed with v4.5 after it. It is the standing *walk every row when a sibling reports N* shape
seen from the other side: the row nobody was assigned is where a seat stays non-conformant after
the cross-drive goes green. The probe asserts the **ruled** pair rather than go's current answer,
because this is ruled rather than divergent, and it therefore fails until go lands it.

---

## SA-PY-40 — the 500 slot got its enumerated set; the **400 slot** is the same shape and no seat has walked it

**Status:** 🔵 **OPEN — filed 2026-09-04.** ·
**Found while:** walking `EXTENSION-TYPE` v1.3 Appendix A row by row after the fold, against all
three trees — the *"when a sibling reports N rows, walk every row"* rule applied to a table that
had just come into existence. ·
**Spec:** V7 §3.3's 400 row and its default-code force (0.8.2.7/0.8.2.8); `EXTENSION-TYPE` v1.3
Appendix A; `EXTENSION-TREE` Appendix A; `EXTENSION-REVISION` §2.3 ·
**Read at:** core-protocol `7ac75fd` (0.8.2.8) · arch `c07f282` · go `c14a1d3` · rust `27a1dc3`

### What the fold changed, and the obligation it created without naming it

`0.8.2.8` enumerated the 500 row's specific codes and the cohort swept its 500 slot. **The 400
row works the same way** — a named default (`invalid_request`), an enumerated specific set
(`invalid_path`, `invalid_params`, `unexpected_params`, `chain_depth_exceeded`,
`signature_path_conflict`), per-extension tables, and §3.3's *"an undefined spelling is
non-conformant."* **No seat has run the 400-slot census.**

And a new table creates the obligation retroactively: a code that was merely *undeclared* while
its extension had no table becomes *undefined against an existing table* the moment one lands.
`EXTENSION-TYPE` Appendix A landed this fold.

### Measured, both directions

**`entity-core-go`'s type surface, at their `c14a1d3`** — four spellings, twelve sites, none in
Appendix A and none anywhere in either corpus:

| Code | Sites | Appendix A row that covers the condition |
|---|---|---|
| `decode_error` | `adopt.go:30`, `analysis.go:17,40`, `converge.go:24`, `reconcile.go:31`, `validate.go:26`, `constraint/handler.go:71` | row 1 → `invalid_request` |
| `invalid_entity` | `validate.go:33` | row 1 (*a required field absent — `entity`*) → `invalid_request` |
| `encode_error` | `adopt.go:59`, `converge.go:40`, `reconcile.go:65` | last row → `internal_error` |
| `invalid_strategy` | `reconcile.go:42` | **no row** — the fold answered §6a.4 by omission |

The first three were already routed: the proposal's §6a.4 says *"`decode_error` and `encode_error`
are undeclared at their statuses and there is nothing to declare them **as** — they are the
generic case … go aligns; nothing new is minted."* That is a fourth ruling in the same fold, and
go's cycle-2 pass implemented the other three. **It reads green because go's own type gate
(`op_*_roundtrip`, `op_*_missing_type_404`) drives neither a decode failure nor a bad strategy** —
the under-scoped-gate law they ratified this session, applied to the gate they wrote.

**And ours, disclosed in the same breath because it is the same defect class.** py emits `400
invalid_strategy` at two sites whose owning tables define no such row:

- `revision.py:1748` — the **`merge`** operation. `EXTENSION-REVISION` §2.3 pins `400
  invalid_strategy` at **`merge-config`**'s config-write, which is a different operation.
  (`revision.py:3725`, the config-write site, is correct and unchanged.)
- `tree.py:762` — the **tree** handler's merge. `EXTENSION-TREE` Appendix A is the owning table
  and contains **zero** occurrences of the code.

Neither sibling emits it at either site.

### What we did

**Nothing, and the reason is this fold's own precedent.** `backend_error` was in exactly this
position last cycle — a useful specific code an implementation minted for a condition its
extension owns, with no table row — and arch **defined** it rather than sweeping it
(`EXTENSION-DISCOVERY` v1.2 Appendix A, alongside a tabulated `unknown_backend` at 400). A closed
strategy enumeration is the same shape. Converging to `invalid_request` unilaterally would delete
a distinction a caller can branch on, in the one direction that is hard to undo.

**Retirement condition, written so nobody re-litigates it:** when TREE and REVISION either
tabulate a strategy-rejection row for `merge` or decline to, we take the answer in the same
session — bless it and the two sites stand; decline and both move to `invalid_request`.

### What upstream could rule

1. **Run the 400-slot census cohort-wide**, the way the 500 slot was run. It is the same command
   at each seat and it is the only way to find the rows a table's arrival made non-conformant.
2. **Tabulate or decline the strategy-rejection row** for TREE `merge` and REVISION `merge` —
   `invalid_strategy` already exists in the corpus for the sibling operation, so this is a
   scoping decision, not a new code.
3. **State the general rule once:** *a table landing makes previously-undeclared codes in that
   handler's surface undefined, and the owning seat owes a sweep in the same cycle.* The
   obligation is currently implicit, which is why three implemented rulings and a fourth
   un-implemented one shipped in the same commit.

---

## SA-PY-39 — `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §3 row 2 is implemented by zero of three seats

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-04, same day** — `EXTENSION-TYPE` **v1.3**
Appendix A collapses rows 1 and 2 with our argument verbatim: *"In a typed decoder there is no
seam between them — both arrive at the same site, and no implementation emits a distinct code."*
`invalid_params` is explicitly retained as a valid §3.3 code *"for surfaces that can separate the
two; this operation set is not one of them."* **py was already conformant; nothing changed here.**
The adjacent row below moved too, and it moved against `entity-core-go` — see the note at the end. ·
**Found while:** landing the §6a.3 `type_not_found` alignment `entity-core-go` routed, and
walking the rest of the proposal's table rather than only the rows their gate drives. ·
**Spec:** `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §3 (DRAFT) ·
**Read at:** arch `d8ddb8a`, go `c42bbf3`, rust `f0a399b`, py `4c87a41`

### The row

§3's table splits the params class in two:

| Failure | Code | Status |
|---|---|---|
| Params undecodable as the declared request type | `invalid_request` | 400 |
| A required params field absent (`entity`; `type_a`/`type_b`) | **`invalid_params`** | 400 |

### The measurement

**No seat emits `invalid_params` anywhere in its type extension**, censused first-hand:

| Seat | 400 spellings in the type surface |
|---|---|
| `entity-core-go` (`ext/type/`) | `decode_error` ×7 · `invalid_request` ×3 · `invalid_entity` · `invalid_strategy` |
| `entity-core-rust` (`extensions/type-system/`) | `invalid_request` ×8 |
| `entity-core-py` (`type_handler.py`) | `invalid_request` ×7 |

rust's eight are the same sites the proposal's §1 cites as `bad_request` — including *"type_a
and type_b required"*, which is row 2 by name — and they moved to `invalid_request`, not to
`invalid_params`. So folding §3 as written makes **all three** seats non-conformant on row 2
on the day it lands, and the seat that produced the failure set is one of them.

### Why the row cannot be implemented as split

**Rows 1 and 2 are not separable in a typed-decode implementation.** go decodes params into a
declared request struct, so an absent required field *is* the decode failure — hence one
spelling (`decode_error`) for both rows. rust is the same shape with a different word. Only a
peer that decodes loosely and then checks fields, as this one does, can even reach a state
where the two are distinguishable — and it still spells them alike, because the distinction is
not one a caller branches on: both mean *fix your request*, neither is retryable, and neither
carries a different recovery.

The row is derived from the declared request type rather than from a failure, which is the
exact provenance §4 warns about (*"a derived failure set is a claim about what these operations
can fail on"*) and §6 item 2 applies to the operations nobody had built. §6a corrected the
premise for the *operations*; the **rows** were never re-derived against the three builds it
found.

### What we did

**Nothing.** py already answers `400 invalid_request` at all seven sites, which is rust's
answer and one of go's two. Moving to `invalid_params` would make this seat the only emitter of
a code no other peer produces, out of a DRAFT row, which is the shape this repo exists to find
rather than to add.

### What upstream could rule

1. **Collapse rows 1 and 2 into one `400 invalid_request` row** — matches rust exactly, matches
   py exactly, matches go's `invalid_request` sites, and leaves go one sweep (`decode_error` →
   `invalid_request`) that they already owe under §3.3's undefined-spelling rule.
2. **Keep the split and say which side a typed decoder falls on** — implementable, but it makes
   the code depend on the implementation's decode strategy rather than on the request, which is
   cross-impl-observable and decided by a language choice.

We would adopt (1) same-day. It is the only one of the two that a peer cannot get wrong by
being written in Go.

### The adjacent row, worth ruling in the same pass

§6a.4 asks go whether `invalid_strategy` and `invalid_entity` *"name distinct failures a caller
would branch on."* They are also **divergences nothing measures**: `reconcile` with a
`strategy` outside `{intersect, union, prefer}` answers `400 invalid_strategy` at go and `400
invalid_request` here, and go's `op_*_roundtrip` / `op_*_missing_type_404` gates drive neither.
Our position: the enum is closed and named in the result of the refusal's message, so
`invalid_request` carries everything a caller can act on — but we hold no stake, and either
answer is cheap for us. What is not cheap is leaving it unmeasured on a surface where two seats
already answer differently.

---

## SA-PY-38 — `EXTENSION-TYPE` §8.5 is occupied, so the taxonomy's target anchor resolves to the wrong rule

**Status:** ✅ **RESOLVED 2026-09-04, same day** — the fold landed the table as `EXTENSION-TYPE`
v1.3 **Appendix A**, not as §8.5, so the collision never happened and `system/type/violation`
keeps its section. Both seats' call-site citations move to Appendix A. **The retirement condition
fired as written.** · **Concurred with `entity-core-go`'s routing of the
same collision; filed here because we cite the anchor at a call site.** ·
**Found while:** citing the ruling in `type_handler.py` and checking the anchor before writing
it into a comment. · **Spec:** `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` (Target: *"new §8.5"*)
vs `EXTENSION-TYPE` §8.5 · **Read at:** arch `d8ddb8a`

### The collision

The proposal's header declares **Target: `specs/extensions/EXTENSION-TYPE.md` — new §8.5
(operation error codes)**. `EXTENSION-TYPE.md:1095` already reads `### 8.5 system/type/violation`,
and §8.1–§8.4 are likewise occupied by supporting type definitions. A grep of the spec for
`type_not_found`, `OP-3` or the §6a.3 rows returns nothing.

So a reader sent to *"§8.5"* today gets the violation type — a **supporting type definition** —
rather than an error-code table, and the two are not confusable enough to notice: both are
plausible things for a section named §8.5 to be.

### Why it is worth a filing rather than a note

The code comment at our refusal site has to cite something, and this is `COHORT-OPEN-ITEMS`
OP-3's first worked instance — the fold's whole point is to give the row a home so that
0.8.2.7's escape clause (*"defined for the operation in a spec code set"*) has something to
point at. **A citation to an occupied anchor is worse than a citation to a DRAFT**, because it
resolves, silently, to a rule about something else.

### What we did

Cited the **proposal** at the call site, explicitly not §8.5, with the collision named in the
comment so a later seat "tidying" the reference to the spec section does not point it at the
violation type. Same choice `entity-core-go` made at their gate. Retirement condition: the fold
lands the table at an unoccupied anchor, and both citations move to it in the same pass.

---

## SA-PY-37 — §9.1's list of "non-conformant 501 spellings" includes one an extension pins as a MUST

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-04** — `0.8.2.8` qualifies §9.1's sentence exactly as
asked: the list is now scoped *"of this row"*, and **`unsupported_mode` is named as the worked
case** of a domain code that answers 501 for a different failure and is therefore not a synonym.
The test arch states is the general form of the ask — ***the failure named, never the status
shared***. Arch recorded the conflict as theirs (AP-22, a blacklist built from an implementation
census). **py held this alone against go and rust**, both of whom now move to `unsupported_mode`;
our two registry sites are unchanged and were correct throughout. ·
**Found while:** sweeping §3.3's 501 slot — **by `entity-core-go`'s validator turning red on a
change we made from the list.** · **Spec:** V7 §3.3 (0.8.2.7's default-code force and escape
clause), §9.1's dispatch conformance row; `EXTENSION-REGISTRY` §6a.9.2 ·
**Read at:** `entity-core-protocol` `221d8c3`, `entity-system-architecture` `646b82e`
**Severity:** medium — it is a **MUST against a MUST**, and the list is the artifact every seat
is currently sweeping from.

### The conflict

§9.1 (0.8.2.7): *"The code slot at 501 carries no synonym: `unknown_operation`,
`not_implemented`, `not_supported`, **`unsupported_mode`** and `not_available` are all
non-conformant spellings of this row."*

`EXTENSION-REGISTRY` §6a.9.2 pins `unsupported_mode` **twice, both `[MUST]`**:

- *"`set-issuer-policy` MUST reject `mode: "domain-control"` with **`400 unsupported_mode`**
  until the challenge format lands, rather than storing a policy it cannot enforce."*
- *"The registry MUST answer live registration **`501 unsupported_mode`** and MUST NOT fall back
  to `open`, `manual`, or an unset-style `404` … **This is a cross-impl-observable answer with
  four plausible codes, so it is pinned rather than left to converge.**"*

The second is the same status as §9.1's row, so they collide directly.

### Which we think wins, and why this is a wording defect rather than a real conflict

**§6a.9.2 wins, and 0.8.2.7's own text says so.** Ruling 2's escape clause: *"a more-specific
code is permitted only where one is DEFINED for the operation in a spec code set — §4.7,
`EXTENSION-TREE` Appendix A, or **the owning domain handler's own table**."* §6a.9.2 is the
owning domain handler's definition. So §9.1's sentence is over-broad rather than wrong in
substance: it enumerates spellings **seats were emitting** and reads as an enumeration of
spellings **the corpus leaves undefined**.

**That is arch's own AP-21 reaching its own remedy a second time.** AP-21 is *a count of the
token is not a census of the slot*; this is *a census of emissions is not a census of
definitions*. Both are positive-sounding sentences whose truth condition is a negative — *no
spec text defines this code* — so the *prove a negative* rule never fires, and the list is
persuasive precisely because it cites five measured spellings. The `unsupported_mode` row was
measured at `entity-core-rust`, where it may well be undefined-and-minted; the census did not
distinguish that from ours, which is pinned.

### What it cost here, which is the argument for fixing the sentence

We swept **both** registry sites from the list: `400 unsupported_mode` → `invalid_params`, and
`501 domain_control_unsupported` → `unsupported_operation`. The unit suite was green on both
(we moved the assertions with the code — *our constant against our constant*), and
`entity-core-go`'s `registry_issuer.set_issuer_policy_domain_control_rejected` is what caught
it. **A cohort seat sweeping from §9.1 without opening §6a.9.2 breaks a pinned code and its own
tests agree with it.** rust is the seat most likely to do this next, since their
`unsupported_mode` is on the list twice over.

Second finding from the same pass and it is ours alone: our 501 site emitted
`domain_control_unsupported`, **a fifth spelling for the answer §6a.9.2 pinned specifically
because it had four plausible ones**. Fixed to `unsupported_mode`.

### What upstream could rule

1. **Qualify §9.1's sentence** — *"… are non-conformant spellings of this row **unless defined
   for the operation in a spec code set (§3.3 ruling 2); `unsupported_mode` is so defined by
   `EXTENSION-REGISTRY` §6a.9.2**."* Smallest, and it makes the list re-usable as a sweep list.
2. **Drop `unsupported_mode` from §9.1's list** and note why. Loses the information that it is
   minted at seats which have no registry.
3. **Move §6a.9.2 off the spelling.** Largest blast radius; it is pinned in two MUSTs and both
   ground-up seats plus go's validator assert it.

(1), and we have implemented as if (1) were ruled — with the exemption **cited at the call
site and in the gate** rather than carved, so a later seat cannot widen it by assertion.

### Cross-impl question worth asking with it

The other four spellings on §9.1's list deserve the same grep before any seat sweeps them.
`not_available` and `not_implemented` in particular are common enough that an extension may
have pinned one somewhere the census did not look — and the census that produced this list was
of **implementations**, not of the corpus.

### Enforcement point

`tests/integration/test_status_code_slot_3_3.py` — `DEFINED_ELSEWHERE`, whose entries each name
the section that pins them, plus `test_the_defined_exemptions_are_still_emitted_where_the_spec_
pins_them` so the exemption cannot rot into cover for nothing.

---

## SA-PY-36 — §3b's 404 satisfaction mode assumes no seat registers a total handler

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-04** — `0.8.2.8` adds the exception to §3.3's
404 satisfaction mode, in the shape asked for: *"at a peer that registers a catch-all pattern, no
unregistered path exists, so the row's input is unconstructible … Such a peer is conformant; the
check MUST record a **declared SKIP** naming the catch-all, and MUST NOT report the fallback's
answer as a failure of this row."* `entity-core-go` had already moved the check FAIL → SKIP at
`c2ff3a2`, citing this filing by name. **One harness item remains and it is go's** — the skip is
not yet *declared*, so pass 1 still exits non-zero on it; see `ROUTING-2026-09-04-b` §2. ·
**Found while:** implementing 0.8.2.7's 404 row and building its gate. ·
**Spec:** V7 §3.3's *Satisfaction mode* paragraph (normative, 0.8.2.7), §6.2, §9.1's
dispatch-routing row. · **Read at:** `entity-core-protocol` `221d8c3`,
`entity-system-architecture` `646b82e`
**Severity:** low as a defect, higher as a **conformance-claim** question — it decides what a
green 404 row means at this seat.

### The gap

§3b states the 404 row is *"drivable over the wire: dispatch to a path where no handler is
registered, targeting the local peer."* **On a peer built with `with_default_handlers()` that
input does not exist here.** This implementation registers `storage_handler` at pattern `*`
with priority 0 as a CRUD fallback, so `_resolve_handler` never returns `None` and the
no-handler branch is unreachable. A conformance client dispatching to "a path with no handler"
gets the catch-all's answer — now `501 unsupported_operation`, correctly, because a handler
genuinely IS registered at that path.

**This is not obviously a defect in either direction**, which is why it is filed rather than
fixed. Registering a total handler is a legitimate architecture and nothing in the corpus
forbids it; under it, the 404 row's *input* is simply not constructible. But the row is
normative and §9.1 carries a conformance row for it, so a peer that cannot be driven to emit
it is in a state the spec does not name.

### What we did

Emit the correct code at the one call site that is the row (`ExecuteResponse.handler_not_found`
in `peer/peer.py`, reached from `_resolve_for_dispatch`'s `_DispatchDenied(404, …)`), and
assert **both** facts in `tests/integration/test_status_code_slot_3_3.py::TestThe404Row` — that
the branch emits the row, and that a default peer cannot reach the branch. The second row is
the one worth having: without it the first reads as conformance evidence it is not.

### What upstream could rule

1. **Name the catch-all case in §3b** — *"a peer that registers a total handler satisfies this
   row by source audit"*, mirroring the 500 row's own escape. Cheapest, and it keeps the
   satisfaction mode honest about what a probe can construct.
2. **Say a conformance peer MUST NOT register a total handler**, or must expose a probe
   configuration without one. Larger, and it constrains an architecture the corpus otherwise
   allows.
3. **Rule that the row is satisfied by the 501 answer** — i.e. a total handler makes the 404
   row vacuous rather than unsatisfied.

We have no stake beyond wanting the claim to be truthful. (1) is the cheapest.

### Cross-impl question worth asking with it

Do `entity-core-go`, `entity-core-rust` or the keystone-generated peers register a total
handler? If any do, their 404 rows are in the same state and their probes are measuring the
fallback. rust holds two tests pinning `handler_not_found` and is the reference for the row, so
the likely answer is no — but it is a measured read, not an assumption, and the absence-of-
evidence hazard cuts both ways.

---

## SA-PY-35 — 0.8.2.6 Q2 rules the established state and the half-open state is unstated

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-04** — `0.8.2.8` names the half-open state
explicitly (§4.7, after row 10): a connection that has completed `hello` but not `authenticate` is
**not established**, the out-of-order row governs it, and an unauthenticated `ping` there is
**409 `connection_sequence_error`** — the reading we shipped and filed. Arch's stated reason for
writing it down is the one this filing gave: *"two adjacent rules each look like they cover it and
neither does,"* and *"all three ground-up implementations answer 409 correctly by construction;
the row is made explicit so the behaviour is pinned by text rather than by three independent
derivations."* **The divergence risk this was filed for — rust moving its intercept ahead of
`verify_request` — is now closed by text rather than by a probe that could never reach the
state.** ·
**Found while:** driving the two rows `ROUTING-2026-09-03-a` §5.2 reported unmeasured at this
seat. · **Spec:** V7 §3.2 (the connection-path exception to `author`/`capability`), §4.2
bullet 1 (0.8.2.6's *"in any connection state, before and after establishment"*), §5.1, §4.7
row 10. · **Read at:** `entity-core-protocol` `221d8c3`
**Severity:** low, and the risk is a **later sweep** rather than the current behaviour.

### The gap

0.8.2.6 Q2 rules that an unauthenticated connect-path operation MUST be served, and its
argument is explicitly about the **established** connection: *"by the time the connection is
established both peers have authenticated (§4.6) and the frame arrives on that authenticated
connection"*, answering the objection that per-frame authority would re-prove *"at every
keepalive, an identity the connection already carries."* §4.2 bullet 1 then gains the broader
wording *"in any connection state, before and after establishment."*

**Three states, two ruled.** Pre-hello `ping` is §4.7 row 10's ordering rule (`409
connection_sequence_error`, ruled 0.8.2.4). Established-and-unsigned `ping` is Q2 (`200`).
**Post-`hello`, pre-`authenticate` is named by neither** — and §4.2's new wording reaches it
while Q2's argument does not, because in that state the peer has proved nothing.

### What we did

`409 connection_sequence_error`, unchanged, on the reading that the half-open state is an
ordering question rather than an authorization one. Pinned with its reasoning in
`test_pre_establishment_execute_ce1.py::TestTheTwoRowsNobodyDrove` — **both** arms, so a later
reader "completing" Q2 from the one-line routed summary has to argue with a row rather than
delete a silence. That summary (*"unauthenticated post-handshake ping → must be served"*) is
true under both senses of *unauthenticated*, which is how this nearly became a one-line "fix"
here: the first draft of that test drove the half-open state, read the 409 as a defect, and was
corrected by opening the ruling rather than the packet.

### What upstream could rule

1. **§4.2 bullet 1's state qualifier gains a carve-out** naming the half-open state as §4.7 row
   10's, not §4.2's. Cheapest and matches what two seats appear to do.
2. **Serve it** — the pre-authorized path is pre-authorized, full stop, and the sequence rule
   only governs `hello`/`authenticate`.
3. **Say nothing and let §4.7 row 10 govern by default**, which is our reading — but then the
   phrase *"in any connection state"* is doing work it does not mean.

### Cross-impl question worth asking with it

rust's `pingServedOnceEstablished` intercept is moving ahead of `verify_request` per the
ruling's §5. **Which state does the moved intercept fire in?** If it fires post-`hello`, rust
and py will disagree on this frame the moment both land Q2 — a divergence created by the fix
rather than found by it, and invisible to every probe, because no probe constructs the
half-open state (reaching it means stopping a handshake halfway, which a client library does
not offer).

---

## SA-PY-34 — `ExecuteResult` drops `result.data.code`, so an in-process sub-dispatch cannot forward a refusal's code

**Status:** 🔵 **OPEN — filed 2026-09-03.** Local defect, not a spec gap — logged here because
it is what stops three sites satisfying 0.8.2.7 and a reader of those sites needs the reason. ·
**Found while:** sweeping §3.3's rows. · **Spec:** V7 §3.3 (*"Error responses use
`system/protocol/error` as the result entity type"*, and 0.8.2.7's default-code force)
**Severity:** low today, and it grows with every handler that delegates.

### The gap

`ExecuteResult` (`entity_core/handlers/context.py`) carries `status`, `result`,
`envelope_included` and `error` — **a human-readable message, and no code.** So a handler that
sub-dispatches via `ctx.execute()` and forwards the refusal has the status and the prose and
has structurally lost the programmatic identifier the caller branches on.

`storage_handler` is where it bites: three `if not result.ok` arms forward an upstream status
with a bare `{"error": message}` body carrying **no `code` at all**. That is a plainer failure
of 0.8.2.7's MUST than any synonym — a code that is absent cannot be the row's default — and it
is on the handler registered at `*`, so it is the most reachable refusal in the peer.

### What we did

**Nothing, deliberately, at those three sites**, with the reason at the call site. Minting a
code there would fabricate a claim about a refusal this handler did not make — the
`connect_refusal` lesson (*a default is a decision; the correct decision is not always the
correct value*), and §3.3's 404 default is exactly the wrong answer for an entity-absent 404
arriving from the tree handler. The fix is to plumb `code` through `ExecuteResult`: one field,
13 construction sites, and a separate change from the code sweep it was found by.

The two arms that do **not** depend on the plumbing were fixed: the unknown-operation
fallthrough (`501 unsupported_operation`) and the `delete` miss (`404 not_found`, the
entity-level spelling §3.3's 404 row explicitly preserves).

### Cross-impl question worth asking with it

`entity-core-go`'s and `entity-core-rust`'s in-process dispatch seams: does either carry the
code across a sub-dispatch? This peer's §5.2 in-process authorization gap (2026-08-17) was the
same shape — *a second dispatch path is a second boundary, and the in-process one is the
untested half* — and a result type that cannot represent a refusal's code is that law arriving
in a **data structure** rather than in a check.

---

## SA-PY-33 — `bad_request` in `EXTENSION-SIGNALING` is a forbidden synonym under V7 §4.7 (filed against §9.2; **ruled: the defect was §4.3**)

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-02** — `EXTENSION-SIGNALING` **v1.2**
(`entity-system-architecture` `4edb02e`), routed as `ROUTING-2026-09-02-h` §3. Implemented and
closed here at `a726478`.
· **Filed:** 2026-09-02 ·
**Found while:** implementing FM-2e, by walking §3.3's 400 **code set** after core-go walked
the §4.7 **row set**. · **Spec:** V7 §3.3 (status table), §4.7 (0.8.2.4's `invalid_request`
paragraph); `EXTENSION-SIGNALING` §9.2 (the closed error enum) ·
**Read at:** `entity-core-protocol` `e482d5a`, `entity-system-architecture` `a01c86a`
**Severity:** low consequence, but it is a **MUST against a MUST** and both are landed.

### The ruling, and the one correction to this filing

Arch adopted the remedy this entry called *"the cheap one"* — §4.7's MUST NOT is scoped to the
wrapped EXECUTE surface — **and corrected where the defect lived.** This entry framed it as
§9.2's enum colliding with core §4.7. It was not: §9.2 is `error: tstr` values in the §9
non-entity protocol, which has no status line and which §4.7 does not reach, and **§9.2 is
unchanged**. The wrong line was **§4.3**, in §4 *Handler and Operations* — the wrapped section
— which listed `bad_request` as an EXECUTE error. That is why both seats emitted it there:
*we implemented the spec correctly and the spec was wrong.* §4.3 now reads `invalid_request`;
both sections gained a scope note naming §4.7 as the authority for the wrapped side, so the
next sweep is a grep rather than a search.

The correction is worth keeping because the reasoning it fixes is the kind that survives a
right answer: we located the conflict at the section we could *see* our code failing against
(§9.2, which our constant transcribed) rather than at the section that *governs the surface we
serve* (§4.3). Same remedy, different defect, and only one of the two readings tells the next
person which sentence to grep.

**§2.2 is not violated by the split**, which this entry did not consider: §2.2 binds the three
*verbs* to be semantically identical, not their error encodings — and the two surfaces could
not share an encoding in any case. Class boundaries are identical on both sides.

### What landed here

All five wrapped emission sites move, and the constant moved with them
(`CODE_BAD_REQUEST` → `CODE_INVALID_REQUEST`): a name holding the other set's value lies to
the next reader about which set it transcribes. The ratchet's directory-wide exemption is
**retired on the retirement condition it wrote down**, so the `bad_request` literal is now a
hard zero across every package — closing to nothing rather than narrowing, because this tree
has no §9 listener. The gate row is re-pointed rather than deleted, so whoever builds that
listener learns the exemption is re-arguable for that file specifically.

Also found in the pass: both signaling rows asserted `== CODE_BAD_REQUEST`, i.e. our constant
against our constant, so neither could fail while the value was wrong. They now assert the
spec's literal.

### The conflict

V7 §4.7, 0.8.2.4, normative:

> **`invalid_request` — the generic malformed-request code.** A well-formed frame whose
> *content* the responder cannot act on as a request … is refused **`400 invalid_request`**.
> … **Extension specifications use this code for the same class and MUST NOT mint a synonym.**

`EXTENSION-SIGNALING` §9.2, normative, a **closed** enum (*"a node MUST NOT invent codes
outside this set"*):

> \| `bad_request` \| malformed frame or CBOR, unknown `op`, wrong key length, missing field \|

That is the same class, spelled differently, and a signaling node cannot satisfy both. It is
not academic here: **our node serves the wrapped surface** — a `system/signaling` handler
returning an EXECUTE_RESPONSE — so the code lands exactly where §3.3's set governs, and a
client keying remedies off `result.data.code` sees `bad_request` from one handler and
`invalid_request` from every other one, for the same failure.

`entity-core-go` carries the identical string at the matching site
(`ext/signaling/node/node.go`, `errResponse(400, "bad_request", msg)`) — which is the evidence
that this is the corpus disagreeing with itself rather than one seat being sloppy. Both seats
are conformant to the extension and non-conformant to the core sentence.

**Confirmed at the other seat and endorsed, 2026-09-02** (`entity-core-go`
`ROUTING-2026-09-02-g`): core-go verified the collision in its own tree rather than relaying
ours, declined to change the string unilaterally on the same reasoning, and routed the conflict
to arch beside this filing. Two seats, one open MUST-vs-MUST; nothing is owed here until it
rules.

### What we did

**Filed, not fixed.** Changing it unilaterally breaks a pinned enum and manufactures a
cross-impl divergence out of a spec conflict — the error this repo exists to find in other
stacks. The rest of the class **was** fixed in the same pass: `bad_request` was this kernel's
*generic* 400 code, via a default argument, and is now §3.3's `invalid_request` at every
core site (`83caa5f`). The signaling constant is the one survivor and it is exempted by name,
one directory wide, with a gate row that fails if the exemption grows.

### What upstream could rule

Either sentence, in one edit — but the cheap one looks right: §9.2's enum is described for a
**raw TCP listener** (*"malformed frame or CBOR"*), while §4.7's MUST NOT is written about the
EXECUTE surface. If that is the intended line, say so — scope §4.7's sentence to the EXECUTE
`result.data.code`, and note that a node serving the **wrapped** surface answers §3.3's set.
If instead the enum should move, `bad_request` → `invalid_request` is a one-row edit in §9.2
plus a migration note, and the cohort has exactly two implementers to move.

**The general shape, which is the part worth a standing rule:** an extension that pins a
*closed* code enum is making a claim about a namespace it does not own. §9.2's enum was
written before core declared a generic 400 code, and nothing rechecks a closed enum against
the core status table when that table gains a row.

---

## SA-PY-32 — V7 §4.5: the `protocols` row negotiates a string the section never names, and it is in §8.4

**Status:** ✅ **RULED IN OUR SHAPE 2026-09-02** — ENTITY-CORE-PROTOCOL `0.8.2.4`
(`entity-core-protocol` `e482d5a`). §4.5's row now reads *"Intersection of the §8.4 protocol
version identifiers (`entity-core/1.0`), must be non-empty"* — the cross-reference this entry
asked for, **with the literal inlined as well**, which is the stronger of the two remedies
proposed. §4.5 additionally gained a paragraph naming the failure mode by name (*"a peer
advertising an identifier that resembles this document's section numbering rather than §8.4's
protocol version is well-formed, silently non-interoperable, and undetectable until the
intersection is first enforced"*). Nothing owed here; our constant already converged at
`ae88668` and is ratcheted at one literal.
· **Filed:** 2026-09-01 ·
**Found while:** implementing §4.7 row 1 (FM-2), after `entity-core-go` landed the check.
**Spec:** V7 §4.5 (negotiation table), §8.4 (*Protocol Version*), §4.4 (hello example),
§4.7 row 1 · **Read at:** `entity-core-protocol` `c296d28`
**Severity:** low as a spec defect, **measured cost: a cohort partition.**

### The gap

§4.5's table is the only normative statement about `protocols`:

> \| `protocols` \| Yes \| — \| **Intersection, must be non-empty** \|

It says the intersection must be non-empty and **never names the value being intersected.**
The literal lives two thousand lines away in §8.4 (*"`entity-core/1.0`"*) and in one §4.4
example. Meanwhile the document is titled `ENTITY-CORE-PROTOCOL-V7`, is cited as `v7.66`,
`v7.69`, `v7.74` throughout, and every section reference a reader has in working memory
starts with a 7.

**This peer advertised `entity-core/7.0` from its Genesis release until 2026-09-01.** Nobody
noticed for the life of the project, because §4.5's *"must be non-empty"* had **no implementer
in any of the three trees** — the field was carried on every hello in the cohort and read by
nothing, and a dead field cannot diverge observably.

The divergence was therefore **created by the first conformant implementation, not revealed by
it**: the day `entity-core-go` landed row 1, a py initiator dialing a go peer got

```
Connect hello failed (status 400 incompatible_protocol):
  no common protocol version: initiator=[entity-core/7.0] responder=[entity-core/1.0] (V7 §4.5)
```

and had we implemented row 1 as relayed without comparing the constant, go→py would have
broken symmetrically. **A cross-impl suite could not have caught it**: the cohort agreed on
the *behaviour* (ignore the field) and disagreed on the *value*, and every responder-side
probe ever written dials the peer under test and so offers that peer's own string back to it.

### What we did

Converged on §8.4's `entity-core/1.0`, in **one** module constant
(`entity_core.handlers.connect.PROTOCOL_VERSION`) where there had been four literals, with a
zero-ratchet gate against a fifth. Implemented the §4.5 intersection. Both measured against a
live go peer at `7262f17`. No local reading of §8.4 was in question — we were simply wrong.

### What upstream could rule

**One cross-reference, in the row itself:** make §4.5's `protocols` row read *"Intersection of
the §8.4 protocol version identifiers, must be non-empty"*, or inline the literal. FM-2's
Edit B already adds a pointer from §4.7 row 1 to §4.5's row; **the pointer that would have
prevented this one goes from §4.5's row to §8.4**, and it is the same edit's natural
neighbour.

The general shape is worth a sentence in the authoring standard too: **a negotiated field
whose values are a fixed vocabulary should name the vocabulary at the negotiation site.**
`hash_formats` and `key_types` both do (`ecfv1-sha256`, `ed25519` appear in §4.5 in terms);
`protocols` is the one that does not, and it is the one that got a seat wrong.

---

## SA-PY-31 — V7 §4.5: `protocols` is Required, and no row says what an omitted one means

**Status:** ✅ **RULED 2026-09-02 — reading 2, against the arm we shipped.**
ENTITY-CORE-PROTOCOL `0.8.2.4` (`entity-core-protocol` `e482d5a`): §4.5 now says a hello with
**no `protocols` field, or an empty list, MUST be rejected with `400 invalid_request`**, and
§4.7 row 1 is narrowed to a **non-empty** disjoint set. Adopted here at `3c5a15a`; wire-gated
by `connect_absent_protocols` (core-go's `connectivity` category), measured **PASS** against a
live py peer 2026-09-02.

**Our argument carried it and our fallback was wrong, which is the half worth keeping.** The
ruling rests on the reasoning this entry filed — `incompatible_protocol` says *"we compared and
share nothing,"* which cannot be said to a caller that named no version, and the remedies
differ (send the field vs. change the version), so answering row 1 misdirects the remedy. What
we got wrong was the *cohort-consistency* fallback: we reasoned from the two ground-up seats,
and **reading 1 was never the cohort position** — keystone's generated `csharp`
(`ConnectHandler.cs`) and `typescript` (`connect-handler.ts`) peers already required the field,
so reading 1 would have made 46 peers non-conformant.

**Read first-hand, those peers do not implement the ruling they justify — routed as a separate
finding.** Both call `Ecf.require(hello.data, "protocols")`, which throws
`EntityProtocolException(status=400)`; the dispatcher answers **`400 handler_error`** for the
**absent** arm, and the **empty list** passes `require` and falls to the membership test,
answering **`400 incompatible_protocol`** — reading 3, which 0.8.2.4 forecloses in terms. So
the citation is right about the direction (they refuse) and wrong about the pair, on the arm
the ruling names in its own sentence. `connect_absent_protocols` will FAIL against a keystone
peer today, and the tempting read of that FAIL is that the check is wrong.

**Independently re-measured at `entity-core-go` and confirmed, 2026-09-02**
(`ROUTING-2026-09-02-g`): they treated our claim as a build-state claim rather than a fact and
read `ConnectHandler.cs:70-73` / `connect-handler.ts:80-82` first-hand, reaching the same two
pairs. Routed to arch as *"regenerate the anchor or restate L16"*. The ruling itself is not
reopened — reading 2 is landed and we implement it — so this is a defect in the **anchor**, and
the note that matters downstream is the one about the FAIL: it is the anchor's gap, not the
check's.

**A cohort-consistency argument is only as good as the census behind it, and ours counted two
of three families.** This is the standing *"the conjunction of two readings bounds the
disagreement, not the error"* shape with a **census** as the subject: the seats we polled
agreed, and the rows nobody re-examines are exactly the ones they agree on. The generated
family is the one a ground-up seat forgets it is in a cohort with — it has no `AGENTS.md`, files
nothing, and is invisible to a `git log` in the sibling trees we do read.

· **Filed:** 2026-09-01 ·
**Found while:** implementing §4.7 row 1 (FM-2). · **Spec:** V7 §4.5, §4.7 row 1
**Related:** FM-2 §2 (`PROPOSAL-CONNECT-SURFACE-RECONCILIATION`), which rules the *disjoint*
case and does not reach this one.

### The gap

§4.5 marks `protocols` **Required: Yes** with **no default** — unlike `hash_formats`
(`["ecfv1-sha256"]`) and `key_types` (`["ed25519"]`), which have declared floors. §4.7 row 1
pins the refusal for *"incompatible protocol versions"*. Neither says what a responder does
with a hello that carries **no** `protocols` at all, or an empty list.

Three readings, all defensible:

1. **Unconstrained** — refuse only a non-empty disjoint set. (What `entity-core-go` shipped,
   and what we matched.)
2. **Malformed hello** — a Required field is absent, so `400 invalid_request`.
3. **Row 1** — an empty set intersects to empty, so `400 incompatible_protocol`.

This is the standing *"a binary operator with no arm for the absent case is a policy decision
wearing a type guard"* shape (`AGENTS.md`, ratified 2026-08-19 on the resolver TTL ceiling):
the natural implementation writes `params.get("protocols") or []` and has silently picked
reading 1 while looking like a null check.

Reading 3 is the one to refuse and it is worth saying why, because it is the tidy one: it
answers *"incompatible protocol **versions**"* — a statement about two sets — to a peer that
named no version at all, which points the client at renegotiating a version rather than at
the field it omitted. That is exactly the argument arch used to split §4.7 row 10, applied one
row up.

### What we did

**Reading 1, matching `entity-core-go` byte for byte, and recorded as a decision rather than
resolved.** Not because it is clearly right — reading 2 has the better textual case — but
because this surface's divergence unit is *a refused connection*: a responder that refuses
where its sibling accepts partitions the cohort, and inventing that out of a spec gap is the
error this repo exists to find in other people's stacks. **This is two seats declining to
widen an unruled divergence, not convergence**, and recording it as agreement would be the
"cohort-consistent, not independent" overclaim.

Pinned by `TestTheAbsentArmIsARuling` (both arms, separately — `absent` and `present-but-empty`
are folded by our `or []` and the rows exist so that a future move of either arm is visible
rather than silently carrying the other).

### What upstream could rule

Any of the three, in one sentence on §4.5's row — but **rule it for the cohort at once**,
because unlike most gaps in this file, the cost of two seats reading it differently is not a
wrong field or a wrong code: it is that they cannot connect.

---

## SA-PY-30 — `EXTENSION-RELAY` §3.1: `forward-request.expires_at` is dropped at every intermediate hop

**Status:** 🔴 **OPEN** · **Filed:** 2026-09-01 ·
**Found while:** implementing D7 of the `[RL-P]` worklist (`ROUTING-2026-08-31-a §5`).
**Spec:** `EXTENSION-RELAY` §3.1 (`expires_at`, v1.3), §6.2.1, §8.1 ·
**Read at:** `entity-system-architecture` `EXTENSION-RELAY.md` v1.3
**Measured at:** `entity-core-go` `0f9eb65` — `ext/relay/relay.go`, the intermediate-hop
`relayed := types.ForwardRequestData{...}`.

### The gap

D7 adds `expires_at` to `forward-request` and grounds it explicitly on the `ttl_hops`
precedent:

> `expires_at` on the outer request is the same move `ttl_hops` already makes for hop count:
> the outer envelope carries its own copy of a bounding concept because the inner one is
> unreachable.

**`ttl_hops` is carried hop to hop; `expires_at` is not.** Both peers that have implemented
D7 read the field, honor it on their *own* §6.2.1 fallback, and then rebuild the relayed
request without it. go's construction names five fields and omits the sixth; ours did the
same until this pass.

The consequence is not cosmetic. On `A → B → C → D` where the originator set a deadline and
`C` is where delivery fails, `C`'s fallback store-entry is written with **no bound at all** —
the message it holds on the originator's behalf outlives the deadline the originator set,
because the field that carried it died at `B`. §3.1 says a relay **MUST NOT** extend a
deadline the originator set. Dropping the field reaches exactly that outcome by omission
rather than by assignment, which is why neither seat's `MUST NOT extend` test catches it: the
tests drive the single-hop shape, where the drop cannot happen.

It is also the state D7 exists to prevent, one hop later. arch's own framing — *"the relay
picks the expiry for a message it holds on someone else's behalf … the only party who knows
how long the message is worth holding cannot say so"* — describes `C` precisely.

### What we did

**Carry it, unclamped, and route the divergence rather than assume our reading wins.**

*Carried*, because the alternative is the unbounded store above, and because a field defined
on `forward-request` that a relay silently drops when rebuilding a `forward-request` is not a
field the originator can rely on.

*Unclamped*, because §8.1's ceiling bounds what **this** relay stores. Clamping a request we
are only transiting would impose our operator's capacity policy on a peer we have no authority
over — and would be indistinguishable, at the next hop, from the originator having asked for
less. The clamp belongs at the store, and it is applied there on both of our store-write paths.

Pinned by `tests/integration/test_relay_store_bounds_v13.py::TestForwardRequestExpiresAt::
test_the_deadline_travels_to_the_next_hop` and `…::test_the_relayed_deadline_is_not_clamped_
by_our_ceiling`.

### What upstream could rule

1. **The deadline travels** (our reading): §3.1 states that a relay forwarding a
   `forward-request` onward MUST preserve `expires_at` verbatim, as it preserves `destination`
   and `route` and decrements `ttl_hops`. One sentence; go converges by adding one field.
2. **The deadline is hop-local**, in which case §3.1 should say so and explain what bounds the
   store at hop N>1 — because *"the originator's deadline"* and *"a value only the first relay
   ever sees"* are different fields, and only the first is what §3.1 currently describes.

### Cross-impl note

**go and py now differ on the wire for a multi-hop forward carrying `expires_at`** — go's
relayed request omits the field, ours carries it. Both encode byte-identically to v1.2 when
the originator sets no deadline, so nothing currently in either suite is affected. rust has
not implemented D7 at all yet, so it has no position; **worth ruling before rust builds it**,
since a third independent implementation of the same drop would look like convergence.

Not shipped as a wire check by us: the oracle is go's, and a check written to our reading
would discriminate on the contested value — the standing rule that produced go's own
`2026-09-01-a` and `-b` filings.

---

## SA-PY-29 — §5.2 Dimension 4 / §6.2: the ruled default self-grant argues from an enforcement point no shipping peer has

**Status:** ✅ **RULED and CLOSED 2026-09-09** — `ENTITY-CORE-PROTOCOL` **0.8.2.17** §1.4
(*"The enforcement point, and the authority it runs against"* — PD-2). The finding was upheld:
the enforcement point did not exist, and the ruling supplies it. **The ruling's credit belongs to
`entity-core-keystone`** — arch had reached two candidate readings and both were wrong (one keyed
an authority question on a transport predicate; the other made a bootstrap-time grant depend on
who later connects), and keystone saw that the split is on **the authority being spent**.

**Adopted here at `1173dfa`.** Every row of the pin was written to *fail when an enforcement point
landed*, with the retirement condition in its own assertion message; the condition fired as
written and the file is inverted into
`tests/integration/test_outbound_sub_dispatch_authorization_pd2.py`. That is the **third** recorded
instance of a deferral's forward half actually executing.

**One row of the pin had stopped discriminating and would not have told us.** It asserted that
`target_peer` is read *after* the remote return in `_dispatch_local_execute` — still literally
true after the fix, because the new check reads it inside a helper. A negative assertion survives
the very change that empties it; it was re-pointed at where the check sits relative to the
transport rather than left passing.

**What the ruling did NOT settle is filed as SA-PY-42** — the presented-authority arm names two
values (`handler_pattern` for an unresolvable remote handler; the frame the presented capability
is evaluated in) that an implementation must supply and the text does not define.

**Filed:** 2026-09-01 ·
**Found while:** implementing the 0.8.2.3 default-self-grant ruling and PD-1h in the same pass.
**Spec:** `ENTITY-CORE-PROTOCOL` §5.2 (`check_permission` Dimension 4), §6.2 (*"Default
self-grant shape (normative, 0.8.2.3)"*), §1.4, §6.5 step 3 ·
**Read at:** `entity-core-protocol` `a544743` (0.8.2.3)
**Prior art:** `entity-core-go` spec-issue `2026-08-23-a` — the same observation from the go
seat, filed 2026-08-23 and **not** answered by the 0.8.2.3 ruling that absorbed it.

### The gap

§6.2 pins the default per-handler self-grant with `peers` **omitted**, and justifies the shape
with a behavioural claim:

> So the network bound is carried entirely by **`peers`**, which is omitted here and therefore
> defaults to `{include: [local_peer_id]}` and **is still checked** (§5.2 Dimension 4). A
> default-scope handler consequently **cannot** dispatch at a foreign peer, which is the
> escalation that matters.

*"Cannot"* is a claim about where the check runs. **On this peer there is no such place, on
either path** — so the ruled grant shape changes what the grant *says* and nothing about what
the peer *permits*:

| path | why Dimension 4 does not decide |
|---|---|
| inbound wire | PD-1h (§1.4) now refuses a foreign handler uri at canonicalization, **400 `invalid_request`**, *before* `check_permission`. Correct and required by §6.5 step 3 — and it removes the dimension's only wire-observable case |
| in-process sub-dispatch | `_dispatch_local_execute` returns at `_remote_execute` for a foreign uri **before** `_resolve_for_dispatch`; `target_peer` is computed *below* that return, so the only value that can reach the check is the local peer |

Measured 2026-09-01: a handler holding exactly the ruled default grant, sub-dispatching at
`entity://{foreign}/system/tree`, gets **`502` — "Remote execute failed: No live transport
profile"**. The peer went looking for a *route*. It had already decided the dispatch was
permitted; only the absence of a dialable path stopped it.

### Why this is not a py defect report

`entity-core-go` measured the identical structure in their own tree and wrote it down first
(`2026-08-23-a`): *"the handler-grant ceiling runs only on the local branch of
`makeLocalExecute`: a cross-peer URI returns at `d.RemoteExecute(...)` before the
`CheckPermission` call … Dimension 4 of this grant is not a live decision in go today."* They
asked for *"a ruling plus a conformance vector that can actually observe the dimension (i.e.
one that reaches the ceiling with a cross-peer uri)"*.

**0.8.2.3 delivered the ruling and not the vector.** It settled which shape the grant has and
left unstated where the outbound check binds — while resting the argument for that shape on
the check existing. go's PD-1d #2 reaches the adjacent conclusion from the wire side and stops
there: post-PD-1h the dimension is *"unconstructible from an external wire probe"*.

So the field is now specified, defaulted, parsed, ruled — and consulted on no path a shipping
peer takes. That is this repo's standing *"a field the type system parses is not a field the
authorization path checks"* law, arriving with a **ruling** on the parsed side instead of a
dataclass.

### What we did

**Landed the ruled shape and did not invent the enforcement point.** `peers` now comes out of
the default self-grant (`create_default_handler_self_grant`, split off from
`create_full_access_grant` so the two surfaces that legitimately reach across peers — the
debug-mode grants issued to connecting peers, and the extension execute pathway that delivers
notifications to remote subscribers — keep their wildcard).

Adding an outbound Dimension 4 check unilaterally would refuse a sub-dispatch go permits,
manufacturing a cross-impl divergence out of a spec gap — the trade SA-PY-24 declined and the
ruling it produced vindicated. It would also silently re-ceiling every cross-peer handler in
the tree, which is a behavioural change no seat has measured.

The gap is pinned as behaviour instead:
`tests/integration/test_peers_dimension_outbound_gap.py`. Its rows **fail when the enforcement
point lands**, each carrying its own retirement condition in the assertion message — including
a structural row asserting that `target_peer` is still read *after* the remote branch, because
the missing check is not a missing `if` but an argument that cannot be anything except the
local peer. A reviewer reading the call site alone sees a correct four-dimension check and
cannot see that one of its arguments is a constant.

### What upstream could rule

1. **Dimension 4 binds the outbound sub-dispatch** — `check_permission` runs against the
   caller's grant before a cross-peer `_remote_execute` / `RemoteExecute`. Makes §6.2's
   *"cannot dispatch at a foreign peer"* true, and needs a vector that installs a handler and
   drives it (go already said an external probe cannot construct this).
2. **Dimension 4 is inbound-only**, in which case §6.2's justification paragraph is describing
   an effect that does not exist and should be re-derived — the shape may still be right, but
   *"the grant should not claim authority it never exercises"* is a different argument from
   *"this closes the escalation"*, and only the second is currently written down.

Either is adoptable here same-day. What should not stand is the current state, where two seats
have independently measured that the sentence justifying a normative shape is not true of
their peers, and the ruling absorbed the filing without addressing it.

### Cross-impl note

go: same structure, self-reported, unfixed. rust: unread on this point — worth measuring
before anyone concludes the cohort agrees, since agreement here would be three seats sharing
one blind spot rather than three seats converging.

---

## SA-PY-28 — `EXTENSION-REVISION` §6.1 `status.pending`: the no-head case is undefined, and both go and py answer it in the direction that blinds a conformance oracle

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-30 ·
**Found while:** measuring `entity-core-go`'s burst-convergence detector against a python peer
(their `docs/validation/reports/2026-08-30-burst-convergence-cross-impl.md`, which recorded python
as NOT MEASURED).
**Spec:** `EXTENSION-REVISION.md` §6.1 `status`, §339 (`pending: {type_ref: "primitive/uint"}`),
§739, §775 · **Read at:** `entity-system-architecture` release copy, 2026-08-30

### The gap

§6.1 defines `status.pending` as the count of pending changes, and §775 characterises the
population as *"live-tree paths not present in either version (in-flight writes pending
auto-version capture, untracked paths, prior application state)"*. **The spec never says what
`pending` is when there is no head at all.**

Both shipping implementations guard the entire computation on the head's presence:

- py — `_handle_status`, `packages/entity-handlers/src/entity_handlers/revision.py`: `if local_hash:`
- go — `ext/revision/status.go`: `if !headVal.IsZero()`

So with live paths under the prefix and no head, both answer **`pending = 0`**.

### Why it is not a wording nit

`0` then means two opposite things — *the head has captured everything* and *nothing has been
captured at all* — and the second is precisely the state a peer is in when auto-version fails from
the first write.

That collision is load-bearing right now, because `pending` is the oracle of a **conformance
check**. `entity-core-go`'s `auto_version.burst_convergence_no_capture_loss` bursts concurrent
writes at a **freshly generated random prefix** and asserts `pending` settles to 0. A peer that
captures *nothing* for that prefix never mints a head, answers 0, and **passes the check whose
entire purpose is to detect that loss**.

Measured against a python peer on 2026-08-30, by mutation:

| peer | `pending` no-head arm | detector verdict |
|---|---|---|
| py, capture stopped outright | `0` (spec-silent arm) | **16/16 PASS** — blind |
| py, capture stopped, arm fixed to count live paths | `N` | **FAIL** at the 8s settle window |
| py, clean, arm fixed | `0` | **PASS**, 3/3 runs, no false alarm |

go's own teeth-check could not have surfaced this: the go defect leaves earlier captures (and so a
head) behind, so go's detector was verified RED only on the arm that already worked.

### What we did

Implemented the reading §775's own words support — with no head, every live path under the prefix
is uncaptured, so `pending` is their count (exclude-filtered, matching the head arm's filter).
Enforcement point: `tests/unit/test_revision_status_pending_oracle.py`, whose headline row is the
*(entities present, no head)* combination no fixture in this repo had ever driven, with an
empty-tree control so the assertion is a count and not a flag.

**This is a unilateral choice on an unruled point and we flag it as one.** It is deliberately *not*
the SA-PY-24 deferral shape: that filing withheld a local fix because inventing a refusal would
have rejected a client core-go accepts, manufacturing a cross-impl divergence out of a spec gap.
Here nothing is refused — the change makes a count strictly more informative, is unobservable on a
peer whose capture works (head present ⇒ untouched arm), and the alternative is shipping a peer
that answers "fully captured" when it has captured nothing.

### What upstream could rule

1. **`pending` counts live-tree paths not captured by the head, and an absent head captures
   nothing** — what we implemented; makes the existing detector armed on all three seats with no
   change to the check.
2. **`pending` is defined only when a head exists**, with an explicit sentinel or a separate field
   for "no head" — then the burst detector needs a second condition, because `pending == 0` can no
   longer be its pass criterion.

We would adopt either same-day. What must not stand is silence, because the field is already being
used as a conformance oracle by a shipped check.

### Cross-impl note

go carries the same guard and is affected identically; rust unread on this point. Routed to
`entity-core-go` with the measurement rather than filed as a py-only defect — **their detector is
the thing that loses teeth**, and it loses them against every seat, not just ours.

---

## SA-PY-27 — D8 clause 3: the enumeration is missing a row, and the grep it names cannot see the shape that motivated it

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-22 ·
**Found while:** implementing the D8 ruling (arch `ROUTING-2026-08-21-h` §4b,
`PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS-AND-CONCAT-ARGS-SHAPE` §10.3) — *by writing the gate
clause 3 asks for and running it against the shipping grammar.*
**Spec:** `EXTENSION-COMPUTE.md` §2.1, §7.1 · **Read at:** arch `12245ca` (spec file v3.26)

### The gap

§10.3 clause 3 states a checkable grammar invariant and names its enforcement point:

> Every reference field in the expression grammar is a **scalar `system/hash`** (after D3,
> `map_of`/`array_of` hash appear only in `compute/apply.args` and `compute/let.bindings`, both of
> which are enumerated in §2.1). … ***Enforcement point:*** clause 3 is a grep — an
> `array_of`/`map_of` whose `type_ref` is `system/hash`, in a type block outside §2.1's enumerated
> two, is the violation.

**Two defects, and the second is the one with teeth.**

**(a) There are three, not two.** `compute/construct.fields` is `{map_of: {type_ref:
"system/hash"}}` in §2.1's own declaration block, shipping since long before D3. It is an ordinary
reference container the walk must enter — the field hashes are expressions. So the clause as written
flags a legitimate field, and the first seat to run the grep either "fixes" a correct declaration or
adds an exception with no ruling behind it. Measured, not read: three of the four `array_of`/`map_of`
hash fields in this repo's grammar table are reference containers (`apply.args`, `construct.fields`,
and `let.bindings` in substance), and the fourth (`system/compute/subgraph.authorized_data_hashes`)
is an allowlist on a metadata entity that is never walked.

**(b) The grep cannot see `compute/let.bindings` at all.** It is declared `{array_of: {type_ref:
"primitive/any"}}`; the `value: system/hash` lives inside an untyped struct described only in the
prose sub-block under the declaration. A grep for *"`array_of`/`map_of` whose `type_ref` is
`system/hash`"* does not match it. **So the enforcement point is structurally blind to the exact
shape D8 exists because of** — and a future field that hides a reference inside a `primitive/any`
container passes clause 3 while breaking the walker in precisely the `let.bindings` way. The clause
enumerates `let.bindings` as an exception to a grep that would never have flagged it, which is how
the blindness reads as coverage.

This is the same shape as this repo's own inventory-unit lesson (`AGENTS.md`: *when a rule is scoped
by an inventory, the inventory's unit must be the thing the rule binds*) — here the unit is the
declared `type_ref`, and the thing the rule binds is *a reference reachable inside a field value*,
which is a strictly larger set.

### What we did

Implemented clause 1 — the prose `[MUST]` — as a genuinely recursive traversal (`_hash_refs_in`,
shared by both walkers), so **our conformance does not depend on either half of clause 3 being
right**. Wrote clause 3's gate anyway, over the enumeration as it actually is, with `construct.fields`
listed and annotated as unenumerated-upstream, and pinned (b) as an explicit row rather than working
around it. Nothing local diverges: (a) and (b) are both about what the *clause* can detect, not about
what the grammar means.

### What we need

1. `construct.fields` added to clause 3's enumeration (or a statement of why it is not a reference
   container), and
2. a decision on whether clause 3's enforcement point should read *declared* `type_ref` at all. If
   the invariant is meant to bound what a **walker** must enter, the grep's unit is wrong and the
   real enforcement is the behavioural one — in which case say so, because a clause that names a grep
   as its enforcement point is read as having one.

---

## SA-PY-26 — `EXTENSION-COMPUTE` §3.5: the C-8 ruling has no normative text, and the text it contradicts is still shipping

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-21 ·
**Found while:** implementing the C-8 ruling (arch `172589e`)
**Spec:** `extensions/EXTENSION-COMPUTE.md` §3.5, §2.3 N1, §2.4 · **Read at:** arch `10f84ba`
(spec file **v3.26**), proposal `PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS-AND-CONCAT-ARGS-SHAPE`
(status **DRAFT**, target **v3.27**)

### The gap

Arch ruled the three §3.5 corners on 2026-08-21 and the ruling is unambiguous. **None of its four
deltas (D1–D4) are in `EXTENSION-COMPUTE.md`.** The file is still v3.26, and §3.5 still reads:

> **The contained set is exactly three positions** — `assoc`'s `value`, `concat`'s elements,
> `group-by`'s `members`. An error reaching materialization from anywhere else remains the §4.1
> defect it has always been.

The ruling replaces that sentence with the rule that generates it, and makes the set **five**. So
the shipping normative text does not merely lag the ruling — **it states the opposite of it**, and
it states it as a closed enumeration with a `[MUST]` on the guard. `system/compute/concat-args`
likewise still declares `collections` as an array of hashes (D3 changes it to one scalar hash).

**Why this is not just paperwork.** Every seat that implemented C-8 did so from a routing packet.
A fourth implementer — or any of us re-reading in three weeks — implements from the spec file and
gets the superseded answer, with `map`'s output element short-circuiting and a reactive `concat`
that silently never re-fires. That is the same failure shape as an absorbed-but-unretired
compatibility path: *an implementation accepting a spelling nothing sanctions*, inverted — a spec
sanctioning a spelling nothing implements.

### What we did

Implemented the ruling (`_eval_builtin`'s three closure primitives, `_CONTAINED_ARGS[fold]`, the
`concat-args` declaration), and cited **the ruling** rather than the section number everywhere the
two disagree, so a reader who checks §3.5 finds the discrepancy flagged instead of concluding our
code is wrong. `_materialize_contained_error`'s docstring carries the correction inline.

### What we need

The D1–D4 spec edits landed as v3.27, or a statement that the ruling is normative in its own right
and the spec file is not the source of truth for compute — which we do not believe and would want
said out loud, since `AGENTS-STANDARD` tells every seat to implement against the **landed spec**.

### Answered, not closed (arch `ROUTING-2026-08-21-h` §7) — **the fold is NOT taken this cycle**

Arch agrees the fold is owed and declines it on a stated reason rather than by default: **T5 (COMPUTE)
is DEFERRED by operator decision**, and reversing that inside a day on arch's own judgment is churn
this board has already measured. **The cost is on the record rather than buried** — v3.26 carries two
sentences now known wrong in live published text (§3.5's *"the contained set is exactly three
positions"* and §2.3 N1's *"and only those three"*; it is five), and an implementer who has never
heard of this cohort reads them and ships `map`'s output element and `fold`'s accumulator as
short-circuits. Arch names that as *"the defect you shipped, from that reading, this week."*
**The rulings live in the proposal, and the proposal is the text.** This entry stays 🔴 until the
spec file carries them — the ask is unchanged and now has a decision and a decision-maker attached.
*(Second-order note, and it is why the entry stays open rather than being downgraded: the deferral
has no written retirement condition. `AGENTS.md` — a deferral without one is an omission with better
prose.)*

---

## SA-PY-25 — `EXTENSION-COMPUTE` §5.1/§5.4: an evaluation limit is a `compute/error`, so a caller can spell one as a literal

**Status:** ✅ **RULED 2026-08-21**, adopted here `2026-08-22` · **Filed:** 2026-08-21 ·
**Found while:** concurring with `entity-core-go`'s C-8 eval-limit carve-out (go `9ad0110`)
**Spec:** `extensions/EXTENSION-COMPUTE.md` §5.1, §5.4, §2.4, §3.5 · **Read at:** arch `10f84ba`

### The gap

C-8 makes `map`'s output element and `fold`'s accumulator **contained** positions. Both go and py
carve out the evaluation-limit codes (`budget_exhausted` / `depth_exceeded` / `cascade_limit`),
because containing one turns a single stop-point into `[be, be, …]` at a shifted budget — the
peers fork on the containing array's bytes, and the budget stops being a stop-point.

The carve-out is right and **the thing it discriminates on is wrong in both seats, in opposite
ways**, because the spec gives an evaluation limit no representation of its own:

- **go** discriminates on **provenance** — `isEvalLimitCode` is checked only on the minted arm of
  `builtinMap`, so a closure returning a stored `compute/error{code: "budget_exhausted"}` is
  *contained* while a real exhaustion propagates. That is precisely the §2.4 asymmetry the same
  ruling closed, narrowed to three codes.
- **py** discriminates on the **code**, uniformly across both representations. That is
  provenance-independent — but it makes "the evaluator gave up" a string a program can write down,
  so a caller can abort their own `map` with a stored literal.

Neither is a security problem (nothing escalates; the caller costs themselves their own
expression). Both are a **cross-impl byte fork** on a configuration no vector contains, which is
the shape that has bitten this cohort at every §3.5 corner so far.

### What we did

Implemented the code-based discriminator (`is_eval_limit`, `_EVAL_LIMIT_CODES`), because it is the
one of the two that satisfies §2.4, and pinned the divergence with a named row
(`TestEvalLimitCodesPropagate::test_a_value_form_limit_code_propagates_too_and_that_is_the_divergence`).
Deliberately **not** seeding a corpus vector — go held the limit codes out of the frozen corpus for
exactly this reason, and a vector minted from one seat's discriminator answers a false red to a
conformant peer holding the other, the same trap `REG-DISPATCH-CONFIG-REFUSED-1` row 8 sat in.

### What we need

A ruling on what an evaluation limit **is**. The two candidates:

1. A limit is a `compute/error` like any other, and the carve-out is by **code** — in which case
   say so, and say that a stored literal carrying a limit code aborts a contained position, because
   that is the consequence and it should not be discovered.
2. A limit is **not** an error-as-value at all — it is the evaluation refusing to continue, and
   therefore not expressible in the value language. Then the discriminator is structural, no
   literal can forge it, and the §9.1 code table needs a line saying these three codes never appear
   as a *value*.

We prefer (2): it is the only one under which the rule cannot be spelled by a caller, and it makes
the carve-out derivable rather than enumerated. But it is a change to what `compute/error` means at
the top level (§7.2's F10 return currently carries `budget_exhausted` as a value), so it is arch's,
not ours.

### The ruling (arch §8.4 / `ROUTING-2026-08-21-h` §5.1) — **(1), and (2) is refuted**

**The value form exists because the spec mandates its creation**, which is the part we asked for and
did not have: §7.3 requires that budget exhaustion during reactive re-evaluation *"writes a
`compute/error` to the `result_path`."* A downstream `compute/lookup/tree` therefore reads a
value-form `budget_exhausted` produced by a conformant peer doing exactly what §7.3 says. It cannot
be legislated away, so (2) is not available. With *both-contain* refuted for `budget_exhausted` by
§8.1, the only provenance-symmetric survivor is **both short-circuit, keyed on the code** — rust's
*"keyed on the CODE, never the variant"* adopted verbatim. **The residual we flagged is ruled to be
correct and not a hole:** §2.4 makes the stored and minted errors the same materialized entity
(content-addressed over `code` alone), so distinguishing them would require the evaluator to know
something the boundary cannot express, and an author could already halt an expression by placing an
error in a consumed position.

**And the ruling moved a row at this seat that the ruling itself says it did not.** §8 records
*"`entity-core-rust` and `entity-core-py` short-circuit `budget_exhausted` and `cascade_limit` and
**contain** `depth_exceeded`"*, §5.3 says *"your `depth_exceeded` containment stands. Nothing owed,"*
and go's `2026-08-22-compute-v327-*` relayed both. **py short-circuited all three** —
`_EVAL_LIMIT_CODES` at `f09ae70`, which this filing's own second paragraph states plainly. Adopted
here at `depth_exceeded` → contain, keyed on the code, both arms; CV-9a/CV-9c-shaped rows plus the
value-form-depth row and the fold-recovery row, all four mutation-verified RED beforehand
(`tests/integration/test_compute_v327_closure_result_positions.py`). See `AGENTS.md`, *"a routed
report's claims about our repo are hearsay"* — third subject: not our architecture, not our coverage,
but **a ruling's claim about our behaviour, in the flattering direction.**

---

## SA-PY-24 — `EXTENSION-REGISTRY` §4.3 vs §5: `set-resolver-config` writes `pinned_bindings`, which §5 gives its own capability — and a pin outranks everything §4.3 protects

**Status:** ✅ **RULED 2026-08-20 in our shape — option 1, `EXTENSION-REGISTRY` v1.19** (arch
`9cffb14`; cohort row **R-16**) · **Filed:** 2026-08-19 ·
**Found while:** implementing §4.3 and checking the new operation against §5's capability table
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4.3, §5, §4.1 step 1 / §4.1.1 / §4.1.2 · **Read at:**
arch `05faaa5`; `entity-core-go` `5655494`

### The ruling

§4.3 `[MUST, v1.19]`: *"a write that changes `pinned_bindings` additionally requires
`system/capability/registry-pin` … `set-resolver-config` MUST therefore **diff `pinned_bindings`
against the stored config** and, when they differ, require **both** … absent the latter, refuse
`403 not_entitled` and write nothing. A write that leaves the pin list byte-identical needs only
`registry-configure`."* Option 1 verbatim, including the delta-versus-whole-config distinction we
flagged (validation is whole-config; **authorization** is the delta). §5's `registry-pin` row now
names this clause as its enforcement point rather than a bare tree-edit.

**Adopted here:** `_handle_set_resolver_config` + `_pinned_bindings_differ`
(`packages/entity-handlers/src/entity_handlers/registry.py`), with the check placed **before** the
disclosure filter — an authorization verdict and a policy verdict are different kinds, and telling
an unauthorized caller to set `acknowledge_name_disclosure` invites a retry no acknowledgement can
authorize. Rows:
`test_registry_name_privacy.py::TestSetResolverConfigPinDeltaRequiresPinCap` (seven, including the
teeth control, the byte-identical arm, and **removal** — §5 says *"add **or remove**"*, and a check
written as *"does the submitted config carry pins"* passes every other row while letting the weaker
grant delete the operator's pins).

**One thing the ruling did NOT settle, and it is the reason the wire row is absent** — see the
`registry-pin` **encoding** note below.

### The gap

§5's capability table separates two caps over one entity:

| Cap | Purpose | Operation(s) |
|---|---|---|
| `system/capability/registry-configure` | who may edit the resolver-config | the two §4.3 operations |
| `system/capability/registry-pin` | **who may add or remove pins** | tree-edit `resolver-config.pinned_bindings` |

**§4.3's `set-resolver-config` is gated by `registry-configure` alone and stores the whole config,
`pinned_bindings` included.** So a holder of `registry-configure` now mints pins, and §5 says that
is a different capability.

**The direction is the wrong one.** A pin is not a lesser power than a config edit — §4.1 step 1
returns a synthesized pin **before** the step-2 dispatch filter and before any chain entry is
consulted, so a pin bypasses the §4.1 step 2 name-disclosure control that §4.3 exists to enforce,
**and** the §6a.9.1 resolver ceiling (arch's own §5 note: *"a pin is the user's own assertion, not
a backend's answer"*). A `registry-configure` holder who cannot make `did-web` eligible for
`alice` without an acknowledgement can pin `alice` to a peer of their choosing with no
acknowledgement, no signature, and no expiry.

Verified against both implementations: go's `handleSetResolverConfig` (`5655494`) validates
disclosure and stores the submitted entity verbatim, with no pin-delta check; ours does the same,
deliberately (see below).

### The half that generalizes

**The separation was never enforceable at any layer, and §4.3 is the first place it could be.**
Before §4.3 both caps were declared as bare **tree-writes against the same content-addressed
entity** — and an entity is written whole, so no peer could ever have distinguished *"edits pins"*
from *"edits config"*. §4.3 did not create the gap; it made it visible, and it created the first
surface at which the distinction can be checked (an authorization check on the `pinned_bindings`
delta) or honestly withdrawn.

**This is the third instance of `registry-configure`'s own defect class in one table** —
`registry-manage-issuer-policy` (fixed at §6a.9.2), `registry-configure` (fixed at §4.3), and now
`registry-pin`, which still reads *"tree-edit `resolver-config.pinned_bindings`."* The census is
cheap and worth running corpus-wide: **any capability whose "operations" column is a bare
tree-write is an unenforceable gate**, because a raw write cannot refuse selectively, cannot carry
a qualifier, and cannot be told apart from any other write to the same entity.

### The ask

Rule one of:

1. **`set-resolver-config` MUST additionally require `registry-pin` when the submitted config's
   `pinned_bindings` differ from the stored ones.** Note this is the one place a **delta** is
   load-bearing, and it does not contradict *"validate the whole config, not the delta"* — that
   rule is about validation, this is about authorization.
2. **Withdraw `registry-pin`** and state that `registry-configure` covers pins, with §5's table
   updated so the corpus stops implying a separation no peer implements.

Either is fine; the current text is the one combination that is not, because it names a capability
that nothing can enforce while the thing it gates outranks everything else in the section.

### What we did meanwhile, and the part worth keeping

**Nothing behavioural, deliberately.** Inventing the delta check locally would have refused a client
that `entity-core-go` accepted — a cross-impl divergence manufactured out of a spec gap, which is
the thing this file exists to prevent. The gap was pinned as *behaviour* instead
(`TestSetResolverConfigAlsoWritesThePins`), whose second row demonstrated the escalation end to end:
one peer, one config, a bare name `chain_exhausted` and the pinned name resolving anyway. **That row
survives the ruling unchanged** — it is why the gate exists, not why the gate was missing — and the
class it now sits in is the gate.

### The residue: `registry-pin`'s capability ENCODING — ✅ **RULED 2026-08-20 as R-27**

**Ruled the same day it was raised** (arch `08841d8`,
`PROPOSAL-REGISTRY-PIN-AUTHORITY-CAPABILITY-ENCODING`, DRAFT — the §4.3/§5 fold is owed by arch and
the ruling is in force meanwhile). Option 1: **pin authority is authority over the non-dispatchable
operation `pin-bindings`.** Four clauses, and our state on each:

| # | Clause | py |
|---|---|---|
| 1 | `registry-pin` = authority to invoke `pin-bindings` on the registry handler | already matched — `_OP_PIN_BINDINGS` |
| 2 | `pin-bindings` **MUST NOT be dispatchable** | already true (falls through to `404 unknown_operation`); **now pinned** by `test_pin_bindings_is_not_dispatchable` |
| 3 | pin-delta on the **bytes**, `403 not_entitled`, nothing written | already true; **now pinned** against the field-drop class — see below |
| 4 | **capability checks precede config validation** | already true; **the clause arch flagged as the open question at this seat** — confirmed, and pinned twice |

**The derivation is not ours and is stronger than ours.** We argued the operation axis because *"a
resource-path split discriminates nothing here — `pinned_bindings` is a field inside an entity
`registry-configure` already covers."* Arch derives it from **V7**: a grant scopes on path-scope and
id-scope only, and **the path axis is explicitly non-portable** (*"peers that diverge remain
conformant"* on path locations), so the operation name is the **sole portable discriminator** —
true regardless of this entity's shape. Arch cites the three seats' independent agreement **last and
labelled as corroboration** (L18), with the operative test stated: *if all three had chosen a
resource path, would the argument change?* It would not.

**Clause 4 is the one to carry, because we had the right code for a weaker reason.** We ordered
authorize-before-validate on a *kinds* argument (an authz verdict and a policy verdict are different
things, and telling an unauthorized caller to set `acknowledge_name_disclosure` invites a retry no
acknowledgement can authorize). The ruling's second reason is an **information-disclosure control**:
§4.3's violation response is deliberately verbose — *"every violation, not the first"* — so
validating first hands a **config-shaped disclosure to a caller with no authority to change
anything**. Same code, materially different weight, and *our* reason would not have survived a
refactor that hoisted the violation computation. Pinned by
`test_the_refusal_leaks_no_violation_list_to_an_unauthorized_caller`, which asserts the **body**
rather than the status, because a peer can answer `not_entitled` and still attach the list it
computed.

**Clause 3's byte rule, and a claim about us we checked rather than accepted.** `entity-core-rust`
found `entity-core-go`'s compare was **fail-open**: a typed-struct decode drops any §4.2
forward-compat key a pin carries, so a config adding or stripping one read as *"no change"* and
rewrote the pins under `registry-configure` alone (go `f44ed4d`). Arch's §5 records that *"py decodes
to a native mapping and had no field-drop."* **That is a claim about our repo, so it is verified in
our tree** — a sibling reading us from outside can be right about the defect and wrong about our
shape, and this is the cheap direction to check.
It holds. `test_the_delta_survives_an_unmodelled_key_on_a_pin` proves it against the handler with a
read-back assertion, so the row cannot pass by the key having never been stored in the first place.
*(Note what our comparison is: the **canonical encoding of the decoded pins** — the same encoder that
fixes the stored entity's hash — so "equal" means "the stored pins' bytes would not move," which is
the property §4.3 protects.)*

**And row 8 came off the bench.** The wire row was deferred last cycle *because* this was unruled;
the reason is now discharged and `entity-core-go` landed it (`2e8b9f8`), minting configure-only and
configure+pin child caps in the ruled encoding. **A deferral with a stated retirement condition
actually retired**, one cycle later — which is the half of a deferral nobody usually gets to record.

<details><summary>The residue as originally filed (2026-08-20, pre-ruling)</summary>

The *behaviour* is ruled; **how a capability expresses "pin authority" is not.** §5 names
`registry-pin` descriptively and no rule fixes an encoding, so each seat must choose one. go models
it as authority over a distinguished operation `pin-bindings`; we match that exactly, on the same
axis this handler already uses for the same shape of split (`registry-issue-binding` →
`approve-request`/`deny-request`, §6a.9.3), and a resource-path split would discriminate nothing
anyway — `pinned_bindings` is a *field inside* an entity `registry-configure` already grants
whole-entity authority over.

**Matching is not converging, and the distinction is the point.** Two seats picking the same
encoding is two seats not making the vector worse; it is not a ruling, and it must not be recorded
as one. The consequence is concrete: `REG-DISPATCH-CONFIG-REFUSED-1` **row 8 cannot go on the
wire**, because the shared harness drives all three peers and a row minting one seat's encoding
would answer `403 not_entitled` to a **conformant** peer that checks another — a false red rather
than a finding. go routed exactly this as spec-issue `2026-08-20-a` and deferred the wire row; we
concur, hold the behaviour in-tree with teeth, and add nothing to the wire until it rules.

</details>

---

## SA-PY-23 — `EXTENSION-REGISTRY` §4.1 step 2: *"a pattern that matches unscoped names"* is never defined, and go and py classify `*.*` differently

**Status:** ✅ **RULED 2026-08-20 — a grammar, and it is neither seat's** (arch `9cffb14`,
`EXTENSION-REGISTRY` **v1.19** §4.1b + §4.1b.1; cohort row **R-15**) · **Filed:** 2026-08-19 ·
**Found while:** implementing the v1.17/v1.18
write-time MUST and diffing our classifier against `entity-core-go` `5655494`
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4.1 step 2, §4.1a, **§4.1b/§4.1b.1** · **Read at:**
arch `05faaa5` → `b254845`

### The ruling — §4.1b, four conditions, and an enumerated suffix list

A pattern is **NARROW iff** at least one holds: **(a)** it contains no `*`; **(b)** it contains a
literal `@`; **(c)** its literal head *before the first `*`* ends in `:`; **(d)** it ends in an
**enumerated** typed suffix (§4.1b.1 — today exactly `.eth`) with no `*` after it. Otherwise
**BROAD** — equivalently, *broad means the pattern can match at least one bare name.*

**Neither seat's classifier was the answer, and the ask's own proposed wording was wrong.** We
asked for *"an `@`, a `:` scheme prefix, or a dotted literal suffix the wildcard cannot reach
into"* — go's rule, which we had already adopted. The ruling refuses the third clause and says why:
***"any literal at all" is not the line.*** A dotted literal suffix narrows almost nothing, because
dotted **bare** names are ordinary here (`billslab.com` is a legal local name, §6a) — so `*.lab`
routes every `*.lab` name a user types to a third party while looking scoped. The line is *does the
literal identify an authority or a naming system*, which is why the suffix set is **enumerated**,
grows **only by spec revision** `[MUST]`, and makes an unrecognized suffix **broad**. Admitting a
suffix is a privacy decision, not a pattern-shape inference.

**Two of our answers moved, in opposite directions:**

| Pattern | py before | Ruled | Why |
|---|---|---|---|
| `*.lab` | narrow | **BROAD** | `.lab` is not enumerated — the security-relevant correction |
| `a.b`, `alice`, `""` | broad | **NARROW** | rule (a): no `*` ⇒ exactly one name; we had no rule (a) at all |
| `*.*`, `*.e*` | broad | broad | we had already moved here — see below |

**Adopted here:** `_pattern_reaches_unscoped_name` + `ENUMERATED_TYPED_SUFFIXES`
(`packages/entity-handlers/src/entity_handlers/registry.py`), rewritten to the four-rule form.
Rows: `test_registry_name_privacy.py::TestUnscopedReach` (unit, including
`test_the_rows_the_v1_19_ruling_moved` and a row pinning the suffix tuple at exactly `.eth`) and
`::TestTheClassifierOnTheWriteSurface` (the five wire rows go's `v15` row 7 drives, each holding the
chain constant so the pattern is the only discriminator — because a correct classifier called from
nowhere passes every row a-f, this repo's fourth validator-versus-consumer instance).

### The lesson we take, which is not the one we expected

We had already moved `*.*` and `*.e*` to broad ahead of the grammar, on §4.1's asymmetry argument,
and the ruling agrees. **That made it easy to miss that we were right about the answers and wrong
about the rule** — and it is the rule that decides `*.lab`, the one row where our reading leaked.
*Nobody re-reads the reasoning behind a conclusion that landed* is already in `AGENTS.md` from
SA-PY-21 Q1, where being right about the conclusion cost the reviewing seat a real argument. Here
it cost a live disclosure hole that survived our own move to the conservative side.

### The gap

The MUST is violated by *"naming such a kind in **any rule whose pattern matches unscoped
names**."* **No definition of "unscoped name" appears as a predicate** — the section gives one
contrast (`alice@example.org` is scoped) and §4.1a gives five example patterns. Every
implementation must therefore derive a classifier, and it decides a **refusal**: whether
`set-resolver-config` returns `200` or `403`.

Two derivations exist in the cohort today, and they are both defensible:

| Pattern | `entity-core-go` `5655494` | `entity-core-py` (as filed) |
|---|---|---|
| `*`, `alice`, `a*e` | broad | broad |
| `*.eth`, `*@*.*`, `did:web:*` | narrow | narrow |
| **`*.*`** | **broad** | **narrow** |
| **`a.b`, `alice.eth`** (literal, no star) | **broad** | **narrow** |
| **`*.e*`** | **broad** | **narrow** |

go's rule: narrow iff `@` present, or `:` present, or `*.<literal-with-no-star>`. Ours was:
narrow iff a literal `.`/`@`/`:` survives deleting the stars — sound under the closed grammar,
because every name a pattern matches carries all of the pattern's literal bytes in order, so
a literal `.` means every match is dotted.

**§4.1a's default list cannot discriminate them** — all five of its non-catch-all rows classify
identically under both readings, and the catch-all classifies broad under both. This is the
fourth time in this repo that the spec's own example set has been grammar-identical under every
candidate reading (SA-PY-11, -12, -14, this), and it is the shape the ratified law names: *when a
spec gives one example for a field, assume it was chosen to be readable, not to discriminate.*

### What we did, and why we moved off our own reading

**Adopted go's classification** — the strictly larger broad-set (ours is a subset of theirs, so
this is the conjunction, not a coin-flip). The deciding argument is §4.1's own asymmetry, the one
arch used to settle Q1: a false positive is a **visible edit with a documented override**
(`acknowledge_name_disclosure`), and a false negative is silent, irreversible disclosure. `*.*`
pins **no authority at all** — its suffix is a star — so a config routing every dotted name to
`dns-txt` leaks `my.private.handle` and every dotted typo, which is precisely the harm §4.1 states.

**`a.b` is the residue and we would still argue about it.** A bare literal names exactly one
name, so no *class* of bare names leaks; refusing it is a false positive with no compensating
safety. We take it anyway rather than hold a third position.

### The ask *(as filed — the ruling took the first half and refused the second, see above)*

Define "unscoped name" as a **predicate on the pattern**, not by example — one sentence in §4.1
step 2 would do it, e.g. *a pattern is scoped iff it forces every matching name to carry an
authority the rule or the user has named: an `@`, a `:` scheme prefix, or a dotted literal suffix
the wildcard cannot reach into.* Whichever rule is chosen, `REG-DISPATCH-CONFIG-REFUSED-1` needs
a `*.*` row: without one, two conformant peers disagree on a refusal and the check is blind to it —
the same blindness that made `REG-DISPATCH-CATCHALL-LOCAL-1` unable to settle kind-scoped.

*(Both halves landed: §4.1b is the predicate, and row 7 carries `*.*` plus the four other patterns
the readings split on. The proposed wording's third clause was the part that was wrong.)*

---

## SA-PY-22 — `EXTENSION-REGISTRY` §4.1 step 2 / §16: *"normalized at load"* does not say what normalization touches — and the MUST it serves has one implementer and no vector

**Status:** ✅ **DISSOLVED 2026-08-19 — and our instinct is now the rule at every configuration
surface** (arch `3dd5800`, REGISTRY **v1.17**; `ROUTING-2026-08-19-i` §4.4) · **Filed:** 2026-08-19
· **Found while:** landing the v1.16 ceiling ruling and re-reading our own §4.1 loader against it

### The ruling

With load-time normalization withdrawn there is nothing to rewrite, so the ambiguity dissolves
rather than being decided. What arch took from it is the general rule, stated once: **a resolver
MUST NOT rewrite stored configuration as a side effect of reading it.** Our reading of §6a.9.1's
*"a use bound, not a re-issue"* as the general principle — and implementing view-narrowing rather
than assuming — is recorded as the right call. Enforcement point here:
`test_the_stored_config_is_not_rewritten_by_being_read`, which compares the **address**, not the
fields, because a rewrite preserving every field still moves the hash.

The second half of the filing — *the privacy MUST has one implementer and no vector* — was
confirmed and answered: `REG-DISPATCH-CONFIG-REFUSED-1` is now a declared `validate-peer` check
with six rows, built in go at `5655494` and here at this commit.
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4.1 step 2, §16 (`REG-DISPATCH-CATCHALL-LOCAL-1`)
· **Read at:** arch `fc27873`

### The gap

`REG-DISPATCH-CATCHALL-LOCAL-1` says a violating resolver-config *"MUST be refused or normalized
at load."* **Normalization has two shapes and the spec does not choose:**

* **narrow the in-memory view** — the stored `system/registry/resolver-config` entity is untouched,
  the operator's bytes read back exactly as written, and the offending rows are simply not honored;
* **rewrite the stored entity** — the tree now holds a config the operator did not write, and the
  config's content hash has moved.

They are **cross-impl observable** on the first `tree:get` after load, and on any hash taken over
the config. This is not a style question for the same reason the ceiling was not: it is the
difference between a *use* bound and a *re-issue*.

### Why we think the corpus has already decided it

§6a.9.1 v1.16 rules the resolver ceiling *"computed at resolution and never written back into the
binding… the binding's content hash is unchanged; this is a use bound, not a re-issue."* One
section over, the same peer is invited to rewrite a different content-addressed configuration
entity on the operator's behalf. **We read the ceiling's rule as the general one** and implement
view-narrowing — but it is a reading, and the last time this repo carried a reading of §4.1 step 2
without naming it, an oracle had to find it (SA-PY-17).

### The finding underneath it, which is the reason this is filed rather than assumed

**§4.1 step 2's MUST — *"the primary privacy mechanism"* — appears to have exactly one
implementation in the core tier, and no wire vector.** Exhaustive named searches: go `ca53e2a`,
all four `BackendKind{DNSTXT,WellKnownURL,DIDWeb,ConsensusAnchored}` constants plus the literal
`dns-txt` across non-`_test.go` files → four declarations, one validator fixture, nothing in
`ext/registry`; rust `e6fb500`, the same four literals plus `name_transmitting` across `*.rs` →
tests, a doc comment, and a §6a.10 note. Both implement the **eligibility union** (step 2's
filter); neither implements the **configuration** MUST. And go's harness declares `v1`–`v15` with
no `REG-DISPATCH-CATCHALL-LOCAL-1`.

So the seat that filed SA-PY-21 is the only seat the answer binds, which is precisely how a single
reading becomes the cohort's default without anyone choosing it.

### The ask

1. Say which shape *"normalized at load"* is — and if it is view-narrowing, say so in the same
   words §6a.9.1 uses, so the two rules are visibly one rule.
2. Build `REG-DISPATCH-CATCHALL-LOCAL-1`, or say it is deferred. Its stated observable (*"the
   absence of a request"*) **cannot discriminate SA-PY-21 Q1's two readings** — a kind absent from
   the chain transmits nothing either way — so a ruling on Q1 needs a config-read-back row or it is
   unenforceable.

### What we do meanwhile

`_normalize_config_for_name_privacy` narrows the **loaded view** only; the stored entity is never
rewritten. Routed in `docs/status/ROUTING-2026-08-19-b-*`.

---

## SA-PY-21 — `EXTENSION-REGISTRY` §4.1 step 2 v1.14: the widened privacy MUST has an unstated scope, and an operator `MAY` no field can express

**Status:** ✅ **RULED 2026-08-19 — Q1 against us, Q2 our recommendation plus a surface we did not
propose** (arch `3dd5800` + `05faaa5`, REGISTRY **v1.17/v1.18**) · **Filed:** 2026-08-19 ·
**Found while:** implementing the v1.14 widened MUST (`REG-DISPATCH-CATCHALL-LOCAL-1`)

### The rulings, and the arguments — because neither is the one we argued

**Q1 — kind-scoped `[MUST, v1.17]`.** We implemented chain-scoped and were ruled against. The
deciding argument is **monotonicity under extension**: the MUST binds a *distribution*, and under
chain-scoping *"this shipped config is safe"* is not a property of the shipped artifact — it is a
property of the artifact paired with whatever a downstream operator later adds to
`resolver_chain`, which the distribution cannot evaluate, cannot re-review, and (§1's bootstrap
model) cannot reach again. **You cannot hold a party to a property they are structurally unable
to evaluate.** Kind-scoped makes validity a function of `name_format_dispatch` alone, so a
reviewed artifact stays reviewed.

**The argument *we* sent was explicitly recorded as not the justification**, and that is the part
worth carrying. We routed the "latent configuration / arms silently" case (see the block below);
arch's v1.18 note answers it: *"it does not arm silently — the paragraph binds the configuration
as a whole, so adding that chain entry is itself a write the §4.3 check evaluates, and a
chain-scoped implementation would refuse it at that moment."* The hole we described is closed by
whole-config validation under **either** reading. Being right about the conclusion is not being
right about the reason, and the reason is what the next reader inherits.

**Q2 — the MUST binds the write, not the load `[MUST, v1.17]`**, which is our recommendation's
shape with one addition we did not propose: *never refuse to start*. We had framed the choice as
"withdraw the `MAY`" vs "publication-time MUST" vs "provenance field"; arch kept the `MAY` alive
by moving enforcement to an **operation** (§4.3) where an identified, capability-gated actor is
present, which is a fourth option we did not see — and the one that makes the `MAY` expressible
without a forgeable field. The provenance field we argued against was declined for our reason.

**Landed here** at this commit: the load-time normalizer is deleted, the check moved to
`set-resolver-config`, kind-scoped, with all six `REG-DISPATCH-CONFIG-REFUSED-1` rows and the
load-side surfacing rows in `tests/integration/test_registry_name_privacy.py`.
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4.1 step 2, §11.1 · **Read at:** arch `c984f93`

### What is being implemented

*"A distribution's shipped `system/registry/resolver-config` MUST NOT make a name-transmitting
backend eligible for an unscoped name `[MUST, v1.14]`,"* with two doors (a rule whose pattern
matches unscoped names names the kind; an absent/empty `name_format_dispatch` while the kind
sits in the chain), and §11.1's *"MUST be refused or normalized at load."* Built here as
load-time normalization — narrow the offending rows, and under door B drop the chain entries,
since there is no row to narrow and synthesizing a scoping rule would be inventing the
operator's policy.

### Question 1 — is eligibility chain-scoped or kind-scoped?

The vector binds a config that *"makes a backend **eligible** for an unscoped name,"* and
`eligible_kinds` is defined over **kinds**, with no reference to the chain. Door B's own
sentence, one line later, scopes itself *"while such a kind sits in the `resolver_chain`."*
The two readings differ on exactly one configuration: **a broad rule naming a kind the chain
does not carry.**

That configuration is not hypothetical — two of this repo's own dispatch-filter fixtures name
`did-web` in a catch-all with **no** `did-web` chain entry, using it purely as an eligibility
probe. Under the kind-scoped reading the loader silently rewrites those rows and they stop
measuring what they say they measure.

**We take the chain-scoped reading**, because door B is the only place the spec states a scope
and because the harm the section names is *consultation*, which cannot occur for a kind nothing
consults. Recorded rather than settled locally: it is cross-impl observable (whether the loader
mutates the config), and the last time this repo let one edit carry two edge cases without
arguing both, it took an oracle failure and a correction to notice (SA-PY-17).

> **The argument against our own reading, added 2026-08-19 — we did not have it when we filed,
> and it is the better one.** A catch-all naming `did-web` with no `did-web` chain entry transmits
> nothing *today*, and the config is **durable data**. The day an operator adds a `did-web`
> backend — a routine act, in a different part of the document, touching nothing the MUST talks
> about — the pre-existing row makes it eligible for every bare name, silently. §4.1 frames the
> harm as *irreversible disclosure*; the kind-scoped reading disarms the landmine when the config
> is written rather than when it detonates. What still argues for chain-scoped is that narrowing a
> row for a kind the chain does not carry **destroys operator intent that has no other place to
> live** — and that cost largely disappears if SA-PY-22 rules normalization to be view-narrowing,
> since the operator's bytes then survive and are simply not honored until the chain carries the
> kind. **Q1's cost depends on SA-PY-22's answer, so they should be read together.**

> **And the existing vector cannot settle it.** `REG-DISPATCH-CATCHALL-LOCAL-1`'s stated observable
> is *"the absence of a request"* at the third-party endpoint — but a kind absent from the chain is
> never consulted, so it transmits nothing under **either** reading. The distinguishing
> configuration (a name-transmitting kind named in a broad rule, with no chain entry of that kind)
> is invisible to the instrument. This is SA-PY-17's law with a **vector** as the subject: whichever
> way Q1 is ruled, it needs a row that reads the config back, or the ruling is unenforceable.

### Question 2 — where does the operator's `MAY` live?

§4.1 step 2 says *"an operator MAY override this on their own peer; a distribution MUST NOT
ship it."* §11.1 says the resolver refuses or normalizes **at load**. A resolver that normalizes
at load has no way to honor the override, and there is no field that distinguishes *"a
distribution shipped this"* from *"the operator wrote it deliberately."* The two sentences
cannot both hold as written.

Declaring a local opt-in field is the move we specifically do not make: it moves the
`system/registry/resolver-config` type's content hash for a name no other seat would read —
the type-census divergence §6a.9.3 names when it forbids publishing definitions for
`approve-request`/`deny-request`. Same reasoning as SA-PY-15, which is still open.

### The ask

1. Scope the widened MUST explicitly — chain-scoped or kind-scoped — since it decides whether a
   conformant loader rewrites a config that cannot leak.
2. Either pin the site that carries the operator override (a field, a config flag, or an
   explicit "the override is out-of-band and load-time normalization is unconditional"), or
   withdraw the `MAY`. As written, an implementation that honors the `MAY` and one that
   normalizes unconditionally are both conformant and behave differently on the same bytes.

### What we do meanwhile

Normalize unconditionally at load, chain-scoped, and log a warning naming the kind and the
pattern. Failure direction is deliberate and follows `entity-browser-rust`'s `is_broad`: *a
pattern we cannot confidently classify is treated as broad, because calling a broad pattern
narrow is what leaks.* Pinned by `tests/integration/test_registry_name_privacy.py`, including a
row asserting the chain-scoped reading so it fails loudly if arch rules the other way.

---

## SA-PY-20 — `SDK-OPERATIONS` §11.6.1 step 3: a null `internal_scope` writes no grant, and a handler with no grant cannot be dispatched to

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-18 · **Found while:** building §11.6
**Spec:** `specs/sdk/SDK-OPERATIONS.md` §11.6.1, §11.6.3 · `ENTITY-CORE-PROTOCOL` §6.2 ·
**Read at:** arch `cf6871e` · core-rust `a701e13`

### The gap

§11.6.1 step 3 writes the self-grant *"if `internal_scope` is non-null"*, and §11.6.3 says a
handler registered without one *"cannot call other handlers from its body."* Both sentences
describe **outbound** authority.

But V7 §6.2 makes the handler's own grant a **dispatch prerequisite** — this peer resolves
`system/capability/grants/{pattern}` before invoking any handler and fails closed with `403`
when it is missing, on both dispatch paths. So following step 3 literally produces a handler
that is declared in the tree, present in the dispatch index, discoverable through
`discover_handlers`, and answers **403 to every caller**. Registration succeeds and the handler
can never run — the failure mode §11.6.5's litmus test exists to rule out, arrived at from the
other side.

The grant is doing two jobs — *"this handler exists and is authorized to be invoked"* and
*"this is what it may call"* — and §11.6.1 conditions its existence on the second alone.

### The ask

Say whether registration writes a grant when `internal_scope` is null. If the answer is that
it does not, then §6.2's prerequisite needs an exemption for handlers registered this way, and
that exemption is the interesting half — it is a dispatch-time authorization rule, not an SDK
one.

### What we do meanwhile

Write an **empty** grant (`grants: []`) rather than none. That is the minimum-authority end of
the axis — the opposite of the wildcard §11.6.3 forbids — and it produces exactly the
behaviour §11.6.3 *describes*: dispatchable, authorizing no outbound call. Pinned by
`test_a_null_scope_handler_is_dispatchable_and_cannot_call_out`, which asserts **both** halves,
since a wildcard grant satisfies the first and no grant at all satisfies the second.

Note this peer's own bootstrap path does the opposite for built-in handlers —
`create_full_access_grant()` when no `max_scope` — which is why the "never a wildcard"
assertion is not idle.

---

## SA-PY-19 — `SDK-OPERATIONS` §11.6.1 vs §11.6.6: the collision check refuses the restart recovery §11.6.6 recommends

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-18 · **Found while:** building §11.6 ·
**Affects `entity-core-rust` too**
**Spec:** `specs/sdk/SDK-OPERATIONS.md` §11.6.1, §11.6.6 · **Read at:** arch `cf6871e` ·
core-rust `a701e13`

### The contradiction

§11.6.1: *"Before any writes, `register_handler` MUST check whether a handler is already
registered at the pattern (**either in the dispatch index or the tree**). If so, return 409.
Silent overwrite is not permitted."*

§11.6.6, on peer restart with a persistent tree: *"Tree entries from prior dynamic
registrations may survive. The dispatch index is empty... The recommended approach:
applications re-register dynamic handlers on startup. `register_handler` **replays the tree
writes (idempotent if the entries already exist)**."*

Those are the same situation and two answers. After a restart the tree entry is exactly what
survives, so the collision check refuses precisely the call §11.6.6 recommends making — and it
refuses it with the one error a caller cannot act on, since there is no `unregister` for a
pattern whose handle died with the process.

**`entity-core-rust` has it in the same shape** (`bindings/sdk/src/register_handler.rs`: the
check reads both the location index and the registry), so this is a cohort reading of §11.6.1
rather than one seat's mistake.

### The ask

Rule which one binds. Three shapes are available and they are not equivalent: (a) the check is
dispatch-index-only, and a surviving tree entry is overwritten; (b) the check stays as written
and §11.6.6 gains an explicit `replace=true` or an unregister-by-pattern; (c) re-registration
is idempotent only when the surviving entities are **byte-identical** to the ones this spec
would write, which reads as the intent behind the word "replays" and is the only one that
cannot silently overwrite a *different* handler's declaration.

### What we do meanwhile

§11.6.1's is a `MUST` and §11.6.6's is *"the recommended approach"*, so the MUST wins: a
surviving tree entry produces `409 pattern_collision`. Pinned by
`test_a_tree_declaration_alone_also_collides`, which is written so it fails when the ruling
lands either way.

---

## SA-PY-18 — `SDK-OPERATIONS` §11.6: `HandlerSpec.description` reaches no entity, and `operations` is an array where the entity is a map

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-18 · **Found while:** building §11.6
**Spec:** `specs/sdk/SDK-OPERATIONS.md` §11.6, §11.6.1 · `ENTITY-CORE-PROTOCOL` §3.7 ·
**Read at:** arch `cf6871e` · core-rust `a701e13`

### Two shape divergences between §11.6's `HandlerSpec` and the entities it writes

**1. `description` is declared and has nowhere to go.** §11.6 lists
`description: string? ; Human-readable, for discovery consumers`. §11.6.1 says the interface
entity *"Contains pattern, name, and operations"*, and `system/handler/interface` (V7 §3.7)
declares exactly those three fields. So the field offered **to discovery consumers** reaches
none of them: a caller supplies it and it is silently dropped.

This is the SA-PY-2 class — it fails silently. Nothing errors, the handler registers, and the
description simply is not there when someone reads the interface.

**2. `operations` is `[OperationSpec]` in §11.6 and a map in the entity.**
`system/handler/interface.operations` is `map_of system/handler/operation-spec`, keyed by
operation name, and `operation-spec` carries only `input_type` / `output_type` — no `name`. So
the SDK's array element must carry a name the entity type does not declare, and the SDK does
the projection. §11.6 never says `OperationSpec` has a `name`, which is the field that makes
the projection possible.

**Both seats reached the same answers independently** — `entity-core-rust`'s
`build_interface_entity` writes `{name, operations: map, pattern}` and drops `description`.
Two implementations agreeing is not a ruling (this repo has been wrong about that before), but
it does mean the fix is a documentation change rather than a behaviour change.

### The ask

Either give `description` a home — an optional field on `system/handler/interface`, which
§2.10 open types and `SPECIFICATION-FORMAT` §8.4 both permit — or delete it from `HandlerSpec`.
And state that `OperationSpec` carries a `name`, since the entity's map key comes from
somewhere.

### What we do meanwhile

Accept `description` and drop it, documented at the write site. **Not** smuggled in as an
open-type extra: §2.10 would preserve it, but it would move the interface entity's content hash
away from every other implementation's for the same spec, and `discover_handlers` reads this
entity across peers. Manufacturing a cross-impl hash divergence out of a spec gap makes the
divergence ours — the §6a.9.3 lesson.

---

## SA-PY-17 — `EXTENSION-REGISTRY` §4.1 step 2: the dispatch filter's two clauses answer two edge cases differently, and all three seats differ

**Status:** ✅ **RULED 2026-08-19 — EXCLUDE IN BOTH, and this filing's case-A argument is the
ruling's stated rationale** (arch `6378606`, spec `86643f8`, **REGISTRY 1.14**;
`ROUTING-2026-08-19-a`) · **Filed:** 2026-08-18, **revised the same day** · **Concurs with:**
core-go `docs/validation/spec-issues/2026-08-19-a-…` and core-rust's `ROUTING-2026-08-19`
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4, §4.1, §4.1a · **Read at:** arch `cf6871e` ·
core-go `6ae71c4` · core-rust `b4b7456`

### The ruling

**Eligibility is a pure function of the name**, stated once as a function: the union of
`backend_kinds` over the rules whose pattern matches, **empty set when nothing matches**, and
an absent/empty list disables the filter. *"A kind reaches eligibility only by being named."*
So **both** edge cases exclude — the position this peer already held, arrived at as the
conjunction of go's and rust's exclusions.

**Nobody misread it and nobody won.** The paragraph answered one question twice, and the
per-backend sentence was a **category error rather than a wording problem**: rules name
`backend_kinds`, not backends, so *"a backend without an entry"* had no referent. It is deleted.
The catch-all sentence go and this peer both implemented as *"no filtering"* is deleted with it
— the catch-all is `*`, which matches every name, so no name can fall to it, and it is the most
**restrictive** row in §4.1a's list.

Three further defects were folded that nobody reported: the privacy MUST widened from *the
catch-all row* to *the configuration* (closing the omission door for good), the
`REG-DISPATCH-CATCHALL-LOCAL-1` vector retargeted from remoteness to name transmission, and the
schema's `<POSIX shell-glob>` declaration — *"that one word is the entire provenance of the `?`
question"* — removed.

**Landed here:** no behaviour change was owed (`c74f95e` had already landed case B before arch
read us at `23e77ff`). The v1.14 **widened MUST** was owed and is built —
`_normalize_config_for_name_privacy`, pinned by `tests/integration/test_registry_name_privacy.py`,
with the reading it rests on filed as SA-PY-21.

### Not the grammar — that is settled

`[REGISTRY 1.13]` closed the `name_format_dispatch[].pattern` **grammar**
(`REG-DISPATCH-GRAMMAR-1`) and all three impls agree. This is one paragraph over: how a
matched or unmatched name **narrows the chain**.

### The two clauses

> Backends **without** a `name_format_dispatch` entry default to "match all" (no filtering);
> backends **with** one are consulted **ONLY** when the pattern matches.

…against §4's *"eligible at the **union** of their `backend_kinds`"*, which is set-valued. Two
edge cases separate them, and every seat lands somewhere different:

| Edge case | `entity-core-go` | `entity-core-rust` | `entity-core-py` |
|---|---|---|---|
| **A** — kind named by **no** entry, another entry matches the name | excluded | consulted | **excluded** |
| **B** — kind named by an entry, **no** entry matches the name | consulted | excluded | **excluded** |

### Which is right

- **rust is right on the text.** Both clauses are literally in the paragraph and the
  per-backend reading satisfies both; go's *"if nothing matched, leave the chain unfiltered"*
  branch violates the second clause outright.
- **go is right on case A, and it is the stronger argument.** §4.1 step 2 calls this *"the
  primary privacy mechanism"* and §4.1a makes the catch-all a **MUST**: *"the catch-all MUST
  NOT name a backend whose consultation transmits the queried name,"* because *"the catch-all
  is the path every unscoped name takes."* Under rust's case A that MUST is **evadable by
  omitting a row** — a `dns-txt` backend named nowhere sees every bare name a user types, a
  larger disclosure than the one the rule forbids, reached by leaving a line out. A normative
  privacy rule that omission bypasses is not the intended reading.
- **Case B has the text and the privacy argument on the same side (rust's).** An operator who
  scopes `dns-txt` to `*@*.*` has said that a bare handle must not go there; consulting it for
  `alice` is the disclosure the row was written to prevent.

### What we do meanwhile

**Exclude in both cases** — the conjunction of the two seats' exclusions, not a vote. It is the
only position that satisfies both clauses *and* keeps §4.1a's MUST non-evadable, and it is
§4.1 step 4's own posture: *"fail-closed; no silent fallback."* The consequence is that a
non-empty dispatch list with **no catch-all row** resolves nothing, which is loud
(`chain_exhausted`) rather than silent, and makes shipping the catch-all the operator's
explicit act.

An **empty** list filters nothing; all three seats agree there and it is pinned as the control.

### Two corrections we owe on our own filing

1. **This peer was on rust's reading in both cases until 2026-08-18** — fully per-backend.
   Case A was a genuine privacy hole and changing it was right.
2. **Case B changed in the same commit on an argument that only covered case A.** The catch-all
   MUST argument says nothing about a backend the operator *did* scope. Corrected in a
   follow-up, and ratcheted into `AGENTS.md`: *an oracle failure that makes you change
   behaviour is a claim about the rows it names, not about the ones the same edit happens to
   touch.*

### And the oracle that started it has been withdrawn, for the right reason

`entity-core-go`'s `registry.v15_dispatch_grammar` discriminated match-vs-no-match by observing
`resolved` vs `chain_exhausted` — which **is** this filter question, not the grammar. It passed
go-on-go and failed a conformant rust peer, and they pulled it (`8d2f5ad`) with the ratchet
*"a wire check must not discriminate on an unruled or divergent semantic."* **No honest wire
vector for the grammar exists until §4.1 is ruled**, because the row that distinguishes the
grammar from `path.Match` is the *negative* match, and the negative match is the contested
case. Our grammar pin is therefore the unit rows; the end-to-end rows say in their own docstring
that they encode our filter reading too.

### The ask

Rule §4.1 step 2 as one item to all three seats. Either way something needs a companion fix:
if the union reading wins, the second clause needs scoping or withdrawing; if the per-backend
reading wins, the catch-all MUST needs a clause binding backends that appear in **no** rule,
or it stays omission-evadable.

---

## SA-PY-16 — `EXTENSION-HISTORY` §6.2: key 3's worked pair cannot reach key 3, and the order is still not total

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-18 · **Found while:** implementing the §6.2
three-key tuple (`af50d55`)
**Spec:** `extensions/EXTENSION-HISTORY.md` §6.2 · **Read at:** arch `cf6871e`

### Finding 1 — the illustrative pair cannot exercise the key

§6.2 justifies key 3 with: *"two distinct patterns can agree on both (`a/*/c` and `a/b/*` are
each 2 literal segments at depth 3)."* The arithmetic is right and the pair is unusable,
because §6.2's own matcher is `matches_pattern` (`ENTITY-CORE-PROTOCOL` §5.4) and **§5.4 has
no mid-segment wildcard**. `a/*/c` is therefore an *exact* pattern matching the literal string
`a/*/c` and nothing else. The two patterns tie on keys 1-2 and can never both match one path,
so no config selection ever compares them.

This matters because the obvious vector is the spec's pair, and it **passes for the wrong
reason** — only one config matches, so the selection is trivially deterministic and key 3
never runs. We found it by writing `HIST-CONFIG-SPECIFICITY-1` and watching it stay green
against an implementation with no key 3 at all.

A pair that *is* reachable: `*/a` (canonicalizes to `/*/a`) and `*` (canonicalizes to
`/{local}/*`) are each 1 literal segment at depth 2 and both match `/{local}/a`. That is what
our vector drives, with the unreachability of the spec's pair pinned beside it as a control.

### Finding 2 — three keys do not make the order total

§6.2 states key 3 *"makes the order total, which keys 1-2 are not."* It does not. Two configs
stored under different `{name}`s may carry the **same** `pattern`, in which case all three
keys tie and enumeration decides again — the exact defect the key was added to close, one
level down. `EXTENSION-REVISION` §5.1 closes precisely this residue with a fourth key on the
config's `{name}`, in a ruling issued the same day.

### The ask

Correct the illustrative pair to one §5.4 can co-match, and either add REVISION's `{name}`
key or state that identical patterns under distinct names are out of scope and why.

### What we do meanwhile

Implement exactly three keys, because a fourth key no other seat implements is the divergence
the ruling exists to close. The residue is recorded in `_config_order_key`'s docstring so the
next reader does not re-derive it as a bug.

---

## SA-PY-15 — `EXTENSION-REGISTRY` §6a.9.1: the resolver's ceiling is mandated with no site to carry it

**Status:** ✅ **RULED 2026-08-19 — the site is ours, adopted verbatim** (arch `d3752ca`,
**REGISTRY 1.16**; `ROUTING-2026-08-19-d` §3/§6.2) · **Filed:** 2026-08-18 ·
**Routed:** `ROUTING-2026-08-18-f` §5 · **Found while:** implementing the v1.11 TTL
ceiling (`c65bfe2`)
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4, §6a.9.1 · **Read at:** arch `cf6871e`,
re-checked at `c984f93`, ruled at `d3752ca`

### The ruling

*"The ceiling is declared at `resolver_chain[].hints.max_ttl` (ms) `[MUST, v1.16]`"* — our
suggested site, on our stated reasoning (`hints` is §4's declared backend-scoped slot, already
carries `neg_ttl`, so pinning the key costs no change to `resolver-config`'s type hash), and
**per chain entry**, which the ruling makes the point rather than an accident: *"a registry you
operate does not deserve the same number as one you barely trust."* Two further arms ratified
with it — `max_ttl: 0` is **undeclared** (our diagnostic argument verbatim), and a binding with
**no** `ttl` takes `local_max` (rust's shape; ours was wrong — see SA-PY-15's fallout below).
Arch's own framing of the class is **L17**, credited to this filing: *a `[MUST when present]`
with no declared config site and no conformance vector is a rule two conformant peers cannot
both implement.* Four seats had put this number in **three** places.

> **The process fact, kept because it is the more useful half.** This entry was **dropped in
> handling, not decided** — arch's tree carried **zero** occurrences of `SA-PY-15` while citing
> SA-PY-14 and SA-PY-17 five times each, and the board was declared closed over it **twice**.
> It reached arch only inside `entity-core-go`'s cohort sweep. Arch's fix is
> `docs/COHORT-OPEN-ITEMS.md`, one reconciled ledger where *"board closed"* means zero open on
> the shared view and only an owner's in-tree confirmation closes a row. **The rule that caught
> it here was the cheap one: grep the other tree for your own identifier** — a sibling's summary
> of your board is a claim about your filings, checked the same way as a claim about your code.

### What it cost us to be right about the site and wrong about the arm

Being the seat whose site was ratified did **not** make our implementation conformant. The same
`c65bfe2` that put the ceiling on `hints` guarded the clamp with `isinstance(ttl, int)`, so a
sticky binding — the shape `bind` actually mints — got **no ceiling at all**, and that failed
go's new `v4c_ttl_resolver_ceiling` row (d) on a live peer against a green 3820-test tree. Fixed
by `_effective_lifetime` (three arms, one function, both call sites). See the ratchet entry in
`AGENTS.md`.

### The gap

v1.11 makes the resolver-side ceiling *"the half that protects the consumer"* and specifies
its semantics precisely — `min(binding.ttl, local_max)`, computed at resolution, never written
back. It does not say **where `local_max` lives**. §4's `resolver-config` schema declares
`resolver_chain[]`, `pinned_bindings` and `name_format_dispatch`, and no ceiling field
anywhere. So the one number the security property depends on has no declared home.

This is not a cosmetic omission on a `MAY`. The ruling is a `[MUST when present]`: an
implementation that declares the field somewhere and one that reads it from a deployment doc
are both conformant and cannot be configured by the same operator artifact — and
`entity-browser-rust`'s upheld reasoning (*"a ceiling read at fetch time applies on a cold
boot and silently does not on a warm one; a control present on one boot path and absent on the
other is worse than absent"*) is an argument that the site must be **durable config**, which
makes it a shape question, not a taste one.

### Why we did not just declare a field

Adding `max_ttl` to `system/registry/resolver-config` moves that type's content hash for a
field name no other seat would read — the cross-impl type-census divergence §6a.9.3 names when
it forbids publishing type definitions for `approve-request` / `deny-request`: *"publishing a
definition for one would manufacture a cross-impl type-census divergence out of a spec gap,
making the divergence the publisher's."*

### The ask (as filed)

Pin the site. Our suggestion is `resolver_chain[].hints`, which §4 already declares as
`<opaque object | null>` / backend-specific config and which already carries `neg_ttl` — it
needs no type change and it is naturally per-backend, which is the granularity an operator
wants (a ceiling on a third-party registry, none on their own).

### Landed here

`resolver_chain[].hints.max_ttl`, read per resolution by `_resolver_ceiling` and applied
through `_effective_lifetime` at both the expiry verdict and the surfaced `ttl`. We ship **no
default** — §6a.3's ceiling is a `MAY` and the corpus writes no number, for the reason §4.10
writes none. Enforcement point:
`test_registry_ttl_and_dispatch_grammar.py::TestResolverCeiling`, which now carries all four
`REG-TTL-RESOLVER-CEILING-1` rows plus the read-at-resolution row (one process, three configs
— a latched implementation answers the first one three times).

---

## SA-PY-14 — `EXTENSION-REGISTRY` §6a.9.1: which matcher evaluates `name_constraints`?

**Status:** ✅ **RULED 2026-08-19 — §4's matcher, and our interim IS the ruling** (arch
`c984f93`, **REGISTRY 1.15**; `ROUTING-2026-08-19-c` §1) · **Filed:** 2026-08-18 ·
**Found while:** implementing the v1.13 dispatch grammar (`c65bfe2`)
**Spec:** `extensions/EXTENSION-REGISTRY.md` §4, §6a.9.1 · **Read at:** arch `cf6871e`

### The ruling

*"This is the registry's name matcher, and it is the ONLY one `[MUST, v1.15]`."* Both glob
fields — §4's `name_format_dispatch[].pattern` and §6a.9.1's `name_constraints` — use it;
**there is one matcher per registry.** v1.13's *"scoped to this field"* was written to fence
the matcher off from `ENTITY-CORE-PROTOCOL` §5.4, which it still does, and it fenced off
`name_constraints` as collateral. Filed independently by two seats (go's spec-issue
`2026-08-18-e` and this entry), and it is a ruling rather than a cleanup **because the seats
had already diverged in code**.

**The class this entry named is adopted verbatim into the proposal record:** *a `<glob>` in a
schema block is an undefined referent unless a grammar is cited at that field.* Third instance
in two days (SA-PY-11, SA-PY-12, this) — **all three found by implementers, none by review**,
because a schema block reads as data, so a reviewer checks the field exists and an implementer
has to invent what it means.

### Landed here

Nothing to change — the interim was the ruling. What *was* owed is coverage: until 2026-08-19
the only `name_constraints` test in this repo used `*.lab`, which arch names as the reason the
divergence survived review (*"grammar-identical under every candidate reading"*). The four
discriminating rows now live at the call site in
`test_registry_ttl_and_dispatch_grammar.py::TestNameConstraintsGrammar`, with row 3 pinned at
the matcher because §6.3 makes a `/`-bearing name unregisterable.

**Measured cross-impl:** `entity-core-go`'s new `registry_issuer.name_constraints_grammar`
vector passes this peer **32/32** (their report `2026-08-19-…-three-way`). `entity-core-rust`
FAILs row 1 — `a?c` admits `abc` — and owes the landing.

### The gap

v1.13 closes the grammar for `name_format_dispatch[].pattern` and scopes it explicitly: *"it
is therefore a **registry-local matcher**, scoped to this field."* One subsection over,
§6a.9.1 declares `name_constraints: <glob | null>` and defines that glob **nowhere**. Same
extension, same handler, same domain — a user-facing name string — and the scoping sentence
reads that field out of the ruling that just landed beside it.

This is the D10 class the corpus already names (*a normative algorithm may not name a referent
it does not define*), and it is the third instance in two days after `EXTENSION-REVISION`
§2.4's `glob_match` (SA-PY-11) and §2.3's merge-config call site (SA-PY-12). The pattern is
consistent enough to be worth naming as a class: **a `<glob>` in a schema block is an
undefined referent unless a grammar is cited at that field.**

Not cosmetic: `name_constraints` decides whether a binding is issued at all
(`403 not_entitled` vs a signed, published binding). Two registries running the same operator
policy would admit different names.

### The ask

State which grammar §6a.9.1's `name_constraints` uses. If it is §4's, say so at the field; if
it is something else, define it. Either answer closes it — the current state cannot be
implemented twice the same way.

### What we do meanwhile

Evaluate it with §4's matcher (`name_glob_match`). It was `fnmatch`, which grants `?` and
`[…]` meaning nothing in the corpus grants anywhere, so the choice is between the one grammar
this extension defines over this domain and a stdlib no reading sanctions. **We report the
capability loss rather than requesting it back:** `?` and character classes are expressible
under neither candidate reading.

---

## SA-PY-13 — `EXTENSION-REGISTRY` §6a.3/§6a.9: `renew-request` can still mint the null-ttl binding D11 and D12 forbid

**Status:** ✅ **RULED 2026-08-18** (arch `c243577` → `040afe8` → `d1584a1`, REGISTRY
1.9→1.11) · **Filed:** 2026-08-18 · **Found while:** implementing D11/D12 (`224ef5e`) ·
**Adopted:** `c65bfe2`
**Spec:** `extensions/EXTENSION-REGISTRY.md` §6a.3, §6a.9, §6a.9.2 · **Read at:** arch
`9380d85` · core-go `18e24c3`

> **The ruling — inherit, do not refuse.** A three-step cascade: the request's own `ttl`, then
> the policy's `default_ttl` (current operator intent outranks history), then **the superseded
> binding's `ttl`**. Refusing would revoke a name by inaction, for a policy defect the
> registrant cannot see or fix, on the operation whose whole purpose is keeping the name
> alive. Step 3 is a **recovery** of the registry's own prior signed act — one value, already
> published, byte-identical at every conformant peer — and not the implementation-chosen
> default §6a.9.2 forbids one paragraph up. That distinction is the ruling.
>
> **The correction arch made to itself is the half worth carrying.** v1.9 asserted the cascade
> was *total* because §6a.3 guarantees step 3 — reading an invariant as a fact about stored
> bytes, which is the same mistake §6a.9.2 already documents about a stored bad policy. v1.10
> restored the terminal `403 policy_rejected`, and `entity-core-go` had by then **deleted its
> own guard on arch's instruction** and was minting the null the arc exists to prevent. *An
> unreachable branch that is asserted rather than enforced is how the shape it forbids gets
> minted.*
>
> v1.11 then bounded the other side (`max_ttl` + the resolver clamp), because the null was
> never the only way to reach an unrevokable binding — an uncapped requester-chosen `ttl`
> gets there with the field set.

### The gap the two new rules leave open — ✅ **CLOSED at v1.9; this subsection predates the ruling above**

*(Retained for the record, not open. Arch re-opened it expecting work and found it already
answered — `ROUTING-2026-08-19-c` §2. §6a.9 reads: `renew-request` resolves its `ttl` by a
three-step cascade and **never refuses for a missing one** `[MUST, v1.9]`. So "which status and
code" is **moot, and that is the answer**: there is no refusal, hence no code to pin. The
specific worry below — a curated registry with no policy entity, renew omitting `ttl` — is
`REG-RENEW-TTL-CASCADE-1` row (b) verbatim: the successor carries **the superseded binding's**
`ttl`, which §6a.3 makes non-null, so the cascade cannot resolve null. Arch also records that
declining to fix it unilaterally was right, because the divergence was shared with go and the
ruling covers both. Pinned here by `TestRenewCascade::test_row_b_a_curated_registry_inherits_the_predecessor`.)*

D11 refuses to *store* a live policy with no `default_ttl`; D12 refuses a **register-request**
whose resolved ttl would be null. Both are scoped to registration. `renew-request` mints a
binding by the same act (`_issue_binding` / `issueBinding`) and is covered by neither.

The reachable path does not even need a bad policy. Renew consults the issuer policy
*optionally* — a **curated** registry (§6a.8, no policy entity at all, which §6a.9.2 makes a
conformant configuration) has no `default_ttl` to fall back to, so a renew that omits `ttl`
resolves to null and issues a binding no conformant resolver will honor (§6a.4). §6a.3
requires a peer-issued binding to carry a finite `ttl`, and it does not carve out renewals.

**Both implementations have it, in the same shape.** py:
`_handle_renew_request` → `ttl = policy.get("default_ttl") if policy else None`, unchecked.
go: `register.go`, `else if p, armed := i.loadPolicy(hctx); armed && p.DefaultTTL != nil` —
`ttlPtr` stays nil and nothing tests it. So this is a cohort gap, not a py quirk, which is the
argument for ruling it rather than each seat patching to taste.

### Why we have not just fixed it

The refusal code is not derivable. D12's `403 policy_rejected` is a *policy* verdict, and a
renew that omits `ttl` against a curated registry has broken no policy — there is no policy.
`400 invalid_params` reads better for that case and worse for the seeded-bad-policy one. Two
plausible codes on a cross-impl-observable answer is precisely what §6a.9.2 pinned rather than
left to converge, so picking one here would be inventing wire behaviour in an implementation
repo.

### The ask

Rule whether §6a.3's finite-`ttl` requirement binds the renew path, and if so, pin the status
and code — including for the curated-registry case, where the missing input is the
*requester's* `ttl` rather than the operator's `default_ttl`, which may well point at a
different answer than D12's.

### What we do meanwhile

Nothing — the behaviour is unchanged and deliberately so, because the divergence is currently
**shared** with go and a unilateral fix would create the cross-impl split this entry exists to
prevent. Routed to arch and to core-go as an observation on their tree as well as ours.

---

## SA-PY-12 — `EXTENSION-REVISION` §2.3 vs §2.4: which matcher evaluates a **merge-config** pattern?

**Status:** ✅ **RULED 2026-08-18** in our favour (arch `86d6b20`, REVISION 3.12) · **Filed:**
2026-08-18 · **Found while:** implementing the SA-PY-11 ruling (`1bedce3`) · **Adopted:**
`b338f2f` (matcher) + `7e56047` (V7 + the order)
**Spec:** `extensions/EXTENSION-REVISION.md` §2.3, §2.4 · **Read at:** arch `9380d85` ·
core-go `18e24c3`

> **The ruling.** §2.4 now names **three** fields: merge-config `pattern` is the four forms.
> The decider is §5.1's own worked example — *"all `.lock` files use `source-wins`"* is a
> suffix match, **form 3, the single form §5.4 cannot express**, so the alternative reading
> made the section's own example unexpressible. V7 lands too (see below), and the ask about
> an infix form is answered by not adding one.
>
> **How the scoping error was made is the part arch recorded for reuse, and it generalizes to
> us.** The "and nowhere else" clause was scoped by a **census of `*`-bearing patterns**.
> `glob_match(config.data.pattern, …)` carries no `*` and appears in no pattern inventory, so
> *the field that most needed scoping was structurally invisible to the measurement that set
> the scope.* **When a rule is scoped by an inventory, the inventory's unit must be the thing
> the rule binds** — a lesson about gates, which is where this repo keeps finding the same
> shape.
>
> **And the filing produced a larger finding than the one filed.** Verifying our report,
> core-go found `pattern_specificity` called by §5.1 and defined nowhere — the D10 class, on a
> surface that decides which config wins, hence the strategy, hence the merged bytes, hence
> the version root. All three seats had invented one; ours was byte-identical to go's and
> rust's counted the `*`. That became R15 and is landed here at `7e56047`.

### The contradiction, in two sentences of one document

§2.3's merge-resolution pseudocode selects a per-path strategy with
`glob_match(config.data.pattern, path)` — **the function §2.4 defines**, invoked by name.

§2.4 scopes that function away from this call site in the same breath: *"That matcher is
scoped to `exclude` and `exclude_types` in this document and nowhere else … a `*` appearing
outside these two fields — **including elsewhere in this spec** — is §5.4's `*`."*

So §2.3 calls a function §2.4 says §2.3 may not call. One of the two sentences is wrong and
we cannot tell which from the text.

### Why it is not cosmetic

`system/revision/config/merge/path/{name}` patterns select a **merge strategy**, and strategy
decides the merged bytes, which are content-addressed. A pattern that matches on one peer and
not another produces different merged content for identical inputs — same class as SA-PY-11,
one surface over.

The readings differ on exactly one form. §2.4's forms 1/2/4 *are* §5.4, so the fork is
form 3, the trailing literal: under `glob_match`, `*.txt` matches `a/b/c.txt`; under §5.4 it
is a literal filename. That is a narrow but live difference, and it is the spelling an
operator would most naturally reach for on a merge-config.

### The part that is a divergence under **both** readings

This peer evaluated the call site with **`fnmatch`** until now. `fnmatch` is the only matcher
in play that supports `?`, character classes, and **infix** `*` — so `data/*.txt` matched
`data/notes.txt` here and matches nothing in `entity-core-go`, which evaluates this surface
with its four-form `globMatch` (`ext/revision/strategy.go`, `deletion_markers.go`, `18e24c3`).
An operator with an infix merge-config got `source-wins` on py and the default on go.

Neither ruled reading restores that pattern: the four forms have **no infix form**, ruled
deliberately, and §5.4's vocabulary has none either. **So `data/*.txt` is a capability py had
and no conformant peer has** — we are reporting the loss, not asking for it back.

Note also that §4.4.17 **V6** binds `exclude`/`exclude_types` only, so a merge-config pattern
outside the grammar is **storable** and then falls to form 4 (exact). That is the
accept-then-silently-mismatch shape V6 exists to prevent, one field away from where V6 was
put. Whether merge-config wants its own write-time validation is part of the same question.

### The ask

1. Rule which matcher §2.3 means, and make the two sentences agree.
2. If it is `glob_match`, say whether V6 (or an equivalent) binds `merge-config.pattern` —
   an unvalidated pattern on a hash-reaching surface is the SA-PY-11 hazard again.
3. If infix is wanted anywhere, this is the surface with a real use case for it (`*.txt`
   under a directory), which is worth knowing before the "no infix form" ruling hardens.

### What we do meanwhile

We implement **§2.3 as written** — the call site invokes `glob_match`, so we call
`_glob_match`, the same four-form function the exclude fields use. That converges py with go
today and removes a matcher no reading sanctions. Deliberately *not* justified by "go does
it": the justification is §2.3's own pseudocode naming the function, which go read the same
way. Pinned by
`tests/unit/test_revision_extension.py::TestMergeConfigStarScope::test_an_infix_pattern_matches_nothing_and_that_is_SA_PY_12`,
which asserts the loss rather than describing it, so the ruling has something that fails when
it lands.

---

## SA-PY-11 — `EXTENSION-REVISION` §2.4: `glob_match` is undefined, and `exclude_types` is matched two ways

**Status:** ✅ **RULED — FOUR CLOSED FORMS + WRITE-TIME REJECTION, 2026-08-18**
(arch `ROUTING-2026-08-18-i` §1; adopted here `1bedce3`)
**Filed:** 2026-08-18 · **Found while:** implementing the SA-PY-8 ruling (`cc73a60`)
**Spec:** `extensions/EXTENSION-REVISION.md` §2.4, §4.4.17 · **Read at:** arch `94ea5f2` →
`9380d85` · core-go `41ecf0b`

### The ruling

§2.4 now pins `glob_match` normatively as **four closed forms, tested in order** — `*`
match-all · `<literal>/*` subtree prefix (`ENTITY-CORE-PROTOCOL` §5.4 verbatim, crossing `/`
at any depth) · `*<literal>` trailing literal (byte suffix over the whole subject) ·
`<literal>` exact — and §4.4.17 **V6** rejects anything else at config write with
`400 config/invalid-exclude-pattern`. Nine `REV-GLOB-*` vectors ship with it.

**Both halves of (a) and (b) are answered.** `exclude_types` is glob, by the same four forms
over the type name (`REV-GLOB-TYPES-1`), so go's `matchesAnyExact` is the side that moves.

**The finding was upheld; our proposed fix was not.** We measured against Go's `path.Match`
as the reference and proposed doublestar. `path.Match` has no `**` at all, so it was never a
valid control — arch's correction, and the reason the intervening doublestar pin
(`ROUTING-2026-08-18-h` §1) was retracted before anyone built on it. Worth keeping: *the
report and the remedy are separate claims, and a correct finding does not make its proposed
fix correct.*

**Why rejection rather than definition** is the part to carry forward. A spec that omits `**`
and one that rejects it are indistinguishable until a config carries one; omission leaves each
peer to do something reasonable, and "reasonable" is how `path.Match` and `fnmatch` ended up
in two implementations. Only write-time rejection closes it, because an unrepresentable config
cannot be stored.

### What we did

Four forms in `_glob_match`, V6 in `validate_exclude_pattern` wired ahead of V2/V3 and ungated
by `auto_version`. `tests/unit/test_revision_exclude_glob.py` carries the nine vectors and
keeps `fnmatch` as an explicit control row. Landing it surfaced a **second** matcher in
`auto_version.py` reading `/*` as segment-scoped — the emission gate and the trie filter
disagreeing inside one peer — now unified.

---

## SA-PY-11 (original filing, kept for the record)

**Filed:** 2026-08-18
**Spec:** `extensions/EXTENSION-REVISION.md` §2.4 · **Read at:** arch `94ea5f2` ·
core-go `41ecf0b`

### Two gaps, and the first one is wire contract

**(a) `glob_match` is named and never defined.** §2.4's pseudocode filters versioned bindings
through `glob_match(pattern, relative)`. The filter decides which bindings enter a version
trie and **the trie root is the version's identity**, so the matcher's semantics are part of
the hash. Two peers that disagree about whether `ephemeral/*` swallows `ephemeral/a/b` commit
different version hashes for identical content, and neither is detectably wrong at the call
site — there is no error, just two DAGs that will not converge.

The specific fork that bites: in Go, `path.Match`'s `*` **does not cross `/`**; in Python,
`fnmatch`'s `*` **does**. Reaching for the obvious tool in each language produces two
different filters. `EXTENSION-QUERY` and the capability `matches_pattern` machinery each
define their own matching rules; §2.4 borrows a name from neither.

**(b) `exclude_types` is glob in the spec and exact in `entity-core-go`.** §2.4's pseudocode
says `glob_match(pattern, entity.type)`; `computeVersionedBindings` calls `matchesAnyExact`
(`ext/revision/snapshot.go`) — plain string equality. Any `exclude_types` entry carrying a
metacharacter is therefore a live cross-impl root divergence. Patterns without one behave
identically, which is every pattern either implementation currently ships, so this is latent
rather than firing.

**The ask:** define `glob_match` normatively in §2.4 (or point it at an existing definition
in the corpus), and rule whether `exclude_types` is glob or exact. Both are cheap now and
expensive after a peer has a DAG built on the other reading.

### What we did meanwhile — superseded by the ruling above

**(a)** We matched `entity-core-go`'s `globMatch` exactly — `*`/`?` not crossing `/`, `**`
binding at segment boundaries. **Both halves of that description are now non-conformant**, and
the reason is instructive: it was a faithful port of a matcher nobody had ruled, so it
inherited both `path.Match`'s segment scoping (wrong — form 2 crosses `/`) and a `**` the
corpus does not have.

**(b)** We followed **the spec** and globbed `exclude_types`, per the standing rule that the
spec is upstream. That call held: the ruling glob-matches `exclude_types` and go's
`matchesAnyExact` is the side that moves.

---

## SA-PY-10 — §5.5a/§PR-8: which peer frames a *stored* `dispatch_capability`'s resources?

**Status:** ✅ **RULED — GRANTER-FRAMED, 2026-08-18** (arch `ROUTING-2026-08-18-c` §2;
proposal of record `PROPOSAL-DISPATCH-AUTHORIZATION-FRAME`). **Our first reading, adopted
whole, and nothing we built changes.** §5.5a's landed text disposes of the losing side *by
name* — *"Helpers that use peer-relative form on foreign-granted caps are non-conformant"* —
so core-go's `installJoinFromData` is a minting helper the sentence already covers. The
"acceptance re-frames it" alternative is foreclosed for the reason we gave (reachable by an
attacker who arranges for something to be stored) plus one arch added: the rule exists
*because* the two frames are byte-identical for same-peer caps, so re-framing on acceptance
restores exactly the latency §5.5a was written to remove.

**Two things this closes.** (a) **Do not tune the checker.**
`continuations.join_target_received` reading WARN against core-go's fixture is ratified as
the correct result; declining to soften it was the right call and the fixture is theirs to
fix. (b) **The proximate cause is arch's, not the fixture author's** —
`EXTENSION-CONTINUATION` §3.5's worked example spells a cross-peer capability in
peer-relative form and *taught* the fixture that shape. We read it as "apparently without
meaning to be" on the second side; arch's ruling is that it is worse than that, and D2 fixes
it. `TestAForeignGrantedCapFramesAgainstItsGranter` is adopted upstream as the reference
shape for this class of proof.

**Original filing follows.** · **Filed:** 2026-08-18 · **Found while:** running the §5.2 resource
check on the in-process dispatch path for the first time (SA-PY-9)
**Spec:** `ENTITY-CORE-PROTOCOL` §5.5a / §PR-8 · `EXTENSION-CONTINUATION` §3.5, §3.6 step 5
**Read at:** `entity-core-protocol` `d382d2c` · `entity-system-architecture` `1e635f2`

### The question

§5.5a canonicalizes a capability's **own** resource patterns against the **granter's**
`peer_id`, and §PR-8 makes that the verifier's rule too: a bare peer-relative resource on a
foreign-granted cap authorizes only the granter's namespace, and presenting one cross-peer
MUST fail `403 capability_denied`.

A continuation's `dispatch_capability` does not obviously fit either side of that sentence.
It is minted by peer **A** (the installer), persisted at peer **B** (§3.2 step 5), and later
wielded **by B, against B's own namespace**, with `execute.capability` set to it (§3.6
step 5). Granter is A; the dispatch is local to B. So:

1. **Granter-framed** (what §5.5a says on its face) — A's peer-relative
   `system/inbox/target` names `/A/system/inbox/target`, authorizes nothing at B, and every
   continuation install helper MUST mint cross-peer form. This is what we do.
2. **Verifier-framed for a stored cap** — the cap was accepted at install *by B, about B*,
   so its patterns mean B's namespace and peer-relative form is the natural spelling.

Reading 2 has real pull: §3.5's own worked example spells the scope
`{resources: {include: ["peer_b/data/shared/*"]}}` — peer-relative, and evidently *intending*
peer B. Under reading 1 that example authorizes `/A/peer_b/data/shared/*`, which is nothing.

**Why it is not academic.** `entity-core-go`'s validator mints exactly the reading-2 shape
(`installJoinFromData` → `CreateDispatchCapability`: `Granter` = client identity, `resources`
= the join's own peer-relative targets), and under reading 1 the dispatch is refused. Their
peer does not notice because it never runs the resource check on that path at all (SA-PY-9),
so **no implementation currently holds an opinion here** — this surfaced the moment one of us
started checking.

**The question for arch:** does §5.5a's granter frame apply to a capability the verifier
itself accepted and stored, or does acceptance at install re-frame it? If the former, §3.5's
example is wrong and line 2708's "helpers MUST use explicit cross-peer form" needs to name
continuation install helpers explicitly.

### What we do meanwhile

**Reading 1**, because it is what §5.5a says and because the alternative re-opens V2(a)
under-enforcement by a different door: a rule that says "a foreign cap's peer-relative
patterns mean the verifier's namespace once the verifier has stored it" is one an attacker
reaches by getting something stored. Pinned by
`TestAForeignGrantedCapFramesAgainstItsGranter` (`tests/integration/`
`test_authz_resource_dimension_in_process.py`) — three rows driving the engine's own
predicate: foreign-granted + peer-relative denied, foreign-granted + cross-peer form
admitted, self-granted unaffected. The third is why our suite never moved: when granter ==
verifier the two frames are byte-identical.

**Visible cost:** core-go's `continuations.join_target_received` reads WARN against this peer
(deterministic, 3/3 — not its 200 ms sleep). Routed to them with the trace rather than
absorbed here.

---

## SA-PY-9 — §5.2: does the dispatch-level resource check bind an *internal* sub-dispatch?

**Status:** ✅ **RULED — YES, 2026-08-18** (arch `ROUTING-2026-08-18-c` §1). The check binds
every dispatch that carries a resource target, in-process included; `00b2c05` is conformant
and we owe nothing.

**But our framing was wrong, and the correction is the durable half.** We asked arch to
choose between "wire-entry" and "every dispatch". **§5.2 never had that axis** — its
condition is `resource_target is not null`, a test on the **field**, not on the door. There
was no ambiguity to resolve; there was a mis-reading to foreclose, and we supplied the
mis-reading.

Which also means **our characterisation of core-go was too generous.** We routed it as three
implementations splitting on a reading. Arch read the whole path at `94df9e6` and found
`makeLocalExecute` computes `childResource`, normalizes it, installs it as `childCtx.Resource`
— and *thirty lines earlier* hands the check a literal that omits it. **That is dropping a
field, not exercising a carve-out**: a materially stronger finding than the one we sent, and
the one arch routed. Corrected here rather than in the delivered packet, which stands as
sent.

**The lesson we take:** *when two peers differ, "they read the spec differently" is the
flattering hypothesis and it needs the same evidence as any other.* We reached for it without
checking whether the text had the axis we were attributing the disagreement to.

**Original filing follows.** · **Filed:** 2026-08-18 · **Found while:** chasing handoff (h) §4.2
**Spec:** `ENTITY-CORE-PROTOCOL` §5.2, §6.2 · `ENTITY-NATIVE-TYPE-SYSTEM` §9.4a ·
`EXTENSION-CONTINUATION` §3.5
**Read at:** `entity-core-protocol` `d382d2c`

### The question

§5.2 is written about EXECUTE: *"All four grant dimensions (handler, operation, peer,
resource) are verified at dispatch"*, and *"When `resource` is present, this is a secondary
defense-in-depth check — the dispatch-level `check_permission` handles the primary resource
check."* What it does not say is whether **dispatch** means the wire entry point only, or
every dispatch including a handler-to-handler sub-dispatch.

The corpus answers implicitly, twice, and both times in favour of "every dispatch":

- **§6.2** assigns `system/handler:register`'s install-path authorization to exactly this
  check — *"the standard dispatch capability check on `resource` validates that the caller
  may install/remove a handler at that path"* — and the handler performs none of its own.
  `register` is reachable in-process, so under the narrow reading its install path is
  authorized by nothing.
- **`EXTENSION-CONTINUATION` §3.5** requires the stored `dispatch_capability` be *"checked at
  dispatch time … against the final EXECUTE"*, and §3.6 step 5's dispatch is in-process.

But it is implicit both times, and the cohort has silently split on it:

| | in-process resource check |
|---|---|
| **entity-core-py** | absent until `00b2c05`; now runs it |
| **entity-core-go** | **absent** — `makeLocalExecute` calls `CheckPermission(types.ExecuteData{Operation: operation}, …)`, a literal with `Resource` nil, so Dimension 3 is skipped; `childResource` is computed twelve lines later and handed to the child context (`core/protocol/local.go`, `41ecf0b`) |
| **entity-core-rust** | **unverified** — no `check_permission` in the local branch of `make_execute_fn` in a read at `1a6955b`, but not an exhaustive search; routed as a question, not a finding |

**The question for arch:** confirm §5.2's dispatch check binds internal sub-dispatch, and say
so in the text — or, if a sub-dispatch is deliberately exempt, say what authorizes
`register`'s install path there.

### What we do meanwhile

**We check it** (`00b2c05`), matching the wire path exactly. Pinned by
`test_authz_resource_dimension_in_process.py`: a synthetic handler that performs no
`check_caller_permission`, so the assertion is about the dispatcher's verdict and not a
handler's, with in-scope controls on both seams and the wire rows in the same file so the
in-process rows read as a divergence between two paths.

**Why our suite never caught it:** every join/continuation test in this repo drives a **stub**
`_execute_dispatcher`, so no test in 3667 exercised the real in-process authorization at all.
The secondary handler-level check exists in **8 of the 70** non-`__init__` modules in
`entity-handlers`, so for the other 63 there was nothing between a sub-dispatch and any path
on the peer.

---

## SA-PY-8 — `EXTENSION-REVISION` §2.4 vs §6.1: are auto-version roots exclude-filtered?

**Status:** ✅ **RULED — EXCLUDE-FILTERED, 2026-08-18** (arch `ROUTING-2026-08-18-c` §3;
proposal of record `PROPOSAL-REVISION-AUTO-VERSION-EXCLUDE-PARITY`). **Adopted `cc73a60`** —
`compute_versioned_bindings` at `commit` (four call sites) *and* the filtered trie as the
auto-version root (D1), with the O(1) fast path kept for prefixes configuring no excludes.

**Confirmed and larger than we filed.** Establishing it turned up that **§6.1 contradicts
itself independently of any implementation**: its Amendment-2 paragraph requires a new
version's trie to carry explicit entries for every path bound in the parent's, which an
algorithm assigning `root = current_tracked_root(prefix)` can never do because it builds no
trie, and v3.3's D3 ordering rule names an augment step the pseudocode does not have. The
Algorithm block is the stale half, so the ruling is not a new constraint — it is what the
rest of §6.1 already required. Arch also confirmed the root cannot be filtered where it is
produced: `system/tree/root/{P}` comes from EXTENSION-TREE §3.4.1a driven by a
`tracking-config` with no knowledge of any revision `exclude`. §2.4 and §6.1 are **two
different roots**, not two readings of one.

**The trap, sharper than "inconsistent", and the half that mattered most here:** suppressing
the version *entry* for an excluded write does not suppress that path's *contribution to the
tracked root*, so the very next non-excluded write emits a version whose root commits to data
the config says is not versioned. **On the auto-version path the exclude did not work at all,
one write late.** Pinned by
`test_an_excluded_path_never_enters_a_version_root` (mutation-checked).

**`entity-core-go` is at no fault** — filtering at `commit` and not at auto-version is exactly
what the text said, and their row reaches them as a spec revision rather than a defect report.

**Original filing follows.** · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.revision` (proving SA-PY-5's `exclude_patterns` row against the engine)
**Spec:** `extensions/EXTENSION-REVISION.md` §2.4, §4.4.1, §6.1
**Read at:** `entity-system-architecture` `5f3a50b`

### The question

§4.4.1's `commit` algorithm builds its trie from `compute_versioned_bindings`, which drops
every path matching the config's `exclude` / `exclude_types`. §6.1's auto-versioning
produces a version entry per write, and §2.4 **requires** `exclude` to cover
`system/revision/**` and friends whenever `auto_version: true` on a prefix that
encompasses them — the reentrancy rule.

What §6.1 does not say is where the auto-version entry's `root` comes from, and the two
readings are not equivalent:

1. **Re-snapshot per write** — the root is `compute_versioned_bindings` again, so excludes
   apply and auto-version roots equal what `commit` would produce.
2. **Derive from a maintained structural root** — the root is the tree extension's tracked
   root for the prefix (`system/tree/root/**`, EXTENSION-TREE §3.4.1), which is an
   incremental trie over *every* binding and has no exclude notion at all.

Reading 2 is what makes §6.1 cheap (one `trie_put` per write instead of a full rebuild),
and it is what this implementation does. Under it, **an explicit `commit` and an
auto-version of the same tree state produce different roots** the moment any exclude is
configured — and §2.4 forces excludes to be configured for exactly the prefixes where
auto-versioning is most likely to be on.

**The question for arch:** must a tracked structural root used as a version root be
exclude-filtered (making excludes a tree-extension concern, i.e. a field on
`system/tree/tracking-config`), or must §6.1 re-snapshot? A conformance suite cannot
currently tell a peer that picked differently from a peer that is wrong.

### What we do meanwhile, and the defect this exposed in us

**We apply excludes nowhere.** `_get_snapshot_bindings` (`entity_handlers/revision.py`)
takes every binding under the prefix and never reads the config; the tracked root does not
either. So `commit` and auto-version agree — by both being wrong in the same direction —
and a py peer's trie root for a configured prefix differs from a go peer's.

`entity-core-go` implements §4.4.1 as written (`computeVersionedBindings`,
`ext/revision/snapshot.go`) and leaves its own auto-version path on the other reading, so
the divergence is real in both directions: **py vs go at `commit`, and commit vs
auto-version inside go.** That symmetry is why this is filed as a spec question and not
only as our bug.

Not fixed in the same change that found it: filtering `commit` alone would replace one
uniform wrongness with an internal disagreement between two writers of the same head
pointer, which is the harder failure to debug. The gap is pinned by
`test_commit_does_not_yet_apply_config_excludes`
(`tests/integration/test_sdk_revision.py`), which fails the moment either half is fixed.

**Why the suite never caught it:** every exclude test in this repo drives config *write
validation* (§4.4.17 V1-V5), which reads the field. Nothing drove the snapshot, which does
not. The field was covered where it is checked and uncovered where it is used.

---

## SA-PY-7 — `EXTENSION-REVISION` §4.4.2 vs §4.4.6: `since` names two opposite things

**Status:** ✅ **RULED — THE COLLISION IS REMOVED, 2026-08-18** (arch `ROUTING-2026-08-18-i`
§3.3; adopted here `1bedce3`). **`fetch` keeps `since`** — exclusive watermark, walks toward
newer, unchanged. **`log` takes `start_at`** — inclusive anchor, walks toward older. All three
seats. There is no installed base to migrate, so the old spelling is simply gone:
implementations MUST NOT accept `since` on `log`.

**The sizing question was the whole ruling.** Arch asked whether the two paths genuinely
behaved differently; the measurement below said disjoint, and that promoted a prose fix to a
determinism pin. It also decided the *shape* of the fix — because both readings were
defensible for their own operation, the answer could not be "pick an inclusivity", so the
shared name went instead.

**And the third reading is settled with it.** §4.4.2's *"start after this version"* described a
behaviour no engine implemented; `start_at` is normatively **inclusive**, and the prose no
longer offers a third option. That half was ours to fix and is fixed.

We refuse `since` on `log` rather than ignoring it: an ignored field answers from HEAD, which
is a plausible page that is not the one asked for — the same silent-wrong-answer shape the
rename removes. The error names the operation each spelling belongs to, because a caller on a
pre-ruling copy of the doc made a documented mistake. Pinned at both the SDK boundary and the
handler beneath it (`tests/integration/test_revision_since_divergence.py`).

**Original confirmation and measurement follow.**

🟡 **CONFIRMED as a prose defect, 2026-08-18** (arch `ROUTING-2026-08-18-c` §4),
with one question back to us — **answered below, and the answer changed the sizing.**

**Arch's question:** did our two code paths actually *behave* differently, or did the two
readings only diverge on the page? Both spellings plausibly denote one thing — an exclusive
boundary at the old end, described from opposite directions — which would make this a
`hygiene`-class edit rather than a determinism pin.

**Answered against the engine, 2026-08-18:** they behave differently, **and by more than
inclusivity — the two return disjoint halves of the DAG.** With `v1 → v2 → v3`:

| call | this peer returns | reading |
|---|---|---|
| `fetch(since=v2)` | `[v3]` | exclusive stop marker at the old end |
| `log(since=v2)` | `[v2, v1]` | `since` is the *starting point* of a newest-first walk — **inclusive**, and every result is v2 or **older** |

One field name, two operations, and the sets do not intersect. A client that learned `since`
from `fetch` and reached for `log` gets back versions it already had, with no error — the
shape that fails silently. **So: determinism pin, not hygiene.**

**And a third reading nobody argued for, which is ours to fix either way:** §4.4.2's literal
text is *"Start after this version"*, and our `log` returns `since` itself — so it satisfies
neither metaphor. Separable from the direction question.

Evidence: `tests/integration/test_revision_since_divergence.py`, four rows, characterization
by intent — they assert today's behaviour so the ruling has something that fails when it
lands.

**Original filing follows.** · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.revision`
**Spec:** `extensions/EXTENSION-REVISION.md` §4.4.2 (`log-params`), §4.4.6 (`fetch-params`)
**Read at:** `entity-system-architecture` `5f3a50b`

### The contradiction

Both operations take a `since: system/hash`. The two descriptions point in opposite
directions along the same DAG walk:

| section | field text | reading |
|---|---|---|
| §4.4.2 `log-params` | *"Start after this version"* | a **paging cursor** — resume walking toward the root |
| §4.4.6 `fetch-params` | *"Latest known version hash. DAG walk stops here."* | a **stop marker** — walk from HEAD, halt on arrival |

A walk from HEAD toward the root can only honour one of them per call: the cursor reading
returns everything *older* than `since`, the stop-marker reading returns everything
*newer*. On a linear DAG the two answers are disjoint.

### Why it is not academic — the implementations already split

* **This peer:** `log` implements the cursor reading and starts the walk **at** `since`
  (so `since` reappears as the page's first element — not "after" it either); `fetch`
  implements the stop-marker reading exactly.
* **`entity-core-go`:** `walkHistory(store, head, limit+1, params.Since)` walks from HEAD
  and skips `since` for **both** operations (`ext/revision/dag.go`), i.e. the §4.4.6
  reading applied to §4.4.2's operation.

So `log(prefix, since=X)` against a py peer and a go peer returns disjoint sets, and
neither is refutable from the text. A client paging a remote DAG gets the newest page
forever from one and the correct next page (with a duplicate) from the other.

### What we do meanwhile

Nothing is normalized. `entity_sdk.revision.RevisionClient.log` documents the split and
points at this entry, and `test_log_since_starts_the_walk_here_and_go_stops_it_here` pins
our behaviour so a change to it is deliberate. Silently normalizing at the SDK boundary
would hide a live cross-impl divergence, which is the opposite of this repo's job — and
unlike an absorbed `MAY`, there is no branch to pick: the two readings answer different
questions.

**Suggested resolution:** keep §4.4.6's stop-marker semantics for `fetch` (transfer wants
"what don't I have"), and give `log` an explicitly-named cursor field, or state that
`since` is exclusive-and-toward-the-root and say so in both sections. Either way the fix
is one sentence per section plus a conformance vector; the cost of leaving it is a
cross-peer paging bug that looks like data loss.

---

## SA-PY-6 — `SDK-EXTENSION-OPERATIONS` §4: six handler operations are filed as SDK workflows, and branches as tree data

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.revision`
**Spec:** `sdk/SDK-EXTENSION-OPERATIONS.md` §4 ("SDK Orchestration", "Tree Data") vs
`extensions/EXTENSION-REVISION.md` §4.1, §4.2, §4.3, §4.4.11-13
**Read at:** `entity-system-architecture` `5f3a50b`

### The contradiction

§4 splits the revision surface into *Handler Operations*, *SDK Orchestration (not handler
operations)*, and *Tree Data (not handler operations)*. The extension's §4.1 manifest and
§4.2 core/convenience table put every one of them in the handler.

**This one is not drift by neglect.** §17's v0.2 entry records it as a review decision:
*"Revision: … separated handler operations from SDK orchestration, branches/tags as tree
data."* So the entry is a request to **revisit a deliberate split** against the normative
manifest, not a report of a typo — which is why it is filed apart from SA-PY-5.

| §4 says | `EXTENSION-REVISION` says |
|---|---|
| `pull`, `push`, `diff`, `cherry-pick`, `revert`, `find-ancestor` are SDK workflows composing multiple dispatches | all six are handler operations in the **convenience** tier (§4.1 manifest, §4.2 table) |
| branches are `put("system/revision/branches/{name}", …)` | `branch` is an operation; storage is `system/revision/{H}/branches/{name}` (§3.1.1) |
| tags are `put("system/revision/tags/{name}", …)` | `tag` is an operation; storage is `system/revision/{H}/tags/{name}` |
| checkout is "read trie, batch-write bindings" in the SDK | `checkout` is an operation (§4.4.12) carrying the §4.4.4 transcription invariants |

### The three failure modes, worst first

1. **The branch/tag paths fail silently.** `{H}` is the prefix hash — branches are
   per-prefix and an unhashed path cannot say which prefix it means. A branch written §4's
   way lands, returns 200, and reads back with `get`; every revision operation reports it
   does not exist. Pinned by
   `test_a_branch_written_at_the_sdk_docs_path_is_invisible`.
   §4.3 separately says external callers SHOULD NOT hold `put` on the handler-owned
   namespace at all, so §4 is recommending a write the capability model is meant to refuse.

2. **A client-side `checkout` is a correctness bug, not a style choice.** §4.4.4's
   version-transcription invariants require the diff baseline to be the committed head's
   trie rather than the live tree, and require deletion-marker bindings to translate into
   live-tree *unbinds*. "Read trie, batch-write bindings" honours neither: it drops
   in-flight writes present in neither version, and it binds deletion markers into the live
   location index — the exact invariant §4.4.4 Amendment 3 exists to protect.

3. **A client-side `pull` is slower and worse.** §4.4.8 runs the fetch → incremental
   fetch-entities trie walk → merge loop **inside the peer**; composing it in the SDK puts
   every round of that walk on the wire.

### What we do meanwhile

`entity_sdk.revision` treats all six as the single dispatches they are, and exposes
branches/tags/checkout only through their operations. `fetch` / `fetch-entities` take a
`peer=` argument that redirects the **dispatch** rather than riding as a parameter, since
§4's `fetch(peer, prefix)` signature has no counterpart in §4.4.6's params type.
Enforcement: `TestTheWireWeSend`, `TestBranchesAreHandlerStateNotTreeData`.

### Suggested resolution

Move the six into §4's handler list marked *convenience (SHOULD)*; replace the "Tree Data"
block with the prefix-hashed paths as read-only inventory, cross-referencing §3.1.1; and
strike the client-side checkout recipe in favour of the operation, with a pointer to
§4.4.4's transcription invariants explaining why.

---

## SA-PY-5 — `SDK-EXTENSION-OPERATIONS` §4: the revision params and result shapes disagree with `EXTENSION-REVISION`

**Status:** 🔴 **OPEN** · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.revision`
**Spec:** `sdk/SDK-EXTENSION-OPERATIONS.md` §4 vs `extensions/EXTENSION-REVISION.md`
§2.4, §2.5, §4.4.1-4.4.19, §4.5
**Read at:** `entity-system-architecture` `5f3a50b`

### The contradiction

The fourth instance of the ratified pattern (SA-2/-3/-4): the document an SDK author reads
has drifted from the normative extension it summarizes. On this surface it has drifted in
thirteen places — plus the four classification rows filed separately as SA-PY-6.

**Silent rows — the ones worth ruling first.** Each returns 200 and a wrong answer:

| concern | §4 (the SDK doc) | `EXTENSION-REVISION` | what happens |
|---|---|---|---|
| `log` page size | `count` | `limit` (§4.4.2) | unknown param ignored → the **entire DAG** comes back |
| `log` paging cursor | `cursor` | `since` (§4.4.2) | paging never advances |
| prefix-config excludes | `exclude_patterns` | `exclude` (§2.4) | nothing is excluded; with `auto_version` the reentrancy guard is silently unarmed |
| `merge` result status | `status: uint` — *200 clean, 409 conflicts* | `status: string`, nine values (§4.5) | `status == 409` is never true → a conflicted merge reads as clean |
| `status` result | `{head}` alone | `+ conflicts, pending, remotes, prefix` (§2.5) | a caller cannot see that the prefix is conflicted |

**Loud rows** — a `KeyError`, a `400`, one debugging session each:

| concern | §4 | `EXTENSION-REVISION` |
|---|---|---|
| `merge` source param | `theirs` | `remote_version` (§4.4.4) |
| `merge` conflicts | `[{path, base?, ours?, theirs?}]` | `[path]` — trie-relative strings (§4.5) |
| `log` / `fetch` results | bare objects with `cursor` | a `system/envelope`; entries in `included`, paged by `has_more` (§4.5) |
| `resolve` resolution | `resolution: Entity` | `resolved: hash?`, null = resolve-by-deletion (§4.4.5) |
| `fetch-entities` params | `(peer, hashes)` | `{prefix, snapshot, hashes}` — `snapshot` is what stops it being an open proxy onto the content store (§4.4.7) |
| `config` params | `config(prefix, settings)` | `{name, action, config, expected_hash?}` (§4.4.17) — no `name` → `400 config/missing-name` |
| `config` settings | `merge_strategy` | not a prefix-config field at all — strategy is per-path/per-type in the merge-config namespace (§2.3, §4.4.18) |
| `merge-config` params | `merge_config(path?, type?, config)` | `{scope, name, action, config}` (§4.4.18) |

### Triage, because they are not equally dangerous

The `merge` status row is the SA-PY-2 of this surface. A merge that left conflicts in the
tree answers `"merged_with_conflicts"`; code written against §4 asks `status == 409`, gets
`False`, and proceeds as if the merge were clean — no exception, no bad field, just a
branch that never runs. Proved against the engine by
`test_a_conflicting_merge_reports_a_string_status_never_409`.

The `exclude_patterns` row is second: it disarms a guard rather than dropping a value. §2.4
requires the exclude list to cover `system/revision/**` when `auto_version` is on, and
§4.4.17's V2 refuses a config without it — so spelled §4's way, the same request is
*refused* by the validator with the excludes sitting right there in the payload, and a
caller who works around the 400 by dropping `auto_version` gets neither. Proved by
`test_the_sdk_docs_exclude_patterns_is_a_field_nothing_reads`.

### What we do meanwhile

`entity_sdk.revision` speaks the extension's vocabulary and **absorbs** the three §4
spellings that are straight renames — `count` → `limit`, `theirs` → `remote_version`,
`exclude_patterns` → `exclude` — so a caller working from either document gets one
behaviour while this entry is open. Passing both spellings for one argument is a 400
naming this entry rather than a silent drop.

Two rows are **not** absorbed, because absorbing them would mean inventing a target:

* `merge_strategy` on a prefix config → 400 pointing at `set_merge_config`. Merge strategy
  lives in a different namespace written by a different operation; writing it into the
  prefix config would land a field nothing reads.
* `resolution: Entity` on `resolve` → 400 explaining that the entity must already be in the
  peer's content store and that the hash is what travels. Hashing it client-side would hand
  the peer a hash it cannot resolve — a 404 one layer away from the mistake.

**Retire the absorptions when this is ruled** (`AGENTS.md`: an absorption is a debt to the
ruling). The greppable markers are `_ABSORBED_LOG_PARAMS`, `_ABSORBED_MERGE_PARAMS`,
`_ABSORBED_CONFIG_FIELDS` in `entity_sdk/revision.py`.

---

## SA-PY-4 — `SDK-EXTENSION-OPERATIONS` §6: the query result shape and one operator name disagree with `EXTENSION-QUERY`

**Status:** ✅ **RULED — closed 2026-08-17** (`SDK-EXTENSION-OPERATIONS` 0.8.1, **SA-4**;
verified live at arch `5f3a50b`) · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.query`

### The ruling

§6 now reads `matches: [{path?: string, hash: hash, type: string}]` with `has_more`, and the
operator list spells `not_eq` — each with the pre-ruling text recorded inline as what the
line wrongly said. All four rows resolved the way the entry predicted: align §6 to
`EXTENSION-QUERY`.

**What changed on our side, at `70493c9`+:** the compatibility aliases are **removed** —
`QueryResult.entries`, `Match.content_hash`, and the `neq` operator spelling. They existed
to bridge a defect in a document that has since been corrected, and a name no spec defines
is a local divergence, which is the thing this implementation exists to *find* rather than
ship (`AGENTS.md`: no legacy / back-compat code). `neq` now raises `400 invalid_operator`
naming the ruling that moved it, since a caller on a pre-0.8.1 copy made a documented
mistake rather than a typo.

---

**Original entry, as filed:**
**Spec:** `sdk/SDK-EXTENSION-OPERATIONS.md` §6 vs `extensions/EXTENSION-QUERY.md` §4.3, §4.4
**Read at:** `entity-system-architecture` `0c6cadd`

### The contradiction

§6 gives `QueryResult` as:

> `entries: [{path: string, content_hash: hash, entity?: Entity}]`, `cursor: string?`, `total: uint?`

`EXTENSION-QUERY` §4.3 pins `system/query/result` as `matches` (of
`system/query/match`), `total`, `has_more`, `cursor?`; §4.3's `system/query/match` is
`{path?, hash, type}`. §4.4's not-equal operator is `not_eq`; §6's list says `neq`.

| concern | §6 (the SDK doc) | `EXTENSION-QUERY` (normative) |
|---|---|---|
| result list field | `entries` | `matches` |
| hash field | `content_hash` | `hash` |
| paging flag | *(absent)* | `has_more` |
| `path` | shown as always present | **optional** — absent for content-store-only entities (§5.4) |
| not-equal | `neq` | `not_eq` |
| entity delivery | `entity?` inline per entry | `include_entities` → a `system/envelope` with `data.included` |

### Why it is lower severity than SA-PY-2, and worth saying so

**Every one of these fails loudly.** `result["entries"]` is a `KeyError`; `neq` is a
`400 invalid_operator` from the handler; a missing `has_more` is a missing key. Nobody ships
a silently-broken query the way SA-PY-2 ships a silently-dead subscription. So this is a
**nuisance-tier** entry: it costs each SDK author one debugging session and no correctness.

It is still worth fixing, for the same reason as the others — §6 is the document an SDK
author reads, and "the SDK spec's field names are wrong, use the extension's" is knowledge
currently transmitted by rediscovery.

### What we did

`entity_sdk.query` speaks the **normative** names and aliases §6's:
`QueryResult.entries` → `matches`, `Match.content_hash` → `hash`, and
`normalize_operator` maps `neq` → `not_eq` (raising the handler's own
`400 invalid_operator` for anything unknown). The `system/envelope` wrapper the handler
returns under `include_entities` is unwrapped, so `Match.entity` reads the same either way
and callers never branch on the envelope. Enforcement:
`tests/integration/test_sdk_query.py::TestOperatorSpelling` and `::TestResultFieldNames`.

### What upstream could rule

**Align §6 to `EXTENSION-QUERY` §4.3/§4.4** — the extension is normative, the handlers
implement it, and §6 is the outlier in all six rows. The `entity?`-inline vs
`included`-envelope row is the only one where §6's shape is arguably nicer; if that is
wanted, it is a change to the *extension* and the engines, not a doc edit.

### The pattern across SA-PY-2, -3 and -4

Three entries, one shape: **`SDK-EXTENSION-OPERATIONS` has drifted from the extension specs
it summarizes**, on the event vocabulary (§3), a unit (§3), and a result shape plus an
operator name (§6). Each was found by building the wrapper the doc exists to describe. That
suggests the useful upstream action is not three patches but **a pass reconciling
`SDK-EXTENSION-OPERATIONS` against each extension's normative schema**, plus whatever gate
keeps them from drifting again — the same "declared enumeration vs. emitted value" corpus
check `EXTENSION-REGISTRY` §6a.9 already routed for a closely related failure.

---

## SA-PY-3 — `SDK-EXTENSION-OPERATIONS` §3: `rate_limit` is per-second in the SDK spec and per-minute everywhere else

**Status:** ✅ **RULED — closed 2026-08-17** (`SDK-EXTENSION-OPERATIONS` 0.8.1, **SA-3**;
verified live at arch `5f3a50b`) · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.subscription`

### The ruling

§3 now reads *"Max notifications per **MINUTE** (0.8.1, SA-3 — this line read 'per second';
`EXTENSION-SUBSCRIPTION` §2.4 is the normative schema and says per minute)"*. Resolved as
predicted.

**No change on our side.** The parameter stays `rate_limit_per_minute`: the ruling fixed the
document, and carrying the unit in the name keeps the mistake unspellable regardless of
which revision a caller read.

---

**Original entry, as filed:**

**Spec:** `sdk/SDK-EXTENSION-OPERATIONS.md` §3 vs `extensions/EXTENSION-SUBSCRIPTION.md` §2.4
**Read at:** `entity-system-architecture` `0c6cadd`

### The contradiction

`SDK-EXTENSION-OPERATIONS` §3, in the `SubscribeParams.limits` block:

> `rate_limit: uint?` — Max events **per second**

`EXTENSION-SUBSCRIPTION` §2.4, the normative schema for the same field:

> `rate_limit: {type_ref: "primitive/uint", optional: true}` ; Max notifications **per minute**

The two differ by **60×**. Our engine implements the extension's reading — a
60-second sliding window in `_SubscriptionEntry.check_rate_limit` — so we believe the
extension is right and the SDK doc is stale, but that is an inference, not a ruling.

### Why it matters more than a typo

Nothing in the response distinguishes the two. `SubscriptionInfo.limits` echoes the number
the server stored, not the window it will apply, so a caller asking for `rate_limit: 10`
cannot tell from the result whether they got 10/sec or 10/min. Two conformant peers reading
different documents would both look correct and drop notifications at rates 60× apart. The
symptom lands on the *subscriber* as unexplained missing events, far from the cause.

### What we did

Named the SDK parameter **`rate_limit_per_minute`**, so the unit is in the name and the §3
reading cannot be expressed by accident. It maps to the pinned wire field `rate_limit`
unchanged — the divergence is absorbed at the SDK boundary, not forwarded to the caller
(`AGENTS.md`, the `MAY`-absorption rule). Enforcement:
`tests/integration/test_sdk_subscription.py::TestRateLimitUnit`.

### What upstream could rule

Almost certainly: **fix §3 to say "per minute."** The extension is normative, three
implementations follow it, and the SDK doc is the outlier. Worth confirming rather than
assuming, because the opposite ruling would change engine behaviour in every impl.

---

## SA-PY-2 — `SDK-EXTENSION-OPERATIONS` §3: the `events` filter vocabulary matches nothing on the wire

**Status:** ✅ **RULED — closed 2026-08-17** (`SDK-EXTENSION-OPERATIONS` 0.8.1, **SA-2**;
verified live at arch `5f3a50b`) · **Filed:** 2026-08-17 · **Found while:** building
`entity_sdk.subscription`

### The ruling

§3 now reads *"Event types to filter (`"created"`, `"updated"`, `"deleted"`); null = all
three. (0.8.1, SA-2 — this line read `("put", "remove")`, which matches nothing on the
wire.)"* Resolved as predicted, and the ruling adopted the entry's own framing of the
failure mode.

### The decision this forced on us — the `put`/`remove` alias

While the entry was open, `normalize_events` accepted **both** vocabularies, because §3
documented `put`/`remove` as *the* filter spelling and a caller following it deserved a
working subscription. After the ruling that spelling names **nothing for this parameter**,
so the alias became a local extension — and an SDK accepting a spelling no document defines
manufactures exactly the divergence this repo exists to find in other people's stacks.

**Removed.** `normalize_events` now accepts only §3's three values.

**The subtlety worth keeping:** `put`/`remove` remain fully normative as
`ChangeEvent.event_type` in `SDK-OPERATIONS` §6.1 — the L1 `watch()` surface, which is
untouched. So a caller who reads an event off `watch()` and passes that word to `subscribe`
is confusing **two real vocabularies at two levels**, not making a typo. The 400 names the
distinction and gives the mapping (`put` → `created + updated`) rather than merely refusing.
Enforcement: `test_put_and_remove_are_rejected_and_the_error_names_the_confusion`.

---

**Original entry, as filed:**

**Spec:** `sdk/SDK-EXTENSION-OPERATIONS.md` §3 vs `extensions/EXTENSION-SUBSCRIPTION.md` §2.1, §3.1
**Read at:** `entity-system-architecture` `0c6cadd`

### The contradiction

`SDK-EXTENSION-OPERATIONS` §3, in `SubscribeParams`:

> `events: [string]?` ; Event types to filter (**`"put"`, `"remove"`**); null = all

`EXTENSION-SUBSCRIPTION` pins a **three-value** vocabulary, in three separate places:

| where | text |
|---|---|
| §2.1 notification schema | `event: {type_ref: "primitive/string"}` ; **`"created"`, `"updated"`, `"deleted"`** |
| §3.1 subscribe pseudocode | `events = params.events or ["created", "updated", "deleted"]` |
| §4 matching | `if event_type in subscription.data.events` |

The filter is an **equality test against the stored list**. So a subscription created with
the SDK spec's spelling stores `["put", "remove"]`, and every event the engine produces
(`created` / `updated` / `deleted`) fails that membership test.

### Why it is not a wording nit

**The result is a subscription that matches nothing, silently, for its entire lifetime.**
It is created successfully, returns a `subscription_id`, appears in the tree, and never
fires. There is no error and no moment at which it looks wrong — the same failure shape this
repo already catalogued for reserved `EmitPathway.subscribe` patterns.

And the audience is precisely wrong: §3 is *the document an SDK author reads*. An implementer
building a subscription wrapper from the SDK spec — which is its stated purpose — produces a
broken wrapper, while one who happens to read the extension spec instead does not.

Verified against our engine rather than argued from the text:
`test_the_raw_sdk_spelling_would_match_nothing_on_the_wire` drives the engine's own filter
expression with `["put", "remove"]` and asserts every `ChangeKind` is dropped.

### What we did

`entity_sdk.subscription.normalize_events` accepts **either** vocabulary and emits the wire's:
`put` → `created` + `updated` (which is `SDK-OPERATIONS` §6.1's own projection — "put covers
both create and update"), `remove` → `deleted`. **An unrecognized name raises `400
invalid_events`** rather than passing through, because silence is the failure being
prevented — a typo'd event must not become a subscription to nothing.

### What upstream could rule

1. **Amend §3 to the three-value vocabulary** — smallest change; the extension is normative
   and the engines already implement it.
2. **Keep §3's two values and make the handler translate** — moves the projection server-side
   and makes both spellings valid on the wire. Larger, and it changes stored subscription
   entities across impls.
3. **Say explicitly that both are accepted**, and pin which one is stored.

(1) is what we would expect and would adopt same-day. The choice matters less than that
one of them becomes the answer, because today the two documents are both citable.

### Cross-impl question worth asking with it

Same shape as SA-PY-1's: **if go's or rust's SDK built its subscribe wrapper from §3, their
`events` filter is storing `["put", "remove"]` right now and those subscriptions never
fire** — and a subscription that never fires reads as "nothing changed upstream," not as a
bug. Worth a measured read of both before the ruling rather than an assumption either way.

---

## SA-PY-1 — `SDK-OPERATIONS` §9.1 / §9.2: "implemented as `list(...)`" cannot be satisfied literally

**Status:** ✅ **RULED — closed 2026-08-17** · **Filed:** 2026-08-17
**Found while:** building `entity_sdk.discovery`
**Spec:** `sdk/SDK-OPERATIONS.md` §9.1, §9.2, §3.3, §9.3

### The ruling

**Upstream ruled option 1 — amend the note — at `SDK-OPERATIONS` 0.8.1, tagged `SA-1`.**
Verified live in `entity-system-architecture` `7cfb71d` (the entry below was written against
`0c6cadd`; the ruling had landed by the time we went to route it, which is why it was never
sent).

§9.1's note now reads *"a **prefix scan** under `system/handler/`"* with a normative box:

> **The scan MUST be recursive; a single-level `list` returns nothing useful here
> (0.8.1, SA-1).** … Implement this as a recursive walk over §3.3 `list`, or as an L0
> location-index prefix scan where one is available; **both satisfy §9.3 and neither is the
> single-level operation this note previously named.** The failure mode of the literal
> reading is an empty result rather than an error — it looks like a peer with no handlers,
> not like a bug, which is why it survived review.

§9.2 carries the same note for `system/type/`.

**No change needed here.** `entity_sdk.discovery._walk` is the recursive-walk branch the
ruling sanctions, and it was written before the ruling for the reasons the ruling gives.
Our depth cap (`MAX_WALK_DEPTH = 12`) is a local DoS bound, not a conformance narrowing —
handler and type paths are a handful of segments deep.

*(Kept rather than deleted: the file's format is that an entry records the ruling. The
analysis below is what we filed and is left intact so the ruling has its question attached.)*

---

**Original entry, as filed:**

**Spec:** `sdk-domain/specs/SDK-OPERATIONS.md` §9.1, §9.2, §3.3, §9.3

### The contradiction

§9.1 and §9.2 each close with an implementation note:

> Implemented as: `list("system/handler/")` + reading each manifest/interface entity.
> Implemented as: `list("system/type/")` + reading each type definition entity.

§3.3 pins `list` as a conformance MUST:

> Single-level. Direct children only, not recursive. … **Conformance:** L1 `list` MUST return
> entries conformant to the Entry shape (single-level, immediate children, all four fields
> populated).

These two cannot both hold, because the entities in question are not flat children of those
prefixes. Both storage conventions embed a **slash-bearing name** in the path:

| entity | written to | source |
|---|---|---|
| handler interface | `system/handler/{pattern}` | `register_handler_manifests`, `entity_core/types/registry.py` |
| type definition | `system/type/{name}` | `ENTITY-NATIVE-TYPE-SYSTEM` §4.1 convention |

A pattern is `system/tree`, so its interface is at `system/handler/system/tree`. A type name
is `system/tree/listing`, so its definition is at `system/type/system/tree/listing`. A
single-level `list("system/handler/")` therefore returns the branch `system` and **zero
interfaces**.

### Why it is not merely a wording nit

§9.3 makes membership normative:

> The returned set **MUST include every** `system/handler/interface` (resp. `system/type`)
> entity reachable under the caller's capability scope.

So the literal reading of the §9.1 note satisfies one sentence by returning an empty list and
violates a MUST two sections later. A clean-room implementer following the note gets a helper
that silently returns nothing — the failure mode is an empty result, not an error, which is
the hardest kind to notice.

### What we did

`entity_sdk.discovery` **walks** (`_walk`, depth-capped at 12, capability failures below the
root swallowed per §9.3's "absence is not signaled"). Membership is satisfied; the note is
not followed literally. Documented at the call site so the divergence is deliberate and
findable.

### What upstream could rule

1. **Amend the note to "walk"** — smallest change, matches every implementation that
   currently works, and leaves the storage convention alone.
2. **Flatten the storage convention** — escape the slashes so the prefixes really do have flat
   children. Larger blast radius; changes paths that are already load-bearing across impls.
3. **Add a discovery operation** — have the handler answer `list-interfaces` directly rather
   than making every SDK re-derive it from tree shape.

We have no stake in which. (1) is the cheapest and we would adopt it same-day.

### Cross-impl question worth asking with it

Go's and Rust's SDKs both expose `discover_handlers`. **If they single-level list, their
helpers are returning empty or partial sets right now** and nobody would have noticed, because
an empty discovery result looks like a peer with no handlers rather than like a bug. Worth a
measured read of both before the ruling, not an assumption either way — and worth noting the
absence-of-evidence hazard cuts both directions here.
