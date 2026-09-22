# entity-core-py — status

_Updated: 2026-09-12 · public: v0.8.0 (master)_

## Where it is

Python reference implementation of the Entity Core Protocol V7 (`entity-core/1.0`).
It is built clean-room — directly from the specification, with no shared code with the
other implementations — so its real job is to prove the spec is clear and complete
enough to build a compatible peer from scratch, and to act as an interoperability peer
for the Rust and Go implementations.

The codebase is a `uv` workspace of four packages in a strict tier order —
`entity-core` (0) → `entity-handlers` (1) → `entity-sdk` (2) → `entity-cli`
(presentation) — with imports only ever pointing downward, enforced by
`tests/unit/test_package_layering.py`. The declared edges are narrower than the
tiers: `entity-sdk` depends on `entity-core` alone, reaching handlers by
dispatching to pattern strings rather than importing them.

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
- **entity-sdk** — the L1 operation surface (`EntityClient`: get/put/put_cas/list/remove/
  has/watch/unwatch + `execute`), the §12 error hierarchy, path resolution, change events,
  the Level-0 `store` surface, and the L3 extension wrappers (`subscription`, `query`,
  `registry`, `revision`, `handlers`).
- **entity-cli** — the user-facing CLI (`entity-core start` / `connect` /
  `list-identities`), holding no protocol knowledge of its own.

Maturity: reasonably mature for a research preview. A broad suite — 3,722 test functions
across 209 files (unit, integration, interop, and conformance directories), 4,165 passing
with 0 failures — backs it, and `v0.8.0` ("Genesis") is cut as the initial public research-preview release.
The next release is **0.9.0** — this package set's own version, which since 0.9.0 is deliberately
**not** the protocol version it implements (0.8.2); at Genesis the two coincided because the
package version was set to the protocol version of the day, and that was a starting condition
rather than a scheme. See `CHANGELOG.md` and `AGENTS.md` §Versioning. This is
**not a 1.0 API commitment.** The canonical build/test path needs only `make` + `podman`
on the host (a pinned `Dockerfile` carries the exact Python + `uv`); local dev uses
Python 3.11–3.13 and `uv`.

## Where we left off

> **The owed validator run was taken.** `validate-complete.sh python`, **all seven passes exit
> 0**, on ports below the ephemeral floor — see the note under the number. The two-session-old
> debt from `ROUTING-2026-09-11-c` is discharged and the `0 F` covers `0.8.2.21`'s five
> authorization-path sites plus this session's three.
>
> **This session (2026-09-12) swept the `H1` exclude matrix past the five coordinates
> `entity-core-go` reports closed**, after their correction that *"nothing owed back"* had been
> a whole-matrix claim made from one seat's view. Their five confirmed against this tree; three
> findings past them, two measured in **go's and rust's** trees:
>
> - **§6.3's listing filter — three MUSTs, none of them done here.** Each entry checked
>   individually, `count` over the filtered set, pagination **after** the filter. Measured: a
>   grant excluding one child listed it anyway, `count` 2, and `limit: 1` returned **the
>   excluded child**. `extract` bundled its entity verbatim. Both siblings closed this citing
>   `EXTENSION-TREE` §8.2 — which §12.2 scopes to peers that **implement view trees**, and this
>   peer implements none, so through that citation the item reads *out of scope*. The
>   unconditional statement is in the core protocol. Ratcheted as the tenth axis of the
>   *"a routed report's claims about our repo are hearsay"* law and the first where the routed
>   claim is entirely **true**.
> - **`snapshot` is the unswept row of §8.4, and it subsumes the two that were swept.** §11
>   exempts `diff` from path checks outright; that exemption is sound only while a snapshot
>   cannot commit to bindings the caller may not see. Driven: snapshot the prefix, diff against
>   an empty one, read the excluded key **and its content hash** out of `added`. Unfiltered in
>   **both** siblings, read first-hand; filtered here now.
> - **`check_path_permission` had no PATTERN arm, and `EXTENSION-SUBSCRIPTION` §2.3 routes a
>   pattern into it by name.** A grant reading *"everything under data except `data/secret`"*
>   was **accepted** for an `include_payload` subscription on `data/*`, and delivery re-checks
>   nothing — so the excluded entity's **body** is pushed on every write to it. A push channel
>   carrying bodies, which is worse than the read leak above it. No seat has the arm at this
>   site; the cohort's vector drives the *neither* arm and cannot see it.
>
> Also: a third `G-3`-shaped site (the advertisement filter read `include` and dropped
> `exclude`) — **unreachable here** and landed with a reachability row rather than a behavioural
> one. Verified already-closed: `merge`'s per-path `put`, delegation exclude inheritance on all
> four axes, and `query`, which was the only bulk reader that already had the rule.
> Filed: **SA-PY-55 / -56**. Routed: `ROUTING-2026-09-12-a`.

**The citable number is `1644 · 1627 P · 16 W · 0 F · 1 S @ core-go `b8ee9e5`` (2026-09-12)** —
all seven `validate-complete.sh` passes exit 0, read from each pass's own summary. **The `0 F`
is the load-bearing part**: this session moved the handler-level authorization check and all
three tree bulk readers, and a change to the authorization path is a change *no local run at
this seat can measure*. Against the prior sample the delta is one check `P → W`, and it is
`concurrency.t1_1_concurrent_demux` — the documented timing warn that flips run to run. Total
unchanged at 1644, so it is a warn flip, not a check leaving the set.

⚠ **Pick harness ports below 32768.** The first attempt at this run died at pass 2 with
`[Errno 98]` on `NS_PORT`, after a clean pre-flight *and* the script's own probe — the port was
inside `/proc/sys/net/ipv4/ip_local_port_range` (`32768 60999`) and the suite's own
`t2_1_sustained_load` traffic took it as an outbound source port mid-run. It presents as *"the
namespace-scoped peer will not come up"*, one pass after an authorization change. Sixth instance
of the fixed-port class and the first that is **self-inflicted and invisible to a pre-flight**;
routed to go as a one-line harness guard.

*(Prior sample: `1644 · 1628 P · 15 W · 0 F · 1 S @ core-go `c3eaa82`` (2026-09-11) — all
seven passes exit 0 on `80a54e7`.)* The `+6` recorded at that sample over the one before it
is go's new **`resource_effective`** category (`CORE-RESOURCE-EFFECTIVE-1`, six arms), and it
fires **6/6 against a py peer on its first drive**, with no harness change at either end —
**two seats of the three-way on the resources dimension, which had never been driven
cross-impl.**

That result is attributable rather than incidental: `resource_effective_pattern_malformed`
drives `system/content:get` with a single **pattern** target, `content:get` reads its subject
through the shared three-arm helper, and deleting this session's §3.3 third arm reddens that
row (measured). The arm would have FAILED against the parent commit.

**`0.8.2.20` is absorbed.** Beyond the relay's *"one item"* (the `effective[0]` selection,
which landed 2026-09-10 at `254da7b` — **at the authorizer**, not in the helper) the ruling
carried four more pieces of work, none of them in the per-seat relay section: **R11**
(`canonicalize` is total, `NEVER_MATCH`, three ruled consumers, matcher arm FIRST), **G6**
(every `validate_absolute_path` call site consumes its verdict), **§3.3's third arm**
(a single pattern effective target → `malformed_resource`), and **§6.7's withdrawal** of
*"the handler-level path check is secondary."* Wiring G6 found two things nothing else could:
a `/*/*` grant covers a target rooted at a non-peer segment (the sentinel does not close it —
only the consumed verdict does, and `entity-core-go`'s `validConcreteTarget` drops that
clause, routed), and `is_peer_id` compared `!= 46` where §5.4 calls 46 a **minimum**.

Also this round: the **403 code slot censused for the first time** — thirteen spellings the
corpus defines nowhere, twelve ledgered for their owning tables (SA-PY-51) and `forbidden`
swept to `capability_denied` at ten sites, two of them `system/tree` `get`/`put`; the
**continuation advance's three forwarders** dropping the caller's `exclude` (go's `-11-a` §3
shape, reached through a *suspension* rather than a copy); and **SA-PY-50**, a `[MUST]` whose
literal pseudocode neither ground-up seat implements and nothing can detect.

*(Prior sample: `1638 · 1621 P · 16 W · 0 F · 1 S @ core-go `b320c1e`` (2026-09-10) —*
all seven `validate-complete.sh` passes exit 0, image built from `614a9d8`. **The 2 F are
gone**: go re-based the two `system/*` checks onto `0.8.2.13`'s withdrawal, which is what the
entry below said was theirs to do. The one skip is **declared**, not unmeasured —
`connectivity.handler_not_found_on_unregistered_path` under §3.3's total-handler exception
(0.8.2.8, cf SA-PY-36): this peer registers a catch-all `*`, so the 404 row is not drivable
against its posture. Check count `1637 -> 1638`; warns `15 -> 16`, the delta being
`t1_1_concurrent_demux`, the documented timing warn that flips run to run (it was absent from
the 2026-09-09 first sample and present in the second).*

**The four F63/E3 origination rows PASS** (`dispatch_outbound_{reentry,ambient_refused,
narrow_grant_refuses_out_of_scope,multisig_root_refused}`), which is go's sharpened §7a.1a
WARN retiring against this tree — it now discriminates on `capability_denied` and py surfaces
it. And `multisig.valid_2of3_peer_signed_accepted` PASSes on the wire, which is the
measurement SA-PY-49 rests on: py's `E3` blindness is one call site without a by-signer
finder, not an inability to verify a multi-signature root.

*(Prior sample, 2026-09-09: `1637 · 1619 P · 15 W · 2 F · 1 S @ bef708b`,*
and **both F were the withdrawn `system/*` rule, not this peer.** `0.8.2.13` withdrew V7 §6.2's
*"user-installed handlers MUST NOT register at `system/*`"*; we landed the withdrawal, and go's
`core_register_reserved_refused` / `_publishes_nothing` still assert `403 forbidden_pattern` for
it. Arch already ruled that disposition to go and the re-base is theirs. **The seat that
implements a withdrawal first is the seat that goes red on the gate that has not caught up** —
there is no ambiguity to resolve here, only a sequencing cost that lands on whoever moves
first. **Discharged: both rows are green at `b320c1e`.**)

Second sample the same day: `1618 P · 16 W`, the one-check delta being `t1_1_concurrent_demux`,
the documented non-violation timing warn that flips run to run. The check count moved
`1624 -> 1637`. **One warn is new and is ours**: `convergence.bisync_a_to_b` (`PASS` with PD-2
disabled in a control run, `WARN` 2/2 with it on) — attributed, not localized, and written up in
`docs/status/ROUTING-2026-09-09-…` §11 rather than absorbed into the baseline.

This session landed `0.8.2.11 -> 0.8.2.17`: PD-2's outbound sub-dispatch check (both arms), the
`0.8.2.16` id-scope fix in `scope_subset` plus the `peers` attenuation that was missing there
entirely, the `path_required` per-operation audit, and — outside the relay's diff, because it was
scoped to go's baseline — `0.8.2.13`'s `system/*` withdrawal and `EXTENSION-COMPUTE` v3.29.

**The previous citable number was `1624 · 1610 P · 14 W · 0 F · 0 S @ core-go `d42752b`` (2026-09-02)** —
all seven `validate-complete.sh` passes exit 0 against a committed tree, `connectivity`
**36/36**. The count moved 1622 → 1624 on two checks core-go added for CE-1 and row 10's
established arm; both PASS. The warn count moved 15 → 14 and **the drop is not attributed** —
the previous run's warn list is not in this session's records, and a one-warn delta explained
from memory is the shape this repo's own flaky-gate rule forbids. This run's 14 are the standing
set, enumerated: 10 × `type_system` (open-type census), 2 × `local_files` (a go-only extension),
`resource_bounds.r3_connection_flood`, `peer_issued.v6_offline_not_found`. None is new.

**Two relayed rulings landed, and the interesting one is that CE-1 was never unruled.** core-go
measured a pre-establishment non-connect EXECUTE on all three live peers — `403
connection_required` · `400 handshake_failed` · `403 capability_denied`, no two alike, none in
any spec code set — and routed it by the divergence rule as *tighten the spec*. **§4.2's third
pre-authorization bullet had ruled it at 0.8.1**, where F32 replaced that bullet's blanket 403
with the auth/authz discriminator; §5.2a gives the code. All three seats were reading §4.7,
which declares itself the MUST-emit contract for that surface and had no row, while §4.2 states
the rule in the vocabulary of *pre-authorization*. 0.8.2.5 adds the pointer and names both
minted codes non-conformant.

Ours is now `401 authentication_failed` at **both** wire boundaries — the relay named the TCP
one; grepping the *gate* rather than the site found the HTTP transport carrying its own copy,
which no probe in the cohort can reach. The sharpest statement of the defect needed no
cross-impl run at all: this peer already answered `401 authentication_failed` for the identical
frame one state later, so it was disagreeing with itself. **SIGNALING v1.2** ruled SA-PY-33 our
way with one correction — the wrong line was **§4.3** (the wrapped handler section), not §9.2's
unwrapped enum, which is unchanged — and the `bad_request` ratchet's one exemption retired on
the condition it had written down, to a hard zero. Routed in
`docs/status/ROUTING-2026-09-02-c-…`.

**The previous citable number was `1622 · 1607 P · 15 W · 0 F · 0 S @ core-go `00261f3`` (2026-09-02)** —
all seven `validate-complete.sh` passes exit 0 against a committed tree, `connectivity`
**34/34**. The count moved 1619 → 1622 on three checks core-go added for the fold's other half
(`connect_second_hello_mid_handshake`, `connect_ping_before_hello`,
`connect_authenticate_peer_id_mismatch_hello`); we owed one of the three and it is landed.

**The routed row and the row nobody probes are one defect.** core-go measured a pre-handshake
`ping` here at `400 invalid_request` where 0.8.2.4 pins `409 connection_sequence_error`. Their
other two findings were verified here rather than accepted — the peer-id cross-check and the
mid-handshake second hello were already right, as reported. Walking row 10 a second time (the
first walk was 2026-09-01, and the row had since been re-cut on a **predicate** rather than on a
list of inputs) found the mirror: an unknown operation on an **established** connection answered
`409 connection_already_established`. One predicate — *does the responder implement this
operation* — classified by two hand-rolled inventories at the two wire boundaries, disagreeing in
opposite directions. Both now read one set. **go and rust hold the established arm correctly
(checked first-hand), so py was the only seat wrong and no cross-impl run could have said so:** a
probe dials in, so every state it reaches cheaply is a pre-handshake state, and an *"in any
state"* clause is systematically driven in one state. Routed with the suggested probe in
`docs/status/ROUTING-2026-09-02-b-…`.

**The previous citable number was `1619 · 1604 P · 15 W · 0 F · 0 S @ core-go `5cd60fe`` (2026-09-02)** —
all seven `validate-complete.sh` passes exit 0 against a committed tree, `connectivity`
**31/31**. The count moved 1618 → 1619 because the oracle gained exactly one check —
`connect_absent_protocols` — and it PASSes; the 15 W is unchanged from the previous run, which
is measured rather than assumed.

**FM-2e is landed, and it is the arm we filed, ruled the other way.** SA-PY-31 asked what a
hello with no `protocols` field means; we had shipped *unconstrained*, matching
`entity-core-go`, on the ground that refusing where a sibling accepts partitions the cohort.
0.8.2.4 ruled it **`400 invalid_request`** — a malformed request, not a version incompatibility
— and §4.7 row 1 narrowed to a *non-empty* disjoint set. Our filing's argument carried the
ruling (`incompatible_protocol` says *"we compared and share nothing"*, which cannot be said to
a caller that named no version); our cohort-consistency **fallback** was wrong, because the
cohort is not the two ground-up seats — keystone's 46 generated peers already required the
field. SA-PY-32 was ruled in our shape in the same fold: §4.5's row now names §8.4's literal.

**Two findings went back with it.** Read first-hand, the keystone peers the ruling *cites as
its justification* do not implement it — the absent arm answers `400 handler_error` and the
empty arm answers `400 incompatible_protocol` (reading 3, which 0.8.2.4 forecloses), so
`connect_absent_protocols` will FAIL against the conformance anchor and that FAIL is the check
working. And walking §3.3's **code set** (rather than §4.7's rows) found that `bad_request` —
this kernel's generic 400, carried in a *default argument* at 12 sites — is in no spec code
set; it is now `invalid_request`, with `invalid_path` / `invalid_params` where §3.3 names them.
The one survivor is `EXTENSION-SIGNALING` §9.2's **closed** enum, which pins `bad_request` for
the class §4.7 forbids a synonym for — a corpus conflict `entity-core-go` shares verbatim,
filed as SA-PY-33 and exempted by name rather than fixed unilaterally. See
`docs/status/ROUTING-2026-09-02-a-…`.

**The previous citable number was `1618 · 1603 P · 15 W · 0 F · 0 S @ core-go `7262f17`` (2026-09-01)** —
all six `validate-complete.sh` passes exit 0 against a committed tree: pass 1b
`761 · 646 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `32/32`, substitute `8/8`, pass 4
`2/2`, pass 0/0b static `63 PASS · 0 FAIL`.

**The W moved 14 → 15 and it is not this diff — but the two claims are separate and only the
first is evidenced.** `concurrency.t1_1_concurrent_demux` is a timing-ratio check (N=16
concurrent vs sequential, ceiling 0.70) that PASSed the previous run and WARNed this one. The
measured numbers, recorded rather than the verdict, because a re-run to green reads identical
to a green: `201.46 ms / 211.61 ms = 0.95` and `79.89 ms / 65.65 ms = 1.22`. The absolute times
differ threefold between runs while the ratio moves the other way, which is the signature of
host load rather than of the peer. It is the same family as the standing `t2_1_sustained_load`
caveat and gets the same treatment: **not** a claim that the demux path is sound. What *is*
established is that nothing in this diff is on it — the diff is the connect handshake — and
that the §6.11(a) no-serialization MUST is carried by `t1_3_no_head_of_line`, which PASSes.

**§4.7 row 10 is implemented — both halves.** arch's FM-2 Edit D found the row to be two
failures wearing one code and one status, and it is landed here as ruled: a second `hello`
mid-handshake is a **state conflict**, `409 connection_sequence_error` (row 9's precedent, and
§4.6's Hardening block presumes 409 is what a state conflict gets); an **unknown connect
operation** is `400 invalid_request`, because nothing is out of *order* when the name exists in
no state, and a code that misdirects the client's remedy fails the contract §4.7 exists to
provide. All three seats are now on the ruled behaviour ahead of the fold rather than after it,
which is the posture the cohort works in — implement, report what building it finds, and let
the fold ratify. Keepalive is unaffected: our connect branch is gated on
`not conn_state.is_connected`, and §5.1 `ping` is served from the established path.

The same run closed §4.7 **row 1**: `connect_incompatible_protocol` PASSes. Landing it found that
this peer had advertised **`entity-core/7.0`** since Genesis where V7 §8.4, `entity-core-go` and
`entity-core-rust` all say **`entity-core/1.0`** — invisible for the life of the project because
§4.5's `protocols` intersection had no implementer in *any* tree, so every peer carried the field
and none read it. Measured against a live go peer, py could not dial go at all. Both directions
green; the constant now has one home and a pin against §8.4. See
`docs/status/ROUTING-2026-09-01-c-…` and SA-PY-31 / SA-PY-32.

**The previous citable number was `1616 · 1602 P · 14 W · 0 F · 0 S @ core-go `d7a5847``** —
all six `validate-complete.sh` passes exit 0 against a committed tree: pass 1b (core profile)
`759 · 644 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `32/32`, substitute `8/8`, pass 0/0b
static `63 PASS · 0 FAIL`. Three checks that FAILed or could not look against py before this
session now PASS: `connectivity.connect_authenticate_bad_signature`,
`connectivity.connect_authenticate_identity_mismatch`, and — against a peer started with
`--relay-store-retention-ms` — both `relay_store_bounds` rows. The two v1.3 `type_system` relay
WARNs are gone; the remaining 14 W is the standing baseline.

**Two runs preceded that number and neither is citable — recorded because the verdict is not
the measurement.** Run A scored `PASS 1` at **4 checks**: a `validate-complete.sh rust` started
by another session was live on the host, which the standing pre-flight (`ps aux | grep
validate-complete`) would have caught and did not, because it was run *before* the other
session's began. Run B, immediately after that run drained, died mid-pass-1 — the peer dropped
`4836/10000` requests in `concurrency.t2_1_sustained_load` and then stopped accepting, taking
every subsequent category with it (~200 rows at `0s` elapsed, which is the signature of a dead
peer rather than of a conformance failure). **Run C is the green one above, and the crash did
not reproduce**: driven in isolation against a fresh container, `concurrency` is `6/6 PASS`
including `t2_1`. So the honest statement is that the gate is green and that one run in three
on a host under heavy concurrent load killed the peer under sustained load — *not* that the
sustained-load path is sound. The distinguishing evidence has not been gathered, and the two
claims ("not my diff" and "not the peer") are separate: t2_1 drives `tree.get`, which nothing
in this session's diff is on.

**Both units core-go routed on 2026-09-01 are closed (§4.7 and RELAY v1.3).**

- **§4.7 connect-error rows (G-28/FM-1g).** go's probe family measured rows 7 and 8 — an
  invalid authenticate signature, and a `peer_id` not derived from its `public_key` — as
  `400 bad_request` here. Confirmed against our own tree before acting, and the cause was
  the one FM-1d had already exposed one function up: the raises carried a message only, and
  `ConnectError` defaults `code` to `bad_request`. Reading the whole table against the
  function found **four more rows no probe drove**: row 6's *mismatch* arm (FM-1 fixed only
  its pre-hello arm), row 8's *second* named input (`hello`/`authenticate` peer_id
  disagreement), §4.6 step 2's *absent*-signature arm, and row 10, whose code
  `connection_sequence_error` this peer emitted for neither of the row's two inputs. All now
  carry the `(status, code)` pair. Row 10's status is the table's 400 with the contest stated
  inline — go emits 409 and routed it as spec-issue `2026-09-01-b`; only the status is in
  question, and `bad_request` was in no row at all.
- **RELAY v1.3 `[RL-P]`** — D4 (§8.1 retention ceiling: clamps, never refuses, with the null
  arm stated), D5 (§8.2: `storage_full`/507, no eviction, dedup-stable), D7 (§3.1
  `forward-request.expires_at` honored on the §6.2.1 fallback, clamped, never extended), §4.1
  publication of the enforced bounds — **and the advertise is now signed**, which §4.1
  requires and a test *named* `test_advertise_publishes_signed_entity` had been asserting only
  the bound path for. `storage_full` did not exist in this tree at all before this pass, which
  is a step past go's and rust's dead constant. Operator knobs
  `--relay-store-retention-ms` / `--relay-max-storage-bytes`, named to match the Go peer's
  exactly so peer-manager can arm us by name.

**Two findings routed back, both from building rather than from reading.** `SA-PY-30` —
`forward-request.expires_at` is dropped at every intermediate hop, in both implementations
that have D7, so on `A→B→C→D` the deadline dies at `B` and `C`'s fallback stores unbounded;
that is §3.1's *"MUST NOT extend a deadline the originator set"* reached by omission, and
neither seat's no-extend test catches it because both drive the single-hop shape. And a gap in
our own landing that only the cross-impl run could see: the v1.3 **type definitions** were not
updated with the behaviour, so `type_system_relay_forward_request_match` WARNed
*"optional locally, missing remotely"* — a peer type-checking against our published
`system/type` would have rejected a request we ourselves send.

**The previous number was `1613 · 1598 P · 15 W · 0 F · 0 S @ core-go `50f2140`` (2026-09-01)** —
all six `validate-complete.sh` passes exit 0 against a committed tree: pass 1b
(core profile) `756 · 641 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `32/32`, substitute
`8/8`, pass 0/0b static `63 PASS · 0 FAIL`. The 15 W is the standing baseline (it includes
`concurrency.t1_1_concurrent_demux`, a timing-sensitive informational check that flaps). Both
of the cohort's new checks PASS: `authz.dispatch_inbound_foreign_namespace_refused` and
`connectivity.connect_prehello_authenticate`, each of which was FAIL against py before this
session. No concurrent validator run and no leftover peer on the harness ports — pre-flight
checked, and this run reaped its own containers.

**Two relayed wire fixes landed, and the relay was wrong about one of the remedies
(2026-09-01).** `entity-core-go` routed PD-1h and FM-1d after arch folded PD-1 at protocol
`0.8.2.2` and corrected it at `0.8.2.3`.

- **PD-1h — an inbound EXECUTE naming a non-local peer is now `400 invalid_request`.**
  §1.4 requires the refusal at canonicalization and §6.5 step 3 makes it a *gate*,
  not an ordering preference. Reproduced here before fixing, independently of the relay: under
  a grant whose `peers` scope covered the named peer we answered **200**, having executed our
  own `system/tree` handler under someone else's address; under a narrower grant we answered
  403, which is the right refusal from the wrong layer and is exactly the shape §6.5 step 3
  forbids. The gate reads the **handler** uri only — a foreign `resource.targets` entry under a
  local handler uri is the §1.4 universal-address-space slot and stays conformant.
- **FM-1d — a pre-hello `authenticate` is `401 invalid_nonce`**, where it was
  `400 bad_request`. **The relayed remedy was insufficient and would have read as fixed.** It
  said to set `code="invalid_nonce"` on the raise, *"it carries a 401"*. In this tree it does
  not: the wire boundary called `ExecuteResponse.bad_request(..., code=…)`, which hardcodes
  status 400, so applying the relay verbatim yields `400 invalid_nonce` — a pair in no §4.7 row
  either, on the one surface whose entire defect was a pair in no §4.7 row. The boundary now
  emits the (status, code) **pair**; §4.7 is a table of triples and three of its ten rows are
  401. Mutation-verified in both halves — status-only and code-only each redden the headline
  rows.
- **The default handler self-grant drops `peers`**, per §6.2's shape pinned
  normatively at `0.8.2.3`. Split out of `create_full_access_grant`, which was carrying three
  different authorities behind one name; the two that legitimately reach across peers keep
  their wildcard.

**And the ruling that pinned that shape argues from an enforcement point no shipping peer has
— filed as SA-PY-29.** §6.2 justifies omitting `peers` with *"a default-scope handler
consequently **cannot** dispatch at a foreign peer."* That is a claim about where a check runs,
and here it runs nowhere: inbound, PD-1h now refuses before `check_permission`; in-process,
`_dispatch_local_execute` returns at `_remote_execute` **before** `_resolve_for_dispatch`, and
`target_peer` is computed below that return, so the only value that can reach the check is the
local peer. Measured: a handler holding exactly the ruled grant, sub-dispatching at
`entity://{foreign}/system/tree`, gets **502 "No live transport profile"** — the peer went
looking for a *route*, i.e. it had already decided the dispatch was permitted. `entity-core-go`
measured the identical structure in their own tree and said so first (spec-issue
`2026-08-23-a`), asking for a vector that reaches the ceiling with a cross-peer uri; `0.8.2.3`
delivered the ruling and not the vector. Filed rather than fixed — inventing the check would
refuse a sub-dispatch go permits, manufacturing a cross-impl divergence out of a spec gap, and
would silently re-ceiling every cross-peer handler in the tree. Pinned as behaviour by rows
that **fail when the enforcement point lands**, each carrying its retirement condition.

**PD-1h also retired a seam two of our own tests were standing on.** `test_authz_peers_dimension`'s
over-the-wire rows asserted `403` from §5.2 Dimension 4; post-gate that answer is `400`, and a
403 there is now a *failure* because it would mean the refusal came from authorization after
resolving the local handler. The rows were re-pointed rather than deleted: they still
discriminate the gate, including on a request the grant would have permitted — which is the
case a peer with only an authorization path gets wrong.

**The leaked peers were ours, and the fix was never "be more careful" (2026-08-22).**
Five entries in `AGENTS.md` describe tripping over a leftover peer on a fixed port; every
one of them ends in a *detection* rule, because from the tripping side the leftover is
someone else's artifact. Measured from the creating side, `cmd_start` ended in a bare
`await peer.serve_forever()` and installed **no signal handlers at all**, so (a) a peer
started by hand ran until something signalled it, and an agent on this host cannot signal
anything, and (b) `ENTRYPOINT ["entity-core"]` makes the peer **PID 1**, where the kernel
discards an unhandled SIGTERM rather than applying its default disposition — `podman stop`
paid its full timeout and SIGKILLed, every time. The `except KeyboardInterrupt` arm that
looked like the shutdown path never ran either (measured pre-fix exit was `-2`, not `0`).
Landed: `--max-lifetime` defaulted from `$ENTITY_PEER_MAX_LIFETIME` (`d1bf909`), SIGTERM/
SIGINT handling (`e98d270`), and — from a flaw in that same change — a `serve_forever()`
crash is re-raised rather than parked by `asyncio.wait` and silently exited 0 (`3d09f02`).
Five mutations, each RED on exactly the predicted rows.

**The interop suite did not fail, it hung — and had for as long as a foreign container held
9000.** `AGENTS.md` records "a liveness probe that tests for a socket rather than for a peer"
as a ratified lesson, but only one module was ever written to it; five others each carried
their own socket probe. With an unrelated Selenium container on 9000 the probe saw a
listener, the skip did not fire, and pytest blocked in `ep_poll` **forever** against a server
that will never speak this protocol. One shared `tests/interop/peer_liveness.py`, all five
converted (`a56008a`): handshake and remote peer id, bounded by a timeout. `tests/interop/`
now finishes in 30s.

**The headline cross-impl row had never passed in visible history** (`85c75be`).
`PINNED_ROOT_HASH` shipped as the byte ladder `0xc0..0xdf` — a stub nobody filled — and read
green everywhere because it `skipif`s without the Go toolchain. It is now filled with the
signature-verified value Go's published root carries (`af1c9f6b…`, measured identical across
three separate fixture publications). This reverses yesterday's "not derivable, route it"
call on evidence: the value is not ours to produce — `fetch_verified_root()` reads it from
inside Go's signed `published-root` entity, so a wrong value would have to be signed by the
publisher's key. go's own consumer pins nothing here and only prints the root, so ours is
the stricter check. The placeholder detector lives in `tests/unit/` with **no** `skipif`,
because needing Go is precisely what hid this.

**Release gate green, and the first measurement of it was void.** Run 1 reported 301 failures
with the peer dying mid `t2_1_sustained_load`; a full **rust** `validate-complete.sh` was
running concurrently on the same box, which our own rule says makes neither result citable.
Re-measured on a quiet host: `1611 · 1596 P · 15 W · 0 F · 0 S @ core-go 0709688`, all six
passes exit 0, `t2_1` PASS at 40.9s. The numbers are recorded across both runs rather than
the verdict of the one that was green.

**The eval-limit ruling said py already complied, and py did not (2026-08-22).** Arch ruled the
§8 carve-out (`PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS` §§8–10, routed as `ROUTING-2026-08-21-h`)
and its opening premise names what each seat does: *"rust and py … **contain** `depth_exceeded`."*
§5.3 concludes *"Nothing owed"*, and core-go relayed it as *"C-14 — you were right."* **We
short-circuited all three limit codes** (`_EVAL_LIMIT_CODES` at `f09ae70`), and our own SA-PY-25 says
so in its second paragraph — arch read that filing's argument about the *discriminator* as a position
on the *outcome*. Landed at `cca75fd`: the set is `{budget_exhausted, cascade_limit}` — the two
counters §5.1 does **not** restore on unwind — and `depth_exceeded` contains like any other error,
because `depth` *is* restored and is therefore element-local. Five rows, each mutation-verified RED
beforehand, plus the one that would have caught this unaided: **assert the property the ruling
reasons from** (`depth` restored on unwind), on the budget object, driven bare so it is orthogonal to
the carve-out it is not about.

**A wrong premise in the *flattering* direction produces no task at all** — that is why this sat
green at three seats. The other shapes of this law (wrong about our architecture, our coverage, our
version) all fail loudly the moment you open the tree. Ratcheted into `AGENTS.md`.

**D8 is landed and had a second site nobody named.** §7.1's `walk` is now recursive **by rule**
(`b3a595d`) rather than correct by enumeration of today's grammar. Arch measured `_walk_deps`;
`_audit_walk` carried a hand-rolled copy of the same four cases, and there the consequence is worse —
a `compute/apply` nested past the enumerated shapes is never reached, so its **install-time
capability/resource check and the F5 structural error never run** and the subgraph installs clean.
Both walkers now share one traversal. Rows (a)/(b) — go's two wire checks — passed here *before* the
fix, which is the point: the discriminating rows are the ones at nesting the grammar cannot express,
and no boundary-hash vector can see them.

**Writing clause 3's grep found two defects in clause 3 (SA-PY-27).** `compute/construct.fields` is a
**third** `{map_of: system/hash}` reference container the enumeration of two omits; and
`compute/let.bindings` is declared `{array_of: primitive/any}`, so the grep **cannot match the one
shape D8 exists because of.** Our conformance does not depend on either half — clause 1's prose
`[MUST]` is implemented as a real recursive traversal — and the blind spot is pinned as a row rather
than worked around.

**The compute cross-bless is LOCKED, 362/362 byte-identical go↔py**, wire corpus
`333de571b27c513c` at go `e777412`, both peers driven over the wire this session (C-18 discharged).
**Our first run reported one divergence and it was our comparison, not the peers:** py's *wire*
emission against go's *in-process* one. `peeremit.go` sends a scalar operations budget and **there is
no wire field for `depth`**, so CV-9a — whose answer is a function of depth — answers `[1, E, 1]` on
route A and `[1, 60, 1]` on route B. Localized by measurement: py in-process at the vector's real
budget produces `00289092…2017f`, go's in-process boundary byte for byte, now pinned in-tree as an
oracle constant. **The half worth flagging past the green:** over the wire CV-9a raises no error at
all, so on the route both siblings use to cross-bless, *the vector authored for the depth ruling
locks green while exercising nothing about it.* Routed to core-go as a harness fix; nothing owed at
py or rust.

**D3's window is closed.** py landed it first and carried the deliberate `1F`; go landed at
`0e1f604`; **rust landed at `69998ac`**, which is arch §9 clause 4 satisfied. `type_system` measures
**436 P · 10 W · 0 F** against py this session — the transient FAIL is gone.

**C-12** needed nothing: `store`'s `path` is absent from `_CONTAINED_ARGS`, so it short-circuits at
the arg loop, and `TestStorePathIsConsumed` has checked it since `0b2d946` with a `type_mismatch`
control.

**The citable number is `1611 · 1597 P · 14 W · 0 F · 0 S @ core-go `e777412`` (2026-08-22)** —
`validate-complete.sh python` **exit 0, all six passes**, from the committed tree. The total rose
1609 → 1611 with go's two D8 wire checks, and **the `1 F` is gone**: it was the D3 transition, and
rust closed the window. `make test` / the full suite is **4035 pass · 2 fail**, both of them the
`PINNED_ROOT_HASH` placeholder routed to core-go 2026-08-21 and still unfilled at `e777412`.

**Two measurement notes, because a number is only as good as what it did not run.**
*(i)* The **first** `validate-complete.sh` run this session was `1591 P · 6 F`, and all six were
`peer_issued` reporting `bind: address already in use` on **`127.0.0.1:9401` — a peer this session
started itself**, which the fixture registry binds by default. Re-measured with `PI_PORT=9411`
rather than attributed: 0 F. Fourth instance of *a validator failure on a fixed port is a leftover
peer until proven otherwise*, and the first where the leftover was ours **and still running** — the
harness blocks agents from killing processes, so the fix was the environment override, not a kill.
*(ii)* **`tests/interop/` did not run**: `127.0.0.1:9000` is held by an unrelated Selenium container
on this host, so `rust_peer_available` sees a listener, does not skip, and the suite hangs
mid-handshake. That is the documented third instance, and the suite is reported **unrun**, not green.

---

**C-8's closure-result positions are landed, and `fold` went the other way at core-go
(2026-08-21).** Arch ruled `map`/`filter`/`fold`'s closure-result positions (`172589e`), replacing
v3.26's *"exactly three contained positions"* with the rule that generates it: **a position CONTAINS
when the primitive places the value without reading it, and CONSUMES when it reads it to decide.**
Landed at `0b2d946`: `map`'s output element contains (§1.5's NaN model is element-wise, so
`map(f,[1,0,2])` is `[a,E,c]` and not one `E`); `fold`'s accumulator contains and `initial` joins the
contained-args table, so **a closure that ignores its accumulator recovers**; `filter` stays consumed
(already correct); and **D3** — `concat-args.collections` is one scalar hash, because §7.1's reactive
walk descends only on *scalar* `system/hash` fields and the declared array shape leaves every
`lookup/tree` inside every `concat` sub-collection unregistered.

**The nothing-broke was the finding:** changing `map` and `fold` broke **zero** of 3998 tests. The
suite *and* a 352-vector corpus cross-blessed byte-identical three ways had never put an error in a
closure-result position.

**Four divergences confirmed on the wire against go `9ad0110`** (`c3f9b87`), with the identical rows
**12/12 green against a py peer in the same session**: `fold` short-circuits an accumulator the
ruling makes contained (go reads arch's word *"propagates"* as *abort*; arch's D2 lists *"fold's
final accumulator"* in the contained set of five); `fold`'s `initial` short-circuits; a **value-form**
`budget_exhausted` is contained on go and propagated here, because go's eval-limit carve-out sits on
its *minted* arm only — the §2.4 provenance asymmetry that same ruling closed, re-opened three codes
wide; and **§8.2 canonical arg order**, `coll_error` vs `idx_error`, which became measurable the
moment go fixed `resolveCollection` (`ded9ea0`) and discharged the retirement condition our `skip`
carried in writing.

**The corpus locked anyway, and stating both facts together is the point.** Route B at **358
vectors** (wire corpus `b7e5b023…`, in-proc frozen `ffb6e354…`) cross-blesses **LOCKED, 358/358
byte-identical go↔py** at exactly the commits where those four rows disagree — go's CV-8c seeds
`fold`'s *position* and not its *discriminator* (one element, closure returns the error: both
readings answer the same), so the vector cannot see the divergence. Arch's CV-8**d** is the shape,
and it was not in the set.

**The citable number is `1609 · 1594 P · 14 W · 1 F · 0 S @ core-go `9ad0110`` (2026-08-21)** —
passes 0/0b/1b/2/3 exit 0, pass 1 exit 1; `make test` **exit 0, 4024 pass / 0 fail / 48 skip**.
**The 1 F is ours and deliberate:** `type_system_compute_concat_args_match` fails because py landed
D3 and go's served declaration is still the pre-ruling `array_of(system/hash)`. It is
declaration-only — nothing on the wire moves — and it retires when go lands the same one-line edit.
Two SAs filed: **SA-PY-25** (an evaluation limit has no representation of its own, so both seats'
carve-outs discriminate on the wrong thing in opposite ways) and **SA-PY-26** (none of C-8's four
deltas are in `EXTENSION-COMPUTE.md`; the file is v3.26 and §3.5 still ships the sentence the ruling
contradicts).

---

**COMPUTE v3.24 → v3.26 is landed, and the routed baseline was three versions off (2026-08-21).**
core-go routed `2026-08-21-a` — `-f` (v3.26's contained-`compute/error` boundary form) and `-g`
(content-URL full wire form) — saying *"rust and py are not yet on v3.26."* True, and it hid the
state: **py was on v3.23.** v3.24 and v3.25 were never routed here, so §3.5's three contained
positions (`assoc`'s `value`, `concat`'s elements, `group-by`'s `members`) **did not exist to carve
out**. Proved before acting (`git log --all -S assoc -- packages/` is empty), and built all three
versions rather than the carve-out alone — a carve-out with no site is a green diff that unblocks
nothing. **A wrong claim about our version fails silently and in the flattering direction**, unlike
the shape/coverage claims this rule was earned on.

`-g` needed no behaviour change at all: `build_content_url` and the serve route (`validate_hash`,
F-PY-13) were already format-relative, and there was no hardcoded-66 gate to remove. What was owed
was teeth, including the row §6.5.3 names by hand and we lacked — a **98-char hex claiming `00`**,
which is exactly what the natural `len in (66, 98)` "fix" accepts.

Two pre-existing holes surfaced that the ruling never mentions, both made routine by v3.24:
`_materialize_bare` had **no array branch**, and **scope capture had the same hole one branch over**,
so `let g = group-by(…) in map(g, fn)` killed the handler task on the CBOR encoder.

**The citable number is `1609 · 1594 P · 15 W · 0 F · 0 S @ core-go `f14cc2c`` (2026-08-21)** —
`validate-complete.sh python` **exit 0, all six passes**, from the committed tree; `make test`
**3998 pass / 0 fail / 43 skip**. **The validator carries no v3.24+ compute checks**, so `-f` is
*not* verified by it —
saying so because "exit 0" would otherwise be read as covering it. What does verify it is the
**compute-corpus cross-bless, route B**: wire corpus `048e67aefc5ecd58` (352 vectors) driven over the
wire against a live py peer and cross-blessed against go's emission → **LOCKED, every vector
byte-identical**, 6 advisory message-text differences only. **That is the C-5 go↔py leg, including
CV-4a and CV-5**, which had never been three-way'd.

**Three findings routed back** (`ROUTING-2026-08-21-…`): go answers `type_mismatch` where §7.2
requires a short-circuit for an error-valued **collection** operand, at **three** call sites
(`concat`, `assoc`, `group-by` — `resolveCollection` uses `Evaluate` where `evalOperand` is
required), measured on the wire with three discriminating controls and **all six rows passing against
a py peer**; a §8.2 canonical-arg-order divergence that is **predicted and currently unmeasurable**
because the first defect masks it, carried as a `skip` with a written un-skip condition rather than
an `xfail`; and a py-side gate that has **never passed** —
`test_cross_impl_publish_fetch.py`'s `PINNED_ROOT_HASH` is the placeholder byte sequence
`0xc0..0xdf`, green on ordinary runners only because it `skipif`s when the Go toolchain is absent.
**A source reading gave the site; only the trace gave the extent** — two of the three call sites came
from running it, and go's own 352-vector corpus cross-blesses LOCKED because none of these
configurations is in it.

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

**R-27 is ruled and row 8 is green on the wire (2026-08-20 b).** Arch ruled go's spec-issue
`2026-08-20-a` the same day (`08841d8`): pin authority is authority over the **non-dispatchable**
operation `pin-bindings`, Option 1. Our `_OP_PIN_BINDINGS` already matched — **and the derivation is
not ours and is stronger**: arch reads it off **V7** (a grant scopes on path-scope and id-scope only,
and the path axis is *explicitly non-portable*, so the operation name is the **sole portable**
discriminator), where ours was *"a resource split discriminates nothing **here**."* **All four
clauses were already true here**, which is a coverage finding rather than work avoided — the normal
forcing function for a test is a behaviour change, so a ruling that demands none leaves the surface
exactly as untested as it was before it became normative. Pinned at `fcdc168`, four rows,
each mutation-verified: dispatchability, byte-identity-without-field-drop, ordering, and **ordering's
*reason***. Clause 4 was arch's flagged open question at this seat: we had the right code for a
weaker reason — the ruling's is an **information-disclosure control** (§4.3's refusal is deliberately
verbose, so validating first hands a config-shaped disclosure to a caller with no authority to change
anything), so the row asserts the **response body**, not the status. The byte-identity row exists
because `entity-core-rust` found a live **fail-open in `entity-core-go`** (`f44ed4d`, a typed-struct
decode dropping §4.2 forward-compat keys); arch records that py has no field-drop, and **we verified
that claim about us rather than accepting it.** Full detail: `ROUTING-2026-08-20-…` §6.

**The citable number is `1601 · 1586 P · 15 W · 0 F · 0 S @ core-go `d697b9a`` (2026-08-20 b)** —
the full armed `validate-complete.sh python` from the **clean committed tree** at `25c3c96`, **exit
0, all six passes**: pass 1b `747 · 632 P · 12 W · 0 F · 103 S`, pass 2 `55/55`, pass 3 `32/32`,
substitute `8/8`, **`registry` `18/18`** — now including **row 8 on the wire**, so the §4.3 pin-delta
is cross-impl green under the ruled `pin-bindings` encoding rather than in-tree only.

> **Open, and not written off: `concurrency.t2_1_sustained_load` is marginal here.** Four runs:
> `30.7s → PASS` · `36.7s → PASS` · `44.0s → FAIL 4.1x` · `56.6s → FAIL 4.2x`, against a **4.0x**
> ceiling, with near-identical failing windows (first-window ~39 ms, last ~161–164 ms) and pass 1b
> green every time. **py sits at 4.0–4.2x and crosses about half the time.** Host-side versus a real
> sustained-load degradation is **not established**, and the earlier report of *"host load"* rested on
> one confirming re-run — corrected. t2_1 drives `tree.get` on a hot path, so no registry diff is on
> it; that half is provable and the other half is not. Not on the release line; owed a look here, and
> the ceiling's tightness is `entity-core-go`'s as oracle author.

*(superseded — the run below predates R-27 and row 8)* **The citable number is
`1601 · 1586 P · 15 W · 0 F · 0 S @ core-go `a7a9493`` (2026-08-20)** — the
full armed `validate-complete.sh python`, **exit 0, all six passes**, measured from the committed
tree at `b4c4881`: pass 1b (`--profile core`) `747 · 632 P · 12 W · 0 F · 103 S`, pass 2 `55/55`,
pass 3 `32/32`, substitute `8/8`, and **`registry` `18/18`** — with
**`registry.v15_dispatch_config_refused` PASS**, i.e. R-11 **row 7** on the wire, so R-15 is
confirmed **cross-impl** and not merely in-tree. Last session's one FAIL is gone: the
`set-resolver-config-request.config` type-ref divergence was go's, as we routed, and go fixed it at
`857a348`. **The first attempt at this run exited 1 on `concurrency.t2_1_sustained_load`** — a
latency-ratio threshold (4.1x against a 4.0x ceiling) that **passed in pass 1b of the same run** and
passes on a quiet host; host load, not this diff, and recorded rather than quietly re-run. Local:
`3931 passed · 31 skipped · 1 F`, the one failure being `tests/interop/test_connect_to_rust_peer`
dialing a fixed `127.0.0.1:9000` held by unrelated Selenium containers — the fixed-port
anti-pattern's fourth occurrence.

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
