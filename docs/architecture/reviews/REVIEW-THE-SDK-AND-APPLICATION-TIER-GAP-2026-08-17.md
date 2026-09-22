# REVIEW — 2026-08-17 — the SDK and application tier: where we are, and what it costs to step up

**Repo:** `entity-core-py` @ `1d951f6` (dev) · **Measured live**, not carried from a report.
**Read at:** arch `489e7dc` · browser-rust `67057be` · workbench-go `4b34418`
**Status:** assessment + proposed architecture. **The presentation-layer choice is open** (§7).

---

## 0. The one-paragraph version

Python is a **complete core peer with a near-complete extension set and no client above it**.
`make test` is green (3368 passed / 36 skipped at `1d951f6`). What is missing is not handlers —
it is **every tier above the wire**: there is no L1 operations SDK, one of ~13 L3 extension
wrappers, no L4 composition, and no L5 application tier. The protocol knowledge that *would*
be the SDK currently lives inlined in **2,004 lines of `entity_cli/main.py`**, where nothing
else can reach it. Separately, and on no one's board: **the layering rule this repo already
declares is violated and unenforced** (§5) — which matters now, because the plan is to stack
two more layers on top of that boundary.

---

## 1. What browser-rust said about us, verified here

`AGENTS.md` holds that a routed report's claims about *our* repo are hearsay until checked here.
Checked. **All four of browser-rust's claims (`ROUTING-2026-08-17-b` §3) hold**, including the
two that were in our favour:

| Their claim | Verdict | Evidence at `1d951f6` |
|---|---|---|
| `query.py` — 837 lines, Level 1, carries `type_filter` | **Confirmed** | `packages/entity-handlers/src/entity_handlers/query.py`, module docstring: *"Level 1 conformance: type_filter, ref_filter, path_prefix, eq/not_eq/in/exists"* |
| `content/sdk.py::ensure_closure` exists as an SDK affordance | **Confirmed** | `ensure_closure(dispatcher, blob_hash, store, namespace, …)`, `entity_handlers/content/sdk.py` |
| `entity_core/sdk` is a `Dispatcher` Protocol | **Confirmed** | `Dispatcher` / `ExecuteRequest` + two adapters, `entity_core/sdk/dispatcher.py`, 185 lines |
| No app tier; `sdk/` is a dispatch contract, not an application SDK | **Confirmed** | 216 lines total across `sdk/`; §3 below measures the rest |

**This is worth stating back to them.** Their §3 measured our tree instead of repeating the
cohort summary, and it was the summary that was wrong. Nothing here needs correcting — which is
itself the report to route.

---

## 2. Where the ecosystem is, and what "third validator" precisely means

From arch's `AUDIT-2026-08-17-grounding-the-tiers-peers-sdk-and-outer-limits` §1, re-read live:

| Tier | Spec surface | Ground-up implementations |
|---|---|---|
| Core protocol (`v0.8.0`) | 3 core specs + TREE | **go · rust · py** + 43–45 generated peers |
| Extensions | **26** `EXTENSION-*` | go · rust · py (partial per extension) · **0 generated** |
| **SDK** | **3** `SDK-*` | **workbench-go's `entitysdk/` only** — 141 files, ~13k non-test LOC, *de facto, not normative* |
| **L5 applications** | 2 conventions + CHARTER | **workbench-go · browser-rust** |

**Correct the count, because the two tiers are at different `n`:**

- At the **SDK tier**, Python would be the **second** implementation. `entitysdk/` is `n=1`.
  A spec with one implementation has never been tested as a spec at all — it has been tested as
  a description of one codebase.
- At the **L5 application tier**, Python would be the **third**, joining workbench-go and
  browser-rust.

**The SDK tier is where the marginal value is highest**, and it is the one nobody named.

**Why this is our mandate and not a new one.** `AGENTS.md` already defines this repo as *"a
clean-room peer for interoperability testing against the Rust implementation — it validates
that the spec is clear and complete enough to build compatible implementations."* Applying that
exact charter one tier up is continuity, not scope creep.

**And the timing is the argument.** Both L5 conventions are *"spine locked 3-way; **next:
vectors**."* Vectors are not yet frozen. ADR-0012's honesty rule — *"a cohort of implementers
all passing one author's vectors is cohort-consistent, not independent convergence"* — means a
clean-room Python read **written against the convention text before the vectors land** is worth
more than the same work afterward. After the vectors freeze, we would be confirming an
artifact; before, we are testing whether the text supports an independent build. That window is
open now and closes on its own.

---

## 3. The gap, measured against `SDK-OPERATIONS` §16

`SDK-OPERATIONS.md` §16.1 is a **MUST** list. Measured, item by item:

| §16.1 MUST | State | Note |
|---|---|---|
| §3.1–3.4 `get` / `put` / `list` / `remove` | **ABSENT** | No typed client API anywhere. Exhaustive search: the only `def get/put/has/remove` in `packages/*/src` outside `handlers/` are **L0 substrate** — `storage/content_store.py`, `storage/entity_tree.py`, `storage/indexes.py`. Every client-side tree op is an inline envelope in the CLI. |
| §4.1 `execute` (local/remote routing) | **PRESENT** | `Connection.execute`, `Peer.execute`, plus the `Dispatcher` Protocol |
| §6.1–6.2 `watch` / `unwatch` | **ABSENT** | Zero hits for `def watch` / `def unwatch` in either package. The *server* half exists (`subscription.py` handles `subscribe` / `unsubscribe`); the client primitive does not. |
| §7.1 `connect` w/ handshake + grant exchange | **PRESENT** | `Connection.connect` |
| §8.1 `create_peer` w/ capability bootstrap | **PRESENT** | `PeerBuilder` / `build()` |
| §11.6 `register_handler` primitive | **PARTIAL** | Server side is `handlers_handler` at `system/handler` (`entity_handlers/handlers.py`). No client-side primitive with handle lifecycle / compensation. |
| §12.1–12.5 error model + code strings | **PARTIAL** | Status preservation exists on `ExecuteResult`; no SDK error hierarchy |
| §14.1–14.2 content identity + type definitions | **PRESENT** | ECF (`utils/ecf.py`), `types/definitions.py` (7,513 lines) |

**The L1–L5 ladder** (`SDK-OPERATIONS` §1), same measurement:

| Level | What it is | Python |
|---|---|---|
| **L0** wire protocol | framing, envelope, handshake | **Complete** |
| **L1** operations | tree ops, dispatch, query, subscription, connection, lifecycle | **`execute` + `connect` + `create_peer` only.** The rest is inlined in the CLI |
| **L2** patterns | scoped handles, entity-backed state, type rendering | **Absent.** `entity_cli/display.py` (358 lines) is a type renderer trapped in the presentation layer |
| **L3** extension operations | ~13 extension wrappers | **1 of ~13** — `content.ensure_closure`. Absent: subscription, revision, history, query, inbox, transaction, compute, network, clock, type, role, continuation |
| **L4** composition | reactive pipelines, cross-peer workflows, workspace transfer | **Absent** — this is browser-rust's *subscribe → materialize → re-serve* |
| **L5** applications | `APP-CONVENTION-EMBED`, `-SEMANTIC-CONTENT-SITE`, share | **Absent entirely** |

**The shape of the gap is a wedge, not a wall.** L0 complete, L1 at ~30%, L3 at ~8%, L4/L5 at
zero. And the handler tier underneath is dense — `entity-handlers` is 43,816 lines across 26+
handlers. **We are not missing capability. We are missing the surface that exposes it.**

---

## 4. Why the SDK never got written (the mechanism, not the excuse)

`cmd_ls`, `entity_cli/main.py`:

```python
response = await conn.execute(
    uri=f"entity://{remote_peer}/system/tree",
    operation="get",
    params={"type": "system/tree/get-request", "data": {"path": path}},
)
```

Every one of the 17 CLI subcommands does this. **The CLI is the SDK, written 17 times, in a
package nothing may depend on.** `entity-cli` sits at the bottom of the dependency order, so
every piece of protocol knowledge that lands there is knowledge no library, no test, no app tier
and no second front-end can reuse.

This is the cause of §3, and it is the thing to fix first — not because the CLI is bad, but
because **any second consumer would have had to duplicate it**, and the app tier is that second
consumer.

---

## 5. The finding on no one's board: the layering boundary is violated and unenforced

`AGENTS.md` declares *"a strict dependency direction **entity-cli → entity-handlers →
entity-core**."* Measured:

- **37 imports of `entity_handlers` from inside `entity-core`.** All 37 are **function-local**
  (0 module-level), confined to `peer/builder.py` (35) and `peer/peer.py` (2). The deferred form
  is what keeps the import-time cycle from raising.
- **`entity-core/pyproject.toml` does not declare `entity-handlers`** — its dependencies are
  `argon2-cffi`, `base58`, `cbor2`, `cryptography`, `pynacl`. So `PeerBuilder().with_all_handlers()`
  on a standalone `entity-core` install is an `ImportError` waiting to happen. That is a real
  packaging defect, not an aesthetic one.
- **No gate test exists.** Exhaustive search of `tests/` for an import-direction or layering
  assertion returns nothing.

`AGENTS-STANDARD.md`: *"A discipline with no enforcement point is theater."* This one is
theater today. It has cost nothing yet **because there is only one boundary**. The plan in §6
adds two more — and an unenforced boundary reproduced three times is how a layered design
becomes a ball of mud that still passes its tests.

**This is a candidate anti-pattern entry, not yet a ratified discipline** (promotion ladder:
bit us once). Filed here with its source: the `with_*_handler()` convenience methods on
`PeerBuilder`.

---

## 6. Proposed architecture — five packages, three enforced boundaries

The user constraint: **one repo** (unlike go/rust, which split the app tier out), but with the
tiers isolated as rigorously as a split would have forced. That trade is only safe if the
isolation is *mechanical*. So each boundary below names its enforcement point.

| Package | Tier | Contents | May depend on |
|---|---|---|---|
| `entity-core` | L0 + kernel | protocol, peer, crypto, storage, capability, types, ECF; `handlers/` = registry + context + bootstrap only | *(nothing internal)* |
| `entity-handlers` | Extensions | the 26 standard handlers **+ their `PeerBuilder` registration** | `entity-core` |
| `entity-sdk` | **L1 / L2 / L3** | typed client ops; scoped handles; entity-backed state; type rendering; the ~13 extension wrappers | `entity-core` |
| `entity-app` | **L4 / L5** | subscribe→materialize→re-serve; `APP-CONVENTION-EMBED`; `-SEMANTIC-CONTENT-SITE`; share | `entity-sdk`, `entity-handlers` |
| `entity-cli` *(+ presentation, §7)* | Presentation | argument parsing, formatting, terminal/web I/O — **and nothing else** | `entity-app`, `entity-sdk` |

### 6.1 The three enforcement points

Each is a **gate test in `tests/unit/`**, greppable and cheap:

1. **Upward-import gate.** No package imports a package above it — *including function-local
   imports*. Walk each package's AST, collect every `Import`/`ImportFrom` at any depth, assert
   the target package's tier is ≤ its own. This is the check that would have caught §5, and it
   catches the deferred form the current shape relies on.
2. **The declared-dependency gate.** Every cross-package import has a matching entry in the
   importing package's `pyproject.toml` `dependencies`. This is the check for the latent
   `ImportError`.
3. **The presentation-purity grep.** *No presentation package constructs a protocol envelope.*
   Concretely: zero occurrences of the `{"type": …, "data": …}` literal pair, and zero
   `conn.execute(` / `Connection` imports, in the presentation package. **This is the one that
   forces the SDK to be complete** — if the CLI cannot be written without reaching for an
   envelope, the missing affordance is an SDK bug, and the gate names it at the moment it is
   introduced rather than a year later.

Gate 3 is the load-bearing one. It converts "we should keep the layers clean" into a failing
test with a filename.

### 6.2 Resolving §5 without a new package

The 35 `with_*_handler()` methods reach up because `PeerBuilder` is the composition root and the
handlers are the things being composed. **The primitives to fix this already exist**:
`PeerBuilder.with_handler(...)` and `.with_extension(...)` are generic. So the standard-handler
convenience methods move **down-stack into `entity-handlers`** (a registration module, or a
mixin `entity-handlers` contributes), and `with_all_handlers()` goes with them. `entity-core`
keeps the generic hooks and stops knowing the names of its own extensions. Mechanical, no new
package, and it makes gate 1 pass honestly rather than by exemption.

### 6.3 Build order

Sequenced so each step is independently verifiable and each one unblocks the next:

1. **Gates first** (§6.1), with the current violations recorded as explicit, dated,
   individually-justified exemptions. A gate added after the migration measures nothing;
   a gate added before it is a ratchet. `make check` is red on **661 ruff findings** (548
   auto-fixable) at `1d951f6` — clearing that is part of this step, since a red `check` means
   no new gate is visible.
2. **§6.2** — move standard-handler registration into `entity-handlers`; drop the exemptions.
3. **`entity-sdk` L1** — the `SDK-OPERATIONS` §16.1 MUST list: `get`/`put`/`list`/`remove`/`has`,
   `watch`/`unwatch`, the error model. Extracted from `entity_cli/main.py`, not written fresh —
   the semantics are already proven by the CLI's behaviour.
4. **Rebuild `entity-cli` as a thin client** over step 3, and turn on gate 3. **This is the
   verification of step 3**, not a follow-up chore: if the rebuilt CLI is behaviour-identical
   and contains no envelopes, the L1 SDK is complete.
5. **`entity-sdk` L2/L3** — scoped handles, entity-backed state, type rendering (lift
   `display.py` out of the CLI); the extension wrappers, prioritised by what the app tier needs:
   subscription, revision, query, content, then the rest.
6. **`entity-app` L4** — subscribe → materialize → re-serve, built against browser-rust's §1
   finding: **remote data at `/{them}/{their path}`, verbatim; prefix read from
   `system/peer/published-root.prefix`; never inferred.** Retrofitting this costs the most, so
   it is a constraint on the first line of L4, not a review comment on the last.
7. **`entity-app` L5** — `APP-CONVENTION-EMBED`, then `-SEMANTIC-CONTENT-SITE`, then share
   (`app/share/*`, record shape per browser-rust `ROUTING-2026-08-17-b` §2.2; the
   `peers`-vs-`grantee` trap in their §2.1). **File spec asks as we go** — the ambiguities a
   clean-room reader hits are the entire deliverable of being the second SDK implementation, and
   they are worth more logged than worked around.

### 6.4 Two things that need no app tier and can go any time

Both are from browser-rust's routing, both are cheap, both are real contributions:

- **The `{peer_pattern}` validator read.** §6.2 closes the form to hex-or-`default`; §6.9a.1
  defines Base58 as the pre-contact affordance. Arch filed
  `PROPOSAL-POLICY-PATH-KEY-FORMS-6-2-VS-6-9A-1` and **needs a py read of our policy-path
  validator.** Measuring what we actually accept is a contribution to a live proposal, today.
- **Be the far side of a file transfer.** `content` + `local_files` + `tree` + `ensure_closure`
  is the whole requirement and we have all four. Their `make e2e-webrtc-file` gate is rust↔rust;
  a py peer on the far side is the first P2P evidence in this cohort that is not.
  *(Their honesty caveat, adopted: arch has not ruled whether py↔rust is independent convergence
  or cohort-consistent. Run it, label it conservatively, don't let the question gate the work.)*

---

## 7. The presentation layer — open

**Measured asset, stated precisely so it is not overclaimed:** `peer/http_server.py` (1,127
lines) is an **HTTP transport for the protocol** — `POST` EXECUTE / EXECUTE-RESPONSE — *not* a
web UI. It is not a free front-end. What it *is*: a working HTTP listener with a
`url_path` / `poll_prefix` request demux, which is the hook point
`APP-CONVENTION-SEMANTIC-CONTENT-SITE` §11 ("URL projection prefix — registers sites at the
§6.5.6 demux") is specified against. A browser can already reach a Python peer.

The cohort's front-ends, for contrast: workbench-go has `shell` (CLI, primary, leading edge),
an Avalonia/.NET GUI, and a **frozen `console` TUI kept deliberately as a renderer-neutrality
enforcer**. browser-rust is the browser.

**The recommendation is CLI-first, then web** — and the reasoning is that the two choices do
different jobs:

- The **CLI rebuild is not a presentation decision at all** — it is step 4, the verification
  mechanism for the L1 SDK. It happens under every option.
- The **web surface is where the L5 validation pays off.** The `applications/` CHARTER exists so
  that *"web, Godot, and terminal front-ends all agree to render the same way"* — a second,
  independent renderer of `EMBED` / `SEMANTIC-CONTENT-SITE` is the convention's actual test, and
  it reuses the HTTP demux above.
- A **native GUI is the weakest option**: it duplicates workbench-go's Avalonia, validates no
  new convention, and carries the largest dependency footprint.

Recorded as a recommendation. **The call is the operator's.**

---

## 8. What this review changes

1. **Python's gap is above the wire, not in it.** L0 complete, L1 ~30%, L3 1-of-13, L4/L5 zero.
   The handler tier is dense and the surface exposing it is missing. §3
2. **The cause is locatable**: protocol knowledge is inlined in a 2,004-line CLI that sits at the
   bottom of the dependency order, where no second consumer can reach it. §4
3. **"Third validator" is two different numbers.** Second at the SDK tier (`n=1` today), third at
   L5. The SDK tier has the higher marginal value and nobody named it. §2
4. **The vectors window is open and self-closing** — both L5 conventions are pre-vector, which is
   when an independent clean-room read is worth the most under ADR-0012. §2
5. **A boundary violation on no board**: 37 deferred upward imports, an undeclared dependency, a
   latent `ImportError`, and no gate. Candidate anti-pattern, source named. §5
6. **The isolation the one-repo plan depends on must be mechanical** — three gate tests, of which
   the presentation-purity grep is load-bearing. §6.1
7. **Two contributions need no app tier**: the `{peer_pattern}` validator read, and being the far
   side of a file transfer. §6.4
