# Running peers, choosing ports, and reading a validator result

**When to open this:** Open this before starting a long-lived peer, and before citing any `validate-complete.sh` number.

Seven instances of one class: a fixed port held by something that is not the peer you think it is. Plus how to read a multi-pass validator log, and what a green re-run is and is not evidence for.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **SEVENTH instance of the fixed-port class, and the port was chosen BY the documented rule —
  because the documented set is the VALIDATOR's, and this repo binds its own.** *2026-09-16.*
  The standing rule says: pick a debugging port **below 32 768** (outside the ephemeral range)
  and **outside the harness's fixed set (`9000`, `9401`, `9451`, `9452`)**. Followed exactly:
  `19501`. Ten errors on the next full run, every one `[Errno 98] address already in use` at
  `127.0.0.1:19501` — because **`tests/integration/test_durability_contract.py` and
  `test_subscription_burst_real_wire.py` bind `19501` as a fixed port**.
  **The enumerated set was never the whole set.** It was assembled from the *cohort validator's*
  ports, by sessions tripping over *the validator's* leftovers — so it names the ports another
  repo's harness owns and is silent about the ones ours does. A rule stated as a list is only as
  wide as the incidents that built it, and every incident here came from one direction.
  **The rule, restated so it is closed:** before binding a long-lived debugging peer,
  `grep -rn "<port>" tests/` **in this repo** as well as checking the documented set — or take
  the port from `ss -ltnp` *plus* a grep, never from the list alone. The cheap general form:
  **debug on a port the repo never mentions**, e.g. `18xxx`, and grep to confirm.
  ⭐ **And the self-reaping worked, which is the half worth recording as a win.** The peer was
  started with `ENTITY_PEER_MAX_LIFETIME=900` and reaped itself on schedule, on a box where an
  agent cannot `kill` — the fifth-instance remedy (*a process an agent cannot reap must reap
  itself*) doing exactly its job. The cost of this instance was one re-run, not a leftover that
  outlives the session. **Set the lifetime even when you are sure the port is free**; it is what
  turned a permanent collision into a ten-minute one.

- **Fifth instance of the fixed-port class, and the probe is no longer the defect — the
  ASSUMPTION about which peer is.** *2026-09-11.* `tests/interop/test_type_parity.py` failed
  against `127.0.0.1:9000` with *"Remote peer missing types: [all 37]"*. The 2026-08-22 fix made
  `peer_liveness.peer_available` complete a **handshake** rather than test for a socket, and it
  worked: the process holding 9000 (`entity-avalonia`, an unrelated app from the
  `entity-browser-rust` family on this host) **is** an entity peer and answers the handshake.
  So the probe is right and the test's premise is what is wrong — it assumes the peer at 9000
  is *the reference peer*, and no handshake can establish that.
  **Deliberately not "fixed":** the obvious repair — skip when the peer serves none of the core
  types — converts the exact regression this test exists to catch into a skip. What the class
  actually needs is an identity assertion (a pinned peer_id or a served marker), which is design
  work rather than a guard. Recorded so the next session does not re-diagnose it: `ss -ltnp |
  grep 9000` first, and if something answers, ask **which** peer before reading the failure.

- **A validator failure on a fixed port is a leftover peer until proven otherwise.**
  *2026-08-17.* `validate-complete.sh` binds **fixed** HTTP-poll ports (9451/9452), so a
  run that aborts leaves a peer holding them — one survived **seventeen minutes** into
  later runs here. It then presents as a peer defect wearing four different costumes: a
  refused dial (`tcp_connect`), a scoped peer that never comes up, and — the convincing
  one — a **content-fetch 404 under a stable root**, which reads exactly like the
  serving gap the vector's own message argues for, because the *stale* peer genuinely does
  not have the node. That message ("a node that will not fetch under a stable root is a
  serving gap, not a harness race") is right about its own peer and says nothing about
  *which* peer answered. **Before theorising, run `ss -ltnp | grep 945` and
  `podman ps | grep entity-pm`** — the question is not "is the root stable?" but "is this
  the peer I started?". Cost of skipping it here: a confidently-written handoff section
  diagnosing a race that did not exist.
  **Second instance, 2026-08-18, and the leftover was *our own previous run*.** A
  `validate-complete.sh` that exits non-zero mid-suite does **not** reap its peer container,
  so the next run's pass 2 dies on `[Errno 98] address already in use` at 9452 — and it
  presents as *"the namespace-scoped peer never comes up,"* which reads like the scoped
  configuration being broken rather than like a port. **So the discipline has a second half:
  after any validator run that did not exit 0, `podman stop entity-pm-*` before re-measuring.**
  The first run failed for a real reason (a genuine FAIL we then fixed); the failure it left
  behind was not related to that reason at all, which is exactly why the two get conflated.
  **Third instance, 2026-08-19, and the port was held by something that is not a peer at all.**
  `tests/interop/` dials a fixed `127.0.0.1:9000` and its `rust_peer_available` fixture skips on
  *"nothing is listening"* — so when an unrelated container publishes 9000 (here a Selenium
  `e2e-firefox` / `perf-chrome` from another project on the same host), the probe sees a
  listener, the suite does **not** skip, and `test_connect_to_rust_peer` dies mid-handshake with
  an `IncompleteReadError` that reads exactly like a protocol regression in whatever you just
  changed. **A liveness probe that tests for a socket rather than for a peer converts a foreign
  process into a false failure in your own diff.** Same first move as the other two: `ss -ltnp |
  grep 9000` before theorising, and check `podman ps` for a publisher — a container from an
  unrelated project counts. (Also: before running the validator, check `ps aux | grep
  validate-complete` — the fixed ports mean a **concurrent** run by another session collides
  with yours, and neither result is citable.)
  **And that pre-flight is a point-in-time sample, which is the half it does not say.**
  *2026-09-01:* the check was clean, and a `validate-complete.sh rust` from another session
  started **after** it and ran alongside. **The collision does not announce itself** — there is
  no port error and no message naming another run. The tell is the *count*: pass 1 reported
  `PARTIAL — 4 total ran` against an expected ~1616, i.e. the peer never came up and the run
  reported a shape, not a failure. **So the rule is: read pass 1's total before reading its
  verdict, and re-check `ps aux` when it is anomalous** — a two-order-of-magnitude shortfall is
  a harness fact, never a conformance result, and it is the one number that separates
  "collided" from "failed" without any log-reading at all.
  **Fourth instance, 2026-08-22, and the leftover was a peer *this session* started and could not
  stop.** `validate-complete.sh python` came back `1591 P · 6 F`, all six `peer_issued`, all six
  saying `bind: address already in use` on `127.0.0.1:9401` — which is where `-peer-issued-addr`
  binds its fixture registry by default, and where a debugging peer started an hour earlier was
  still listening. **The new part is the remedy, because the usual one is unavailable:** this box
  blocks agents from killing processes by policy, so *"stop the leftover"* is not a move an agent
  has. `validate-complete.sh` takes `PI_PORT` from the environment, so the run was **re-measured**
  at `PI_PORT=9411` (→ `0 F`) rather than attributed to the collision from the log message. That
  ordering is the discipline and it is the *"it's the environment" is the flattering hypothesis*
  rule applied to the case where the flattering hypothesis is **true**: the error string named the
  cause outright and it was *still* cheaper to re-measure than to publish an attribution. **Two
  standing consequences:** before starting any long-lived peer for debugging, pick a port outside
  the harness's fixed set (`9000`, `9401`, `9451`, `9452`), because you may not be able to take it
  back; and when a fixed-port collision is unavoidable, look for the **environment override in the
  harness** before you look for a process to end.
  **Fifth instance, 2026-08-22, from the *creating* side — and the four entries above are all
  written by the seat that tripped over a leftover, which is why none of them fixed it.**
  ***RATIFIED*** — the shapes are now five deep and the remedy was never "be more careful".
  Every entry above ends in a *detection* rule (`ss -ltnp` first, re-measure on a free port,
  check `podman ps`). None asks why a peer outlives the session that started it, because from
  the tripping side the leftover is someone else's artifact. Measured here: `cmd_start` ended in
  a bare `await peer.serve_forever()` and installed **no signal handlers at all**, so
  - a peer started by hand ran until something signalled it, and **an agent on this host cannot
    signal anything** — `kill` was withdrawn precisely because agents leaned on it. A workflow
    whose only teardown is a tool you do not have is a workflow with no teardown.
  - `ENTRYPOINT ["entity-core"]` makes the peer **PID 1**, where the kernel does *not* apply a
    signal's default disposition: a SIGTERM with **no installed handler is discarded, not
    fatal**. So `podman stop` paid its full timeout and SIGKILLed — every time, for months —
    and the lesson everyone drew was *"reaping a peer means escalating to a kill."* The two
    leftover `entity-pm-*` containers reaped this session both logged it verbatim.
  - the `except KeyboardInterrupt` arm that *looked* like the shutdown path **never ran**.
    KeyboardInterrupt is raised into the event loop, not into the coroutine's `try`, so it
    propagated past the handler; measured pre-fix exit status was `-2` (killed by SIGINT), not
    `0`. **A shutdown path that has only ever been exercised by Ctrl+C in a terminal has never
    been exercised at all** — nothing in 4000 tests asserted an exit *status*, only that the
    process was gone, and SIGKILL satisfies that too.
  **The rule: a process an agent cannot reap must reap itself.** Where a lifetime cannot be
  bounded by the thing that created it, bound it at the process — `--max-lifetime`, defaulted
  from `$ENTITY_PEER_MAX_LIFETIME`, because a *flag* binds only the peers whose author
  remembered it, which is exactly the set that was never the problem. A malformed value is a
  hard refusal: a typo'd bound is a request for a bound, and demoting it to "unbounded" hands
  back the leak at the one moment nobody is looking.
  **And the test has to assert the property, not the symptom** — *the port comes back*, and a
  **clean** exit status. A peer that dies without running `stop()` also exits and also frees its
  port; a liveness-only row scores the broken peer green, which is how this survived five
  entries' worth of attention. Enforcement point:
  `tests/integration/test_peer_max_lifetime.py` — the flag, the env default, the explicit-zero
  override, SIGTERM, SIGINT, and the malformed-env refusals, each mutation-verified RED on
  exactly the predicted rows (four mutations: race unarmed, env fail-open, env unwired, handlers
  uninstalled). The teeth control holds an *unbounded* peer up across the same window, so the
  headline row's exit is attributable to the flag rather than to a peer falling over on boot.
  **Sixth instance, 2026-09-12, and the collision was created BY MY OWN RUN, AFTER the
  pre-flight, on a port the pre-flight correctly reported free.** Every instance above is
  *somebody else's leftover* — the remedy each time was detection (`ss -ltnp` first, re-measure
  on a free port, check `podman ps`). This one is not a leftover at all, and no detection step
  could have found it.
  `validate-complete.sh python` was run on *"free"* ports `POLL_PORT=39451 PI_PORT=39401`. The
  pre-flight was clean, the script's **own** probe of `POLL_PORT` and `POLL_PORT+1` passed, and
  passes 0 / 0b / 1 / 1b all completed — `1644 total, 1627 P, 16 W, 0 F, 1 S`. **Pass 2 then
  died bringing up the namespace-scoped peer:** `OSError: [Errno 98] … bind on address
  ('127.0.0.1', 39452)`, which is `NS_PORT = POLL_PORT + 1`.
  **`cat /proc/sys/net/ipv4/ip_local_port_range` → `32768 60999`.** 39452 is **inside the
  ephemeral range**. Passes 1 and 1b drive `concurrency.t2_1_sustained_load` — C workers ×
  10 000 requests — so the run's own outbound connections are being handed source ports out of
  that range, and one of them took 39452 in the window between the probe and pass 2's bind.
  Nothing was listening on it before the run and nothing was after it; measured both times.
  **Why it presents as something else, which is the whole reason it is worth an entry.** The
  failure lands on the *namespace-scoped* peer — the one configuration that differs from every
  other pass — one pass after an authorization-path change, in a session whose whole subject was
  authorization. The peer log's **last line** is the bind error, but the forty lines above it are
  a healthy boot (every extension initialized, `Listening on 127.0.0.1:41763`), so a `tail -5`
  shows a peer that came up and then died, which reads as *"the scoped configuration is broken by
  your diff."* It is the *"is this the peer I started?"* discipline with the question moved:
  **the peer is right and the port is wrong, and the port was stolen by the harness itself.**
  **The rule, and it is a one-line change to how ports are chosen:** pick harness ports **below
  32 768** — outside the ephemeral range *and* outside the harness's fixed set
  (`9000`, `9401`, `9451`, `9452`). A port in the ephemeral range is not *free*, it is
  *unclaimed*, and under a load-driving suite those are different things. Re-measured at
  `POLL_PORT=19451 PI_PORT=19401`. *(The other session's concurrent run this session pre-flighted
  around used `41953`/`41954`/`51919` — all three inside the range, so the same trap is live for
  whoever reads its result.)*
  **And the standing ordering held and is worth restating:** pass 1's **total** was read before
  its verdict. `1644 total` is the full check set, not a shortfall, so the `0 F` is a real
  conformance result and pass 2's death is a separate, later, harness fact. Had the rule been
  skipped, *"the validator failed"* was the available summary — and it would have been wrong
  about the only number anyone cites.

- **"It's the environment" is the flattering hypothesis for a flaky gate, and it needs the same
  evidence as any other.** *Candidate, 2026-08-20 — and I published the under-evidenced version
  first, which is why it is here.* `concurrency.t2_1_sustained_load` (go's oracle: C workers ×
  **10 000 `tree.get`s**, p50 of the last window vs the first, ceiling **4.0x**) FAILed a run, so I
  re-ran on a quiet host, it PASSed, and I reported *"host load, not this diff."* **One confirming
  re-run is not evidence for an attribution** — it is evidence that the check is not deterministic,
  which is a different claim. Three runs later the numbers are: `36.7s → PASS` · `44.0s → FAIL 4.1x`
  (first-window 39.05 ms, last 161.02 ms) · `56.6s → FAIL 4.2x` (39.11 ms, 164.22 ms). **The failing
  windows are near-identical**, the verdict tracks the wall time of the 10k run, and *pass 1b passes
  every time on the same tree.* So the honest statement is *"py sits at 4.0–4.2x against a 4.0x
  ceiling and crosses it about half the time,"* and **whether the slowness is host-side or peer-side
  is not established** — it could equally be a real sustained-load degradation worth fixing or a
  ceiling too tight for a peer at py's throughput.
  **Same law as *"they read the spec differently" is the flattering hypothesis***, one floor down,
  with a flaky gate as the subject instead of a sibling's code. The environment is the hypothesis
  that costs you nothing and closes the question, which is exactly why it needs the higher bar.
  **The check:** for a gate that flips, **record the measured numbers across runs, never the
  verdict** — a verdict re-run until green reads identical to one that was green, and the numbers
  are what tell the two apart. The half that *is* established gets stated separately and stays
  stated: t2_1 drives `tree.get` on a hot path, so a diff on the registry config path is provably
  not on it. **"Not my diff" and "not the peer" are two claims; the evidence for the first says
  nothing about the second.**

- **The validator measures your *working tree*, so don't edit it mid-run — and pin the
  oracle or the number is not citable.** *2026-08-18, both halves learned in one run.*
  `peer-manager` rebuilds the peer image from the working tree per pass (it logs
  `working tree dirty at <sha>`), so a run started before an edit and finishing after it
  reports passes measured against **two different trees** under one summary. Run 8 here
  straddled a `peer.py` change exactly that way and had to be thrown out and re-run from a
  committed tree. **Commit first, then measure.**
  Second half: `AGENTS-STANDARD` wants `N·0F @ <oracle-commit>`, and our own handoffs
  published `1594 · 0 F` with no go commit. The cost was concrete — when core-go's validator
  gained `subscriptions.events_vocabulary_filter` (`41ecf0b`) it was impossible to tell from
  our records whether the previous run had included it, so the only way to know was to run
  again. **A conformance number without its oracle commit is a number you will have to
  re-measure.**

- **Read pass 1 before you read the verdict — and a PASS read from the wrong pass is the same
  error wearing the opposite costume.** *Candidate, 2026-09-03.* The standing rule says a
  two-order-of-magnitude shortfall in pass 1's **total** is a harness fact, so read the count
  before the verdict. This is its mirror: `validate-complete.sh` runs seven passes against
  differently-built peers, `tail`ing the log showed
  `PASS connectivity.handler_not_found_on_unregistered_path`, and **pass 1 is a FAIL** — the
  passing line belonged to a later pass with a different peer configuration. I nearly published
  *"the cohort's 404 check passes against us"* on it, against a source read that said it could
  not. **`grep -n` the check name and look at the line numbers, never `tail`** — a multi-pass
  log has one line per pass per check and no two of them are claims about the same peer.
  *And the reasoning was right: the measurement that "disagreed" with it was never a
  measurement of the same thing.*
