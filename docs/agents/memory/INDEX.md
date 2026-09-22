# Memory — index

**Everything this repo has learned that is not yet a check.** Read the row that
matches what you are about to do; you are not expected to read all of it.

`AGENTS.md` answers *how do I work here today?* — read in full, every session.
This directory answers *what would I otherwise rediscover the hard way?* — read by
index, on demand.

| file | open it when | entries |
|---|---|---|
| [`ROUTED-CLAIMS-ABOUT-US.md`](ROUTED-CLAIMS-ABOUT-US.md) | A packet, ruling or fold arrived and you are about to act on it. | 15 |
| [`FILING-AND-ARGUING-UPSTREAM.md`](FILING-AND-ARGUING-UPSTREAM.md) | You are routing a finding out, answering a poll, or holding on a ruling. | 10 |
| [`SPEC-READING-AND-CENSUS.md`](SPEC-READING-AND-CENSUS.md) | You are implementing a normative rule or walking an error table. | 19 |
| [`TESTING-FIXTURES-AND-MUTATION.md`](TESTING-FIXTURES-AND-MUTATION.md) | You are writing a test, building a probe, or citing a result. | 20 |
| [`AUTHORIZATION-AND-CAPABILITIES.md`](AUTHORIZATION-AND-CAPABILITIES.md) | You are touching a grant, a scope matcher or a permission check. | 11 |
| [`WIRE-ENCODING-AND-ENTITY-FIDELITY.md`](WIRE-ENCODING-AND-ENTITY-FIDELITY.md) | You are touching ECF, hashing, the codec or a wire literal. | 6 |
| [`SDK-HANDLERS-AND-DISPATCH.md`](SDK-HANDLERS-AND-DISPATCH.md) | You are wrapping a handler operation, or changing the dispatcher. | 7 |
| [`PEERS-PORTS-AND-THE-VALIDATOR.md`](PEERS-PORTS-AND-THE-VALIDATOR.md) | You are starting a peer or citing a validator number. | 6 |
| [`BUILD-TOOLCHAIN-AND-ENVIRONMENT.md`](BUILD-TOOLCHAIN-AND-ENVIRONMENT.md) | The build or the tooling is behaving oddly. | 4 |

---

## What an entry is

**What happens · why (the mechanism, not the symptom) · what to do**, with the
`file:line` or the command. Findable by the **symptom**, because that is what the
reader arrives with.

Most entries carry a dated provenance marker — `*Candidate, YYYY-MM-DD*` or
`***RATIFIED YYYY-MM-DD***`. That is the promotion ladder of `METHODOLOGY.md` §3,
not session narration: **candidate** means it bit us once and is being applied but
is not claimed to generalize; **ratified** means it bit us a second time in a
different shape. The date is the evidence's date and it is load-bearing.

## The rule that bounds this directory

> **An entry that could become a check SHOULD become one — and then it is deleted
> from here.**

Memory is where a finding waits *while it is still only prose*. It is not where
findings retire. The maintenance pass is not "trim the file"; it is, per entry:
*could a test, a lint rule, a build assertion or a gate make this impossible
instead of merely documented?* Most entries here already name an enforcement point
— those are the ones closest to leaving.

## Conventions

- **Superseded, not appended.** When the truth changes, rewrite the entry. Git
  holds the history.
- **Point at code.** An entry with no `file:line` decays into folklore the first
  time the code moves.
- **No secrets, ever** — name the `file:line` and describe the shape.
