# egress-broker — Engineering Report

**Date:** 2026-10-07
**Repository:** https://github.com/happymode-25/egress-broker (private, `main`)
**Hardening commit:** `5cc27fd` — verified by CI run
[37573264417](https://github.com/happymode-25/egress-broker/actions/runs/37573264417)
**Tool version:** 1.2.0, `SCHEMA_VERSION = 2`

---

## 1. Status at a glance

| | |
|---|---|
| Repository | `github.com/happymode-25/egress-broker`, private; history is flippable to public without a rewrite |
| Latest CI run | `37573264417` — **success**, 5 jobs, 60 steps (58 success + 2 skipped: the orphan check is a Linux-only step) |
| Selftest | **210 checks** — 210 run + 0 skipped on Python 3.11+, 208 run + 2 skipped on 3.9 |
| End-to-end suite | **42 tests** over real sockets and real subprocesses |
| Mutation sweep | **26 of 26** non-canary mutants killed; canary survived (as required) |
| External dependencies | **None.** Python 3.9+ standard library only, enforced by `ci/import_gate.py` |
| Working tree | Clean, `HEAD == origin/main` |

---

## 2. What this is

A policy-enforcing proxy that sits between an LLM agent and the network. Every
outbound request is matched against a policy file; anything unmatched is denied.
Findings are written to a tamper-evident audit log.

It exists because a retrieval-augmented agent reads documents it does not
control, and nothing in a standard agent stack stops those documents from
steering the agent into sending credentials to an attacker. There was no control
point between the agent's HTTP client and the socket — no place for a "no" to
live.

Single file, no install step:

```bash
python egress-broker.py --selftest    # verify the policy engine (210 checks)
python egress-broker.py serve         # run on 127.0.0.1:8888
```

---

## 3. The four features

### 3.1 DNS pinning

The allowlist says `api.openai.com`. The broker resolves that name **itself**,
opens the socket to the address it obtained, and sends the original `Host`
header. The name is never handed to the system resolver and hoped on.

This closes the gap where an allowlisted name resolves to an attacker-controlled
address (DNS poisoning, a hijacked resolver, a compromised split-horizon zone),
and the TOCTOU gap between checking policy and opening the socket.

- **On by default, fails closed.** A name that will not resolve is a denial, not
  a fallback to the unpinned name.
- `allowed_ips` turns the check from observation into enforcement: a name the
  policy allows must also resolve **somewhere** the policy allows.
- Only *successful* resolutions are cached, so a transient failure cannot be
  pinned for the whole TTL.
- Every request event records the `resolved_ip` actually dialled, and it is part
  of the hash chain — so "which address did we really talk to" is answerable
  later and cannot be edited afterwards.
- Flags: `--no-dns-pin` (off), `--dns-ttl` (60s), `--dns-cache-max` (1024).

### 3.2 Per-client policy scoping

Different agents do not share an allowlist. A `[[clients]]` scope narrows what a
single client can reach, matched on the peer CIDR, a header, or both.

- `inherit = true` (default) — the scope's rules are consulted first, then the
  global list: "additionally, this client may also reach X".
- `inherit = false` — the scope's list is the entire world for that client; the
  global list is never consulted.
- **When both a CIDR and a header match the same scope, the network match
  wins.** A client that can be inferred from its address cannot claim a
  different scope by sending a header — weighting CIDR above header is what
  makes the header safe to trust at all.
- The chosen scope is recorded on the request event and in `X-Egress-Reason`, so
  a denial tells you *which* policy was applied. `stats --json` has a `by_scope`
  breakdown.

### 3.3 Threshold alerting

A block that happens once is usually a false positive. The same block twenty
times in five minutes is an incident.

Rules are declared in `[[alerts]]` over four metrics — `denies`, `requests`,
`rule_hits` (with an optional `selector` for one specific rule) and `new_host`.
Each has a `threshold`, a `window_minutes`, and a `severity`.

- Alerts fire to **stderr** (journald, or the terminal you are watching) and are
  persisted to an `alerts` table; read back with `egress-broker.py alerts`.
- `new_host` fires once per host the broker has never seen — the shape of data
  staged somewhere new before it is sent anywhere.
- Counting is in memory and resets on restart; the table is the durable record.
- `cooldown_minutes` defaults to `window_minutes`, so a sustained problem
  reports once per window rather than once per request.

### 3.4 Tamper-evident audit

Every event stores a digest over its own contents **plus the digest of the event
before it**:

```
hash[n] = sha256(id | ts | kind | client | scope | method | host | port |
                 resolved_ip | path | bytes | action | reason | detail |
                 hash[n-1])
```

Editing any retained row invalidates every row after it; inserting a row breaks
the sequence; a truncated tail is caught by a separately stored `chain_head`.

| Attack | Caught |
|---|---|
| Edited row | Yes — it no longer hashes to what the next row recorded |
| Deleted row from the middle | Yes — same reason |
| Truncated tail | Yes — `chain_head` still names a digest that no longer exists |
| Deleted oldest prefix | **No, and cannot be.** Retention deletes the oldest events on purpose; the chain has no external anchor. Copy the store off-host if that matters |

`verify` exits 0 verified / 1 tampered. The store clamps `ts` to be
non-decreasing with `id`, so retention always deletes a chain-safe *prefix*
rather than a scattering of rows — pruning from the middle would be
indistinguishable from tampering and would make `verify` cry wolf after every
ordinary prune.

---

## 4. Verification

### 4.1 Two suites, deliberately split

```bash
python egress-broker.py --selftest      # pure, fast, no sockets
python tests/test_egress_broker.py      # real sockets, real subprocesses
```

210 checks and 42 tests respectively. CI asserts both counts as floors, because
`unittest` exits 0 when it collects nothing and a suite that quietly stopped
running is indistinguishable from a suite that passes.

The check count is not identical across interpreters: two checks need `tomllib`,
which is stdlib only from 3.11, so on 3.9 they report as *skipped*. CI therefore
asserts two numbers per run — how many checks actually *ran*, and run-plus-
skipped:

- selftest: `ran >= 208` and `ran + skipped >= 210`
- e2e: `Ran N tests` must be `>= 42`

208 is exactly what the 3.9 job reports (the constant was derived from the
previous 3.9 job's `202 run + 2 skipped`, plus the six checks added since).
Asserting only the "ran" number would have passed on 3.9 with two checks quietly
missing — and 3.9 is exactly the version where the fallback TOML parser is the
parser actually in use.

### 4.2 Gates that can fail

A check that has never been run is a check that does not work.

| Gate | What it does |
|---|---|
| `ci/import_gate.py` | Fails if any file imports a non-stdlib module (5 files checked) |
| `ci/prove_suites_can_fail.py` | Breaks the tool on purpose *in place* and requires the selftest to fail **by naming a failing check** — a crash is not a failing test. Restores and requires green again |
| count floors in `ci.yml` | Fail if either suite shrinks |
| orphan / working-tree checks | Fail on leftover background processes or a dirty tree, so a parked bug cannot ride a later fix |

### 4.3 Mutation testing

Unit tests can be green because they assert the wrong thing. To find out, each
line of interest was mutated one at a time — the change made, the suite run, and
a *kill* required to be a named assertion failure, not merely a nonzero exit.

**Harness guardrails.** A mutation harness that lies is worse than none, so the
harness (`ci/mutation.py`) is guarded in both directions:

- Mutations run on a **throwaway copy** of the repo, never the working tree. The
  live tool's SHA-256 is captured before and after every run; a mismatch voids
  the run.
- Every anchor must match **exactly once** in the file. An anchor matching twice
  is reported `PATTERN-AMBIGUOUS` and the run is void rather than reporting a
  false verdict. An auditor pass found three bad anchors before any time was
  spent on suites.
- A **canary mutant** — `a - b*c` rewritten as `b*c - a`, which cannot change
  behaviour — must **survive**. If it is killed, the harness is killing things
  that cannot be killed and every verdict in the run is discarded.
- The baseline must be green (210/42) before the first mutant and green again
  after revert, or the run is void.

**Full sweep (this state):** **26 of 26 non-canary mutants killed, canary
survived, live repo untouched.** The earlier sweep — before the hardening
commit — had four survivors, and each was a *test that asserted the wrong thing*
rather than a weak assertion:

1. **`chain`: retention no longer re-points the chain head.** The test deleted a
   prefix with SQL and then called `_refresh_head()` *itself*, so it passed
   whatever `prune()` did. Retention only ever deletes a prefix, so skipping
   the refresh changes nothing **until nothing survives** — the new check empties
   the store through the public `prune()` path and requires the genesis head.
2. **`alerts`: a firing alert is not handed to the sink.** The test wrote its
   row with `record_alert()` *by hand* and then asserted the row was present —
   it checked row encoding and nothing else, so deleting the `_emit()` call that
   delivers a firing alert left every assertion green. The new check fires a
   rule through `AlertEngine` and requires the sink to receive it.
3. **`store`: the audit insert no longer holds the chain lock.** The 6-thread
   concurrency test counted rows (120) but never walked the chain, so deleting
   `_chain_lock` left 120 rows that no longer linked — counting is blind to
   that. `verify_chain()` now runs after the burst.
4. **`parser`: an empty Host header falls back to the loopback origin.** No
   helper could produce a Host-less request, because `http.client` always
   synthesises one — so every test asserted the same well-formed request a
   second time. The handler's fallback for an absent Host decides the whole
   outcome. It now goes out as raw bytes and is asserted denied, with the
   recorded host proven not to be loopback.

All four die now; the re-run sweeps killed all 15 mutants in those groups before
the full sweep confirmed 26/26.

---

## 5. The accept-queue defect

CI failed once with `AssertionError: 20 != 19`. One client of twenty had been
dropped.

Not a flake. `socketserver` listens with a **backlog of 5**; twenty simultaneous
connects overran it before the broker accepted any, and the kernel reset the
rest. An agent making concurrent calls got a *transport error* instead of a
policy decision — the one thing this program promises never to do. Measured: 60
simultaneous clients lost 3 to this on Windows, with the broker otherwise
healthy.

**Fix (commit `0439037`):** `ThreadingBroker.request_queue_size = 128`, as a
class attribute. Setting it on an instance does nothing, because
`server_activate()` has already called `listen()` by then.

**Chasing it turned up three separate ways of being wrong**, each of which had
to be fixed before the real cause could be seen:

1. **The test reported a count, not a cause.** `join()` returns happily after a
   thread raises, so the exception died in a thread's stderr and all that
   survived was `20 != 19`. Client errors are now collected and named.
2. **`rows()` called `store.query()` with no limit, and `query` defaults to
   50.** Every count above 50 came back as exactly 50 — indistinguishable from a
   real count. Raising the test to 96 clients produced `96 != 50`: 46 rows that
   were never missing, and a long hunt for a write-loss bug that does not exist.
3. **The concurrency test had no barrier**, so its threads connected as they
   happened to start. With the bug deliberately reintroduced it missed **5 times
   out of 5**. A `threading.Barrier` now forces all clients onto the wire
   together.

**Choosing the guard.** The regression guard uses **96 clients** because that is
the smallest size that fails 5/5 at backlog 5 *and* passes 5/5 clean at the
shipped 128. Measured refusal rates at the old backlog: **0/5 at 20 clients,
4/5 at 48 and 64**. A guard set where the bug only shows up 4 times in 5 passes
against the bug it exists to catch — it reads as coverage and is worse than no
guard at all.

Verified: red 5/5 at backlog 5 (the mutation sweep's `backlog` mutant kills on
`46 refused` connections), green at 128, every local CI step passing.

---

## 6. Known limitations

These are real, not hedging. Full text in `README.md`, § Limitations.

- **No TLS interception.** HTTPS bodies are encrypted, so body rules apply only
  to plaintext HTTP. Host-level allow/deny and `allowed_ips` still work. This is
  the single biggest gap: an attacker who controls a document controls what goes
  in the body, and today the body of an HTTPS request is the one place they get
  to write unobserved.
- **Thread per connection, bounded queue.** Fine for tens of concurrent calls;
  not a design for thousands. That wants a selector or a process pool.
- **The hash chain has no external anchor.** It proves internal consistency, not
  that the oldest rows were never deleted.
- **Only HTTP and CONNECT.** No HTTP/2, WebSocket, or gRPC. A CONNECT tunnel is
  passed through, so anything inside it is opaque.
- **Body inspection is textual.** Base64 or encrypted payloads are not inspected.
- **Not hardened against a determined local attacker.** One layer, not a trust
  boundary on its own.

---

## 7. Repository layout

| Path | What |
|---|---|
| `egress-broker.py` | The whole tool. Proxy, policy engine, alert engine, hash-chained store, selftest. |
| `policy.toml` | Default policy. |
| `tests/test_egress_broker.py` | End-to-end suite over real sockets. |
| `egress-broker.service` | Hardened systemd unit. |
| `ci/import_gate.py` | Fails on any non-stdlib import. |
| `ci/prove_suites_can_fail.py` | Proves the suites can actually fail, then recover. |
| `ci/mutation.py` | Mutation sweep: throwaway copy, canary-guarded, live tool hashed before/after. |
| `.github/workflows/ci.yml` | 5-job matrix: Ubuntu 3.9 / 3.11 / 3.13, macOS 3.13, Windows 3.13. |

---

## 8. Reproducing this

```bash
git clone https://github.com/happymode-25/egress-broker
cd egress-broker

python egress-broker.py --selftest     # 210 checks
python tests/test_egress_broker.py     # 42 tests
python ci/import_gate.py               # stdlib only
python ci/prove_suites_can_fail.py     # suites can fail, and then recover

# Mutation sweep: writes only to a throwaway copy; hashes this repo's
# egress-broker.py before and after so an escape is visible rather than silent.
python ci/mutation.py                  # all 27 mutants (26 + the canary)
python ci/mutation.py chain alerts     # a subset; the canary always runs
python ci/mutation.py CANARY           # just prove it can see a survivor
```

The rest of CI is the workflow itself — five jobs, both suites plus the gates,
on every push.

---

## 9. Commits

| Commit | Subject |
|---|---|
| `5cc27fd` | selftest: four checks for behaviour the suites were blind to |
| `0439037` | Fix: listen with a backlog of 128, not 5 |
| `5174246` | readme: put the CI result on the front page |
| `dec5ba6` | selftest: stop skipping the fallback-parser checks on the version that needs them |
| `90c6ed5` | ci: fix two gates that could not fail, and add the ones that were missing |
| `8eef1c9` | egress-broker: fail-closed egress proxy with a tamper-evident audit log |

---

*Produced with OpenCode. All results above are from the real repository; every
number in this report is asserted by the CI run linked in §1.*