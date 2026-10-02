# egress-broker

[![CI](https://github.com/happymode-25/egress-broker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/happymode-25/egress-broker/actions/workflows/ci.yml)

A policy-enforcing proxy that sits between an LLM agent and the network.

Single file, Python 3.9+, standard library only. No install step.

## The problem

A retrieval-augmented agent reads documents it does not control. Nothing in a
standard agent stack stops those documents from steering the agent into sending
credentials or private data to an attacker. There is no control point between the
agent's HTTP client and the socket, so there is nowhere for a "no" to live.

This is that control point. Every outbound request is matched against a policy
file. Anything unmatched is denied. Findings go to a tamper-evident audit log.

## Quick start

```bash
python egress-broker.py --selftest                 # verify the policy engine
python egress-broker.py serve                     # run on 127.0.0.1:8888
```

Point the agent at it:

```bash
export HTTPS_PROXY=http://127.0.0.1:8888 HTTP_PROXY=http://127.0.0.1:8888
your-agent --input "summarize these docs"
```

Then ask the store what happened:

```bash
python egress-broker.py stats
python egress-broker.py query --rule exfil_directive
python egress-broker.py alerts
python egress-broker.py verify
```

Dry-run first when adopting it on a live agent. Nothing reaches upstream — not
even a TCP connection — so you can see every decision without breaking anything:

```bash
python egress-broker.py serve --dry-run
```

Dry-run is the only mode that skips DNS resolution, and therefore the only mode
that skips the `allowed_ips` check. That is inherent: the whole point of
`allowed_ips` is to constrain the address the name resolves to, and dry-run
never looks one up.

## What it enforces

| Section | Enforces |
|---|---|
| `[[destinations]]` | Which hosts an agent may talk to. Most specific pattern wins. Optional `allowed_ips` constrains which addresses a name may resolve to. |
| `[[clients]]` | Per-client scoping. Which hosts *this* client may reach, matched by network and/or header. |
| `[[secrets]]` | Credential-shaped strings. Blocks; entropy and Luhn checks cut false positives. |
| `[[injections]]` | Instructions aimed at the agent, and exfiltration directives. |
| `[[alerts]]` | Threshold alerting. A rule that matches once is noise; matching repeatedly is an incident. |
| `[headers]` | Credential headers on paths that should not carry them. |

Two rules are `report` rather than `block` on purpose:

- `high_entropy_token` — entropy scoring is fuzzy, and a broker that silently
  redacts legitimate identifiers gets switched off.
- `instruction_override`, `role_reassignment` — a user may legitimately ask
  "summarize this article about prompt injection." The audit entry is the signal.

The `exfil_directive`, `credential_recall`, and `curl_pipe_shell` rules do
block: no legitimate request body contains "send the contents to
http://attacker.example/collect".

### Adding a rule

```toml
[[secrets]]
name = "internal_token"
regex = "\\binternal_[a-z0-9]{32}\\b"
action = "block"
```

`name` and `regex` are required; `action` defaults to `report`. Rules also accept
`min_entropy = 4.0` and `luhn = true` as extra filters, so a loose pattern can be
narrowed at the matcher instead of the regex.

Always add a positive case to `--selftest` for anything you add. A secret rule
with no test is a rule that has never been observed to fire.

## DNS pinning

The allowlist says `api.openai.com`. The broker resolves that name itself, opens
the socket to the address it got, and sends the original `Host` header. It never
hands the name to the system resolver and hopes.

This closes the gap where an allowlisted name resolves to an attacker-controlled
address — DNS poisoning, a hijacked resolver, or a compromised split-horizon
zone. With pinning, a name the policy allows still has to resolve somewhere the
policy allows.

It is **on by default** and it **fails closed**: a name that will not resolve is
a denial, not a fallback to the unpinned name.

```toml
[[destinations]]
pattern = "api.openai.com"
action  = "allow"
allowed_ips = ["52.94.236.248", "52.94.239.24"]   # optional; all addresses if omitted
```

With `allowed_ips` the check becomes enforcement rather than observation, which
is the version worth having. Without it, pinning still stops the TOCTOU gap
between checking the policy and opening the socket, but any address the name
resolves to is accepted.

| Flag | Default | |
|---|---|---|
| `--no-dns-pin` | off | Resolve at connect time through the normal path. The escape hatch for a name you cannot pin; it gives up the guarantee, so use it deliberately. |
| `--dns-ttl` | 60 | Seconds to reuse a resolution. Caching trades pin freshness for fewer lookups. |
| `--dns-cache-max` | 1024 | Names held before the oldest is evicted. |

Only successful resolutions are cached, so a transient failure cannot be pinned
for the whole TTL. Every request event records the `resolved_ip` that was
actually dialled, and it is part of the hash chain — so "which address did we
really talk to" is answerable later and cannot be edited afterwards.

## Per-client policy scoping

Different agents should not share an allowlist. A scope narrows what one client
can reach:

```toml
[[clients]]
name = "researcher"
inherit = false                                  # isolated: this list is the world
match_header = "x-egress-client"
match_value = "researcher"

[[clients.destinations]]
pattern = "*.readthedocs.io"
action = "allow"
```

- `inherit = true` (default) — the scope's rules are consulted first, then the
  global `[[destinations]]` list. Convenient for "additionally, this client may
  also reach X".
- `inherit = false` — the scope's list is the entire world for that client. The
  global list is never consulted.

A scope matches on the peer's CIDR, on a header the client sends, or both:

```toml
[[clients]]
name = "sandbox"
inherit = false
cidrs = ["10.8.0.0/24"]        # matched against the peer address

[[clients.destinations]]
pattern = "*.ollama.internal"
action = "allow"
```

**When both match a single scope, the network match wins.** A client that can be
inferred from its address cannot claim a different scope by sending a header —
weighting CIDR above header is what makes the header safe to trust at all.

The chosen scope is recorded on the request event and in the `X-Egress-Reason`
header, so a denial tells you *which* policy was applied. Clients matching no
scope fall back to the global list. `stats --json` includes a `by_scope` breakdown.

## Threshold alerting

A block that happens once is usually a false positive. The same block twenty
times in five minutes is an incident, and at 3am you want it to say so.

```toml
[[alerts]]
name = "deny_storm"
metric = "denies"                 # denies | requests | rule_hits | new_host
threshold = 25
window_minutes = 5
severity = "high"

[[alerts]]
name = "exfil_spike"
metric = "rule_hits"
selector = "exfil_directive"      # which rule; omit to count any
threshold = 1
window_minutes = 10
severity = "critical"
```

Alerts fire to **stderr** (so they land in journald, or in the terminal you are
watching) and are persisted to an `alerts` table. Read them back with:

```bash
python egress-broker.py alerts              # human-readable
python egress-broker.py alerts --json       # for scripting
python egress-broker.py alerts --since-days 1 --name deny_storm
```

`new_host` is the one that catches slow exfiltration: it fires once per host the
broker has never seen, which is exactly the shape of data staged somewhere new
before it is sent anywhere.

Counting is in memory and resets on restart; the `alerts` table is the durable
record. `cooldown_minutes` defaults to `window_minutes`, so a sustained problem
reports once per window rather than once per request.

## Tamper-evident audit

An audit log an attacker can edit is worse than no log, because it is evidence.
Every event stores a digest over its own contents plus the digest of the event
before it:

```
hash[n] = sha256(id | ts | kind | client | scope | method | host | port |
                  resolved_ip | path | bytes | action | reason | detail |
                  hash[n-1])
```

So editing any retained row invalidates every row after it, and inserting a row
breaks the sequence. Verify with:

```bash
python egress-broker.py verify            # exit 0 verified, 1 tampered
python egress-broker.py verify --json     # machine-readable, for a monitor
```

What this does and does not catch:

- **Edited row** — caught. The row no longer hashes to what the next row recorded.
- **Deleted row from the middle** — caught, same reason.
- **Truncated tail** — caught by a separately stored `chain_head`, which would
  still name a digest that no longer exists.
- **Deleted oldest prefix** — **not** detectable, and cannot be. Retention
  deletes the oldest events on purpose; the chain has no external anchor to
  notice. Everything retained is still internally consistent, so `verify` passes.
  If you need to prove a window was not truncated, copy the store off-host.
- **`--no-hash-chain`** — writes rows with no hashes at all. `verify` then reports
  "store was opened without hashing" and exits 0, because an unchained store is
  not a tampered one. Do not use it for evidence you intend to rely on.

The store also clamps `ts` to be non-decreasing with `id`, so retention always
deletes a chain-safe *prefix* rather than a scattering of rows. Pruning from the
middle would be indistinguishable from tampering and would make `verify` cry wolf
after every ordinary prune.

## Which host a request is judged by

A proxy sees two sources of authority: the request-target and the `Host` header.
A client can send an absolute-form target and a header naming a *different* host,
and the broker resolves that by trusting the request-target for everything —
the decision, the audit record, and the socket.

This is the property that makes a deny mean something. Evaluating the header
while dialling the target would let a client name an allowed host in the header
and reach anything at all; the reverse would let it name a blocked host and be
refused for the wrong reason. Both tests exist, because the "obvious fix" for
one direction is to start trusting the header and break the other.

`CONNECT` obeys the same rule, and it matters more there: for a CONNECT the
`Host` header is derived from the request-target, so the two are not independent
the way they are for a normal request — but they can still be sent disagreeing,
and reading the header is how a tunnel ends up judged against a name it is not
going to. CONNECT targets are authority-form (`host:port`) and are parsed
strictly, so an unparseable one is a `400` and a recorded denial rather than an
exception. A missing port means 443.

## Local storage

`serve` writes every decision to a local SQLite store. It defaults to
`%LOCALAPPDATA%/egress-broker/egress-broker.db` on Windows and
`$XDG_STATE_HOME/egress-broker/egress-broker.db` (or `~/.local/state/...`) elsewhere.
Pass `--db` to put it somewhere specific, or `--db :memory:` to throw it away.

The default is deliberately not the current directory. This tool gets run from
checkouts, and a database in a git working tree is a database that eventually gets
committed.

SQLite rather than an appended JSONL file because an audit trail you cannot query
is a log, not evidence. When an agent starts exfiltrating, the question is
"every event rule X matched, newest first, with the host and the byte count," and
that is an index, not a `grep`.

| Command | What it answers |
|---|---|
| `stats [--since-days N] [--json]` | What has this broker been blocking, and from where |
| `query --rule R [--host H] [--action A]` | The matching events, with their findings |
| `alerts [--since-days N] [--name N]` | What fired, and how bad it was |
| `verify [--json]` | Is the store's integrity intact |
| `export --out audit.jsonl [--since-days N]` | Hand the store to a log shipper |
| `prune [--retention-days N]` | Apply retention now and reclaim disk |

`--json` works on every one of them for scripting.

Four properties the implementation had to get right:

- **WAL mode.** `stats` and `query` read the store while the broker is serving. An
  audit trail you cannot consult during an incident is not much use.
- **Retention is enforced on write**, every 500 events, not by a cron job that
  might not run. A security tool that silently accumulates unbounded history is
  itself a liability — it keeps the very data it exists to detect. `--retention-days`
  (default 30) and `--max-db-mb` (default 64) both default on; pass `0` to disable.
- **One connection per thread.** `sqlite3` objects are not thread-safe and the
  broker handles each request on its own thread, so a single shared connection
  would need a lock around every statement and would serialise the proxy.
- **Reading never writes.** `stats`, `query`, `alerts` and `verify` open the store
  with pruning structurally disabled, so asking a question cannot destroy the
  evidence it is being asked about. They report the *writer's* retention settings,
  which are recorded in `meta`, because reporting a reader's own disabled window
  would tell you the broker keeps no history when it does.

`--audit path.jsonl` additionally writes JSONL, and the two can be combined; one
broken sink does not stop the other.

### Querying by rule name

Rule names are exact, and destination rules are namespaced, which is the part
that is easy to get wrong:

```bash
python egress-broker.py query --rule aws_access_key
python egress-broker.py query --rule 'destination:*.ngrok.io'
```

`query` returns one row per **event** with its findings attached. It used to join
events to findings and limit the joined rows, which returned a partial finding
list for a single event and one NULL-padded row per event with no findings — 7
events came back as 9 rows and every rule count was inflated.

## Design constraints

**No dependencies.** Python 3.9+ standard library. A control point that needs a
package install is a control point people remove.

**Fail closed.** No matching destination rule means deny. A body larger than
`max_body_bytes` is denied. A body the broker cannot decode is denied. A name
that will not resolve is denied. A policy with no destination rules refuses to
load, because it would silently deny everything.

**The audit log never contains a secret.** Matches are recorded as a 6-character
prefix plus a length. An audit log is precisely where a credential must not end
up, even though that is what people grep for when debugging. This is asserted
against the database file *and* its `-wal` and `-shm` siblings — WAL means a
deleted page can still be sitting in the sidecar file. See `SAMPLE` in the source.

**Two action levels, deliberately different.** `block`/`deny` refuses the
request. `report` forwards it and records a finding. `redact` forwards with the
matched span replaced by `[REDACTED:13b]`. Getting this balance wrong in either
direction is the main way this kind of tool dies: over-blocking trains people to
disable it, under-blocking makes it theater.

## Tests

Two suites, and the split is deliberate.

```bash
python egress-broker.py --selftest                  # pure, fast, no sockets
python tests/test_egress_broker.py                  # real sockets, real subprocesses
```

203 checks and 41 tests respectively. CI asserts both numbers, because
`unittest` exits 0 when it collects nothing and a suite that quietly stopped
running is indistinguishable from a suite that passes.

The check count is not the same on every interpreter, so it is asserted as two
numbers: how many checks actually *ran*, and run-plus-skipped. Two checks need
`tomllib`, which is stdlib only from 3.11, and on 3.9 the suite prints
`all checks passed: 201 run, 2 skipped` — the same 203 covered. Asserting only
the first number would have passed on 3.9 with two checks quietly missing, which
is exactly the version where the fallback TOML parser is the parser actually in
use and least worth being untested.

Two of the gates live in `ci/` as files rather than inside the workflow, because
a check that has never been run is a check that does not work:

- `python ci/import_gate.py` fails if any file imports a non-stdlib module. It
  derives the stdlib's locations from `sys.path` minus the site directories
  rather than hardcoding them, because three separate assumptions about where
  the stdlib lives are false on some platform: extension modules sit in `DLLs`,
  not `Lib`; `os` is frozen on 3.11+ so its "origin" is the string `frozen`; and
  on Windows `site-packages` is *inside* `Lib`, so an origin-based check happily
  calls `requests` stdlib.
- `python ci/prove_suites_can_fail.py` breaks `ip_allowed` so it permits every
  address, and separately injects one unsatisfiable check, requiring the
  selftest to fail at each and to be green again afterwards. It also requires
  the failure to *name a check*: a file too broken to run also exits non-zero,
  and without that distinction a broken negative control reads as a passing one.

`--selftest` exercises the policy engine as a function: given this policy and this
body, what is the verdict. It is fast, and when it fails it points at the rule.
It also covers the store, the hash chain, DNS pinning, client scoping, CONNECT
authority-form parsing and the alert engine, and each of those sections carries
negative controls — a threshold that is *not* reached, a row edited, a row deleted,
a name that will not resolve — so a check cannot pass by being vacuous.

`tests/test_egress_broker.py` starts the actual CLI as a subprocess on a loopback
port and drives it with an HTTP client. Nothing is mocked. It covers the class of
bug the engine-level tests cannot see — a header that never reaches the engine, a
deny response that never reaches the client, a store the handler cannot write,
history that does not survive a restart, a `verify` that would happily pass a
tampered store, the full secret appearing in the database file or its `-wal`
sibling.

Three things worth knowing if you add to it:

**Assert on `X-Egress-Decision`, not on the status code.** The first version of
this suite asserted `200`/`403` and produced six failures, all of them its own
fault: a request the broker correctly *allowed* was relayed to `api.openai.com`,
which replied `403 invalid_request_error` to the junk payload, and the test read
that as a broker denial. Every response carries `X-Egress-Decision: deny` or
`allow-dry-run`, and only the broker sets it.

**The suite fails if it leaks a proxy.** `BrokerProcess` records every pid it
spawns and the test asserts each one is gone at teardown. This exists because it
did not: `run_broker()` entered the process, and every test then wrote
`with self.run_broker():`, which entered it again, spawned a second broker, and
overwrote the handle. 19 tests passed while leaving 20 live proxies behind, each
holding a SQLite store open in a temp directory that `rmtree` then could not
remove. The check is verified against a reintroduction of that exact bug.

**Every feature has a mutation test.** A green suite proves nothing if it is
green for the wrong reason, so each of the four features above was verified by
breaking it — disabling the chain digest, making scope matching a no-op, making
thresholds unreachable, never constructing the pinner, letting readers prune —
and requiring the named tests to go red. Each mutation was killed by the check
that exists to catch exactly that thing.

**Two mutants taught the harness how to lie.** Both were reported as "the test
is too weak" and neither was:

- A mutant that read the `Host` header in preference to the request-target
  *survived* the parser-confusion tests. It had not survived anything: `str.rpartition`
  returns `('', '', whole)` when the separator is absent, so the mutant it was
  compared against happened to compute the original value. A "survivor" that is
  semantically identical to the original is not a test failure, it is a bad
  mutation, and the two look identical from the outside.
- A mutant that stopped resolving names *also* passed the DNS-pinning tests,
  because the pinning test addressed `127.0.0.1` directly. A literal passes
  through resolution unchanged, so an absent pinner and a working one produced
  the same `resolved_ip`. The tests now address `localhost` and assert the
  recorded address, which a name that was never resolved cannot fake.

## Limitations

These are real, not hedging.

**No TLS interception.** HTTPS bodies are encrypted and cannot be inspected, so
body rules apply only to plaintext HTTP. Host-level allow/deny and `allowed_ips`
still work for HTTPS, which is where most of the policy value sits, but a secret
in a request to `api.openai.com` over HTTPS will not be caught. This is the
single biggest gap, and it is large: an attacker who controls a document controls
what goes in the body, and today the body of an HTTPS request is the one place
they get to write unobserved. Adding MITM means generating a CA, distributing
trust, and handling the fact that you have just made the agent's TLS terminate on
a component whose job is to inspect traffic. That trade is worth making
deliberately, not by accident.

**The hash chain has no external anchor.** It proves the store is internally
consistent. It cannot prove the oldest rows were not deleted, because nothing
outside the store remembers them. Copy the store off-host if that matters.

**Only HTTP and CONNECT.** `HTTP/2`, WebSocket upgrade, and gRPC are not handled.
A CONNECT tunnel is passed through, so anything inside it is opaque. Its
request-target is authority-form and is parsed strictly: no port means 443, and
anything unparseable — port 0, port 99999, `port:https`, a bare IPv6 literal — is a
`400` with a recorded denial rather than an exception. That is a deliberate
choice, because the obvious way to write it (`int(path.rpartition(":")[2])`) turns
every malformed request into a dropped connection and no audit record at all,
since `rpartition` returns `('', '', whole)` when there is no colon to find.

**Body inspection is textual.** Base64-encoded or encrypted payloads are not
inspected. An attacker who controls a document controls how it is encoded.

**Not hardened against a determined local attacker.** This is a policy tool
running as a normal process on the agent's machine. Anyone who can read the
policy file can edit it; anyone who can `ptrace` the agent can bypass the proxy
entirely. Use it as one layer, not as a trust boundary on its own.

## Files

| Path | What |
|---|---|
| `egress-broker.py` | The whole tool. Proxy, policy engine, local store, selftest. |
| `policy.toml` | Default policy. Edit destinations first; the rest is reasonable. |
| `tests/test_egress_broker.py` | End-to-end suite over real sockets. |
| `egress-broker.service` | Hardened systemd unit, `StateDirectory` store. |
| `ci/import_gate.py` | Fails if anything imports outside the standard library. |
| `ci/prove_suites_can_fail.py` | Breaks the tool on purpose; requires the selftest to notice. |
| `.github/workflows/ci.yml` | Both suites, the import gate, and the tamper check. |

## Running as a service

`egress-broker.service` runs it as an unprivileged user with a 0700
`StateDirectory` for the store, and a sandbox that denies everything except
reading the policy and writing that directory. A proxy that can be talked into
reading arbitrary files is a worse problem than the one it prevents.

```bash
install -m 0755 egress-broker.py /usr/local/lib/egress-broker/egress-broker.py
install -m 0644 policy.toml          /etc/egress-broker/policy.toml
install -m 0644 egress-broker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now egress-broker
```

The unit binds loopback. Binding `0.0.0.0` turns this into an open relay for
anything that can reach the host, and the default policy's allowlist is not a
substitute for not doing that.

Because the store is under `StateDirectory` and the broker runs as its own user,
add a timer or `ExecStartPost` if you want integrity checked rather than only
available on request:

```ini
ExecStartPost=/usr/local/lib/egress-broker/egress-broker.py verify --db %S/egress-broker.db
```
