"""Mutation sweep for egress-broker, run against a SCRATCH COPY.

Why a scratch copy
------------------
The first version of this harness rewrote `egress-broker.py` in place, in the
working tree. A sweep that dies halfway leaves a mutant sitting in the repo
looking like a legitimate commit, and the damage is invisible until someone
reads the diff. So the live repo is hashed before and after, every mutation is
applied to a throwaway copy, and the harness refuses to start if it cannot make
one.

Why a canary
------------
A sweep that reports "26/26 killed" is exactly what a broken harness reports.
The canary below is a provably semantically identical mutation -- float
multiplication is commutative, so `a - b * c` and `a - c * b` cannot differ --
and it MUST survive. If it is reported as killed, the verdict for every other
mutant in the run is worthless and the run is discarded.

Lessons encoded here, each one bought with a false result:
  * `with` on every write; an unflushed buffer made a mutant that never ran,
    which is indistinguishable from a survivor.
  * the written file is re-read from disk and compared before it is trusted.
  * py_compile must succeed or the run is discarded.
  * __pycache__ is purged around every run, or a stale .pyc masks the change.
  * selftest failures are read from STDOUT (`_expect` prints there), not stderr.
  * the suite is asserted green before the sweep and again after the revert, so
    a harness bug cannot masquerade as a pass.
  * the e2e test COUNT is read from `Ran N tests`. `unittest` exits 0 when it
    collects nothing, so a mutant that stopped collection looks like a pass.

Usage:
  python ci/mutation.py                    # full sweep
  python ci/mutation.py chain alerts       # only these groups
  python ci/mutation.py CANARY             # prove the harness can see a survivor

Run it from the repo root. It never writes to the working tree: mutations are
applied to a throwaway copy, and this repo's `egress-broker.py` is hashed before
and after so an escape is visible rather than silent.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

# The repo this file lives in, so the harness works from a clone instead of
# only from one machine's hardcoded path.
SRC_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join("egress-broker.py")
TESTS = os.path.join("tests", "test_egress_broker.py")
Q = chr(34)

# Files a run needs. Copied wholesale so the tests' __file__-relative lookup of
# the tool keeps working inside the scratch tree.
COPY = [
    "egress-broker.py",
    "policy.toml",
    os.path.join("tests", "test_egress_broker.py"),
]

CANARY = "CANARY"


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_caches(root):
    for dirpath, dirnames, _ in os.walk(root):
        for d in list(dirnames):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(dirpath, d), ignore_errors=True)
                dirnames.remove(d)


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    # newline="" so Windows does not rewrite every LF as CRLF and make the file
    # differ from what we intended to write.
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run(root, args, timeout=900):
    return subprocess.run(
        [sys.executable] + args, capture_output=True, text=True, timeout=timeout, cwd=root
    )


def run_selftest(root):
    p = run(root, [TOOL, "--selftest"], timeout=300)
    failed = sorted(set(
        m.group(1).strip() for m in re.finditer(r"^  FAIL (.+)$", p.stdout, re.M)
    ))
    ran = re.search(r"all checks passed: (\d+) run", p.stdout)
    return p.returncode, failed, (int(ran.group(1)) if ran else -1), p.stdout[-700:]


def run_e2e(root):
    p = run(root, [TESTS], timeout=900)
    text = p.stdout + p.stderr
    names = sorted(set(
        m.group(1).strip()
        for m in re.finditer(r"^(?:FAIL|ERROR): (\S+)", text, re.M)
    ))
    ran = re.search(r"^Ran (\d+) tests?", text, re.M)
    return p.returncode, names, (int(ran.group(1)) if ran else -1), text[-700:]


SUITES = {"selftest": run_selftest, "e2e": run_e2e}


def check_green(root, label, expect_selftest, expect_e2e):
    ok = True
    for name, fn in SUITES.items():
        code, failures, count, tail = fn(root)
        want = expect_selftest if name == "selftest" else expect_e2e
        good = code == 0 and not failures and count == want
        ok = ok and good
        print(f"  {label} {name:9} exit={code} checks={count} failures={len(failures)} "
              f"{'OK' if good else 'BAD'}")
        if not good:
            for line in tail.strip().splitlines()[-10:]:
                print("      " + line)
    return ok


# --------------------------------------------------------------------------
# The mutation table. Each entry replaces exactly one occurrence.
#   (id, description, suite, target substring, replacement line body)
# --------------------------------------------------------------------------

M = [
    # -- canary: must SURVIVE, and proves the harness can see a survivor -----
    # Two lines, not one: `since = time.time() - since_days * 86400` occurs three
    # times in the file, and an anchor that matches three places is not an
    # anchor. `cap = max(1, int(limit))` occurs once, which makes the pair unique.
    (CANARY, "float multiply is commutative, so this cannot change behaviour",
     "selftest",
     "        since = time.time() - since_days * 86400\n"
     "        cap = max(1, int(limit))",
     "        since = time.time() - 86400 * since_days\n"
     "        cap = max(1, int(limit))"),

    # -- accept queue -------------------------------------------------------
    ("backlog", "the accept queue drops back to the socketserver default of 5",
     "selftest", "    request_queue_size = 128",
     "    request_queue_size = socketserver.TCPServer.request_queue_size"),

    # -- chain --------------------------------------------------------------
    ("chain", "prev_hash is never compared to the previous row",
     "selftest", "                if prev_stored is not None and linked != prev_stored:",
     "                if False:"),
    ("chain", "row contents are never recomputed from their hash",
     "selftest", "                if recomputed != stored:",
     "                if False:"),
    ("chain", "a stored chain_head mismatch is not reported",
     "selftest", "            head_ok = prev_stored == head",
     "            head_ok = True"),
    ("chain", "a row that lost its hash mid-chain is accepted",
     "selftest", "                if stored is None:", "                if False:"),
    ("chain", "retention no longer re-points the chain head",
     "selftest", "        self._refresh_head()", "        pass  # MUTANT"),

    # -- alerts -------------------------------------------------------------
    ("alerts", "the threshold comparison never fires",
     "selftest", "                if count < rule.threshold:", "                if True:"),
    ("alerts", "the cooldown never suppresses a repeat",
     "selftest",
     "                if last is not None and (now - last) < rule.cooldown_minutes * 60:",
     "                if False:"),
    ("alerts", "the sliding window never evicts, so counts only grow",
     "selftest", "        horizon = now - rule.window_minutes * 60",
     '        horizon = float("-inf")'),
    ("alerts", "a firing alert is not handed to the sink",
     "selftest", "            self._emit(alert)", "            pass"),

    # -- store discipline ---------------------------------------------------
    ("store", "a read-only handle still writes writer settings into meta",
     "selftest", "            if self._is_writer:",
     "            if True:"),
    ("store", "a reader is allowed to prune",
     "selftest", "        if not self._is_writer:", "        if False:"),
    ("store", "the audit insert no longer holds the chain lock",
     "selftest", "        with self._chain_lock:", "        if True:"),

    # -- scope --------------------------------------------------------------
    ("scope", "an isolated scope still inherits the global allowlist",
     "selftest", "            if not scope.inherit:", "            if False:"),
    ("scope", "scope rules are not consulted before the global list",
     "selftest", "            hit = self._best_match(scope.destinations, host, port)",
     "            hit = None"),

    # -- dns ----------------------------------------------------------------
    ("dns", "the pinner is never constructed",
     "e2e", "        pinner = DnsPinner(ttl=args.dns_ttl, max_hosts=args.dns_cache_max)",
     "        pinner = None"),
    ("dns", "a CONNECT name that will not resolve is relayed anyway",
     "e2e", "                pinned_ip = pinner.resolve(host, port)[0] if pinner else host",
     "                pinned_ip = host"),
    ("dns", "the request path relays an unresolvable name anyway",
     "e2e", "            pinned_ip, dns_error = self._resolve(host, port)",
     "            pinned_ip, dns_error = host, None"),
    ("dns", "the resolved address is not checked against allowed_ips",
     "e2e", "            if not self.engine.policy.ip_allowed(rule, pinned_ip or " + Q + Q + "):",
     "            if False:"),

    # -- parser / connect ---------------------------------------------------
    ("parser", "absolute-form drops the explicit port",
     "e2e",
     "            port = parts.port or (443 if parts.scheme == " + Q + "https" + Q + " else 80)",
     "            port = 443 if parts.scheme == " + Q + "https" + Q + " else 80"),
    ("parser", "the origin-form port in the Host header is ignored",
     "e2e", "                return h, int(p), raw, " + Q + "http" + Q,
     "                return h, 80, raw, " + Q + "http" + Q),
    ("parser", "an empty Host header falls back to the loopback origin",
     "e2e", "        host = self.headers.get(" + Q + "Host" + Q + ", " + Q + Q + ")",
     "        host = self.headers.get(" + Q + "Host" + Q + ", " + Q + "127.0.0.1" + Q + ")"),
    ("connect", "authority-form is never parsed at all",
     "e2e", "            host, port = _split_authority(self.path)",
     "            host, port = self._split_target()[0], 443"),
    ("connect", "an out-of-range port is accepted",
     "e2e", "    if not 1 <= port <= 65535:", "    if port < 0:"),
    ("connect", "the bracketed IPv6 branch never runs",
     "selftest", "    if target.startswith(" + Q + "[" + Q + "):", "    if False:"),
    ("connect", "a portless CONNECT is not defaulted to 443",
     "e2e", "    if " + Q + ":" + Q + " in target:", "    if False:"),
]


def main():
    wanted = set(sys.argv[1:])
    # The canary always runs. It carries no group id, so filtering on groups
    # alone would drop it and then report the run void for its absence -- a
    # subset run must still prove it can see a survivor.
    rows = [m for m in M if m[0] == CANARY or not wanted or m[0] in wanted]

    live_tool = os.path.join(SRC_REPO, TOOL)
    before = digest(live_tool)
    print(f"live repo: {SRC_REPO}")
    print(f"  tool sha256 before sweep: {before[:16]}")

    root = tempfile.mkdtemp(prefix="mutate-")
    for rel in COPY:
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(SRC_REPO, rel), dst)
    clean_caches(root)
    print(f"scratch copy: {root}")
    print()

    tool_path = os.path.join(root, TOOL)
    original = read(tool_path)

    print("== baseline ==")
    if not check_green(root, "baseline", 210, 42):
        shutil.rmtree(root, ignore_errors=True)
        sys.exit("baseline is not green; the harness cannot be trusted")
    print()

    results = []
    try:
        for mid, desc, suite, target, repl in rows:
            clean_caches(root)
            n = original.count(target)
            if n != 1:
                verdict = "PATTERN-MISS" if n == 0 else "PATTERN-AMBIGUOUS"
                results.append((mid, desc, suite, verdict))
                print(f"  {verdict:12} {mid:8} {desc}  ({n} matches)")
                continue
            write(tool_path, original.replace(target, repl, 1))
            if read(tool_path) != original.replace(target, repl, 1):
                results.append((mid, desc, suite, "WRITE-FAILED"))
                print(f"  {'WRITE-FAILED':12} {mid:8} {desc}")
                continue
            c = subprocess.run([sys.executable, "-m", "py_compile", tool_path],
                               capture_output=True, text=True)
            if c.returncode != 0:
                results.append((mid, desc, suite, "WILL-NOT-COMPILE"))
                print(f"  {'WILL-NOT-COMPILE':12} {mid:8} {desc}")
                print("               " + c.stderr.strip().splitlines()[-1])
                continue
            clean_caches(root)
            code, failures, count, tail = SUITES[suite](root)
            killed = code != 0 and bool(failures)
            verdict = "KILLED" if killed else "SURVIVED"
            results.append((mid, desc, suite, verdict))
            print(f"  {verdict:12} {mid:8} {desc}")
            for f in list(failures)[:3]:
                print(f"               - {f}")
            if not killed and not failures and code != 0:
                print("               (nonzero exit but nothing named -- see below)")
            elif killed and count in (-1, 0):
                print(f"               (suite ran {count} tests)")
    finally:
        write(tool_path, original)
        print()

    print("== after revert ==")
    restored = check_green(root, "restored", 210, 42)

    after = digest(live_tool)
    untouched = before == after
    print(f"\nlive repo tool sha256 after sweep: {after[:16]}  "
          f"{'UNTOUCHED' if untouched else 'CHANGED -- the sweep escaped the scratch copy'}")
    shutil.rmtree(root, ignore_errors=True)

    # The canary is the only survivor that is allowed. If it died, the harness
    # is broken and every verdict in this run is discarded.
    canary = [r for r in results if r[0] == CANARY]
    canary_ok = bool(canary) and canary[0][3] == "SURVIVED"
    if not canary_ok:
        print("\nCANARY DID NOT SURVIVE -- the harness kills things that cannot be "
              "killed, so no verdict above means anything.")

    killed = [r for r in results if r[3] == "KILLED"]
    broken = [r for r in results if r[3] in ("PATTERN-MISS", "PATTERN-AMBIGUOUS",
                                            "WRITE-FAILED", "WILL-NOT-COMPILE")]
    survivors = [r for r in results if r[3] == "SURVIVED" and r[0] != CANARY]

    print()
    print(f"killed {len(killed)} / {len(results) - len(broken)} runnable mutants")
    print(f"canary {'survived as required' if canary_ok else 'FAILED -- run is void'}")
    print(f"live repo {untouched and 'untouched' or 'MODIFIED'}")
    if broken:
        print(f"\n{len(broken)} mutant(s) never ran:")
        for r in broken:
            print(f"  {r[3]}: {r[0]} -- {r[1]}")
    if survivors:
        print(f"\n{len(survivors)} real survivor(s) -- these are weak tests, or bugs:")
        for r in survivors:
            print(f"  {r[0]}: {r[1]}  [{r[2]}]")

    bad = survivors or broken or not restored or not untouched or not canary_ok
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
