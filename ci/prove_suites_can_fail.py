"""Prove the selftest can actually fail, rather than asserting that it can.

A green suite is not evidence of anything on its own: it is equally consistent
with "the code is correct" and with "the checks are not connected to the code".
The only way to tell those apart is to break the code on purpose and require the
suite to notice.

Three mutations, each checking something different:

  1. A real behaviour change. `ip_allowed` is made to permit every address. If
     the selftest is genuinely wired to the engine, a check about DNS pinning
     stops passing.
  2. A real check failure, with no code change. If a failing check does not
     produce a non-zero exit, then mutation 1 would have "passed" for the wrong
     reason.
  3. A restore check, because a step that leaves the tree broken proves nothing
     about the next run.

Mutation 1 must fail *as a check*, not as a crash. A SyntaxError or an
ImportError also exits non-zero, so a bare exit-code assertion would be
satisfied by a file too broken to run. The output is required to name a check.

Usage:  python ci/prove_suites_can_fail.py
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

TOOL = pathlib.Path("egress-broker.py")

# Behaviour mutation: an address outside `allowed_ips` is now permitted. The
# selftest asserts the opposite ("an address outside allowed_ips is refused even
# though the name is allowed"), so this can only pass unnoticed if that check is
# not actually exercising this function.
BEHAVIOUR_OLD = (
    "        return any(addr.version == net.version and addr in net for net in allowed)\n"
)
BEHAVIOUR_NEW = "        return True  # deliberately broken by CI\n"

# Reporting mutation: no engine code changes, one check is made unsatisfiable.
# Guards the exit path itself, so mutation 1 cannot pass by exiting non-zero for
# some unrelated reason.
#
# Anchored on the tail of selftest(), immediately before the skip/failure
# report. When this anchor went stale after the summary was reworded, the count
# check below turned a negative control into a hard failure rather than letting
# it pass for the wrong reason -- which is what it is for.
REPORT_OLD = (
    "    for s in skipped:\n"
    '        print(f"  skip {s}")\n'
)
REPORT_NEW = (
    '    _expect(False, "negative control injected by CI", failures)\n'
    "\n"
    "    for s in skipped:\n"
    '        print(f"  skip {s}")\n'
)


def read_source() -> str:
    """Read the tool without translating line endings.

    `open(..., newline=None)` is the default and it rewrites CRLF to LF on the
    way in and LF to CRLF on the way out. A read/write pair through it is not
    an identity on Windows: every line in the file changes, and this script's
    restore leaves a diff behind that looks like an edit nobody made.
    """
    with open(TOOL, encoding="utf-8", newline="") as fh:
        return fh.read()


def write_source(text: str) -> None:
    with open(TOOL, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_selftest(tool: pathlib.Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(tool), "--selftest"],
        capture_output=True, text=True, timeout=600,
    )
    return proc.returncode, proc.stdout + proc.stderr


def named_check_failure(output: str) -> str | None:
    """The first check the suite reported as failing, or None."""
    for line in output.splitlines():
        if line.startswith("  - "):
            return line[4:].strip()
    return None


def attempt(label: str, old: str, new: str, expect_check: bool) -> bool:
    """Apply one mutation in place, require it to fail, then restore.

    In place rather than on a copy in a temp directory, because the selftest
    loads `policy.toml` relative to its own location. A copy elsewhere cannot
    find it, exits non-zero, and names no failing check -- which is a crash
    wearing the costume of a passing negative control. That is the exact
    confusion the "named a failing check" assertion exists to catch, and it
    caught this script.

    The original bytes are held in memory and restored in a finally, and only
    the mutated text is ever written to disk.
    """
    original = read_source()
    count = original.count(old)
    if count != 1:
        print(f"  FAIL  {label}: anchor matched {count} times, expected exactly 1")
        return False

    ok = True
    try:
        write_source(original.replace(old, new))
        code, output = run_selftest(TOOL)
    finally:
        write_source(original)

    if code == 0:
        print(f"  FAIL  {label}: selftest still exited 0 with the code broken")
        ok = False
    else:
        named = named_check_failure(output)
        if named is None:
            print(f"  FAIL  {label}: exited {code} but named no failing check.")
            print("        A crash is not a failing test.")
            for line in [l for l in output.splitlines() if l.strip()][-6:]:
                print(f"        {line}")
            ok = False
        else:
            verb = "failed the check" if expect_check else "exited non-zero"
            print(f"  ok    {label}: {verb} -> {code}")
            print(f"          {named}")

    # Restoring must be green again. If it is not, the harness has left the tree
    # in a state where every later run inherits the damage.
    code, output = run_selftest(TOOL)
    if code != 0:
        print(f"  FAIL  {label}: the restored tool does not pass (exit {code})")
        ok = False
    else:
        checks = sum(1 for l in output.splitlines() if l.startswith("  ok   "))
        print(f"  ok    {label}: restored, {checks} checks green")
    return ok


def main() -> int:
    if not TOOL.is_file():
        print(f"run this from the repo root; {TOOL} not found")
        return 1

    print("baseline")
    code, output = run_selftest(TOOL)
    checks = sum(1 for l in output.splitlines() if l.startswith("  ok   "))
    if code != 0:
        print(f"  FAIL  the suite does not pass before anything is broken (exit {code})")
        for line in output.splitlines()[-15:]:
            print(f"        {line}")
        return 1
    print(f"  ok    green before we touch anything: {checks} checks")

    results = [
        attempt("behaviour mutation", BEHAVIOUR_OLD, BEHAVIOUR_NEW, expect_check=True),
        attempt("reporting mutation", REPORT_OLD, REPORT_NEW, expect_check=True),
    ]
    if all(results):
        print("\nthe selftest fails when the code is broken and when a check fails, "
              "and passes when it is not")
        return 0
    print("\nthis suite cannot be trusted to fail, so it cannot be trusted to pass")
    return 1


if __name__ == "__main__":
    sys.exit(main())