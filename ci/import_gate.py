"""Fail if any Python file here imports something outside the standard library.

The whole appeal of this tool is that it is one file you can read, copy to a
server, and run with the Python that is already installed. That promise dies the
moment somebody adds `requests`, so it is checked in CI rather than trusted.

Written as a file rather than a heredoc in the workflow for two reasons: it can
be run locally before pushing, and it can be tested. A gate that has never been
run is a gate that does not work.

Usage:  python ci/import_gate.py            # checks every .py in the repo
        python ci/import_gate.py --quiet
"""
from __future__ import annotations

import argparse
import ast
import importlib.machinery
import importlib.util
import pathlib
import sys
import sysconfig

# Modules that are not "ours" but are legitimately stdlib-or-nothing.
#
# tomllib joined the stdlib in 3.11. The tool imports it inside a try/except and
# falls back to its own parser on 3.9, so on an older interpreter the name is
# present in the source and absent from the interpreter. Allowing it by name is
# correct rather than convenient: there is no third-party package called
# tomllib that this could be masking, and a hardcoded table of "known stdlib
# names" would rot the first time the tool grew a new import.
EXEMPT = {"egress_broker", "tomllib"}

# Directory names that mean "third-party code lives here". Matched against path
# components, not substrings, so a project directory called `site-packages-docs`
# is not mistaken for one.
SITE_DIRS = frozenset({"site-packages", "dist-packages"})


def _stdlib_dirs() -> list[str]:
    """Every directory the interpreter uses for the standard library, and none
    for third-party code.

    Taken from `sys.path` with the site directories removed, rather than from a
    guess at what the stdlib looks like on each platform. That guess has three
    moving parts and all three bit during development of this file:

      * Pure-Python stdlib is `sysconfig['stdlib']` (`.../Lib`).
      * Extension modules live somewhere else entirely: `DESTSHARED`, which is
        `.../lib/pythonX.Y/lib-dynload` on POSIX -- except on Windows, where
        `sysconfig.get_config_var('DESTSHARED')` returns None and they sit in
        `.../DLLs` instead.
      * On Windows, `site-packages` is *inside* `.../Lib`, so "the origin is
        under the stdlib root" is true of `requests` as well as `json`. Any
        check that reasons about where a module loaded from is wrong here.

    `sys.path` already has all of this right: the interpreter put DLLs and Lib
    on it precisely so extension modules import. Removing the two directory
    names that mean "somebody pip-installed something here" is the whole job,
    and both spellings are stable across every platform and version.
    """
    roots: set[str] = set()

    stdlib = sysconfig.get_paths().get("stdlib")
    if stdlib:
        roots.add(str(pathlib.Path(stdlib).resolve()))

    for entry in list(sys.path):
        if not entry:
            continue
        try:
            path = pathlib.Path(entry).resolve()
        except OSError:
            continue
        if SITE_DIRS.intersection(path.parts):
            continue
        roots.add(str(path))

    return sorted(p for p in roots if pathlib.Path(p).is_dir())


def _is_stdlib(name: str, dirs: list[str]) -> bool:
    """True if `name` is part of the interpreter's own standard library.

    Asked as "can the stdlib dirs satisfy this import", never as "where did it
    load from". The latter has three traps this function would walk into:

      * On Windows site-packages sits *inside* Lib, so a third-party package
        happily resolves to a path under the stdlib root.
      * `os` is a frozen module on 3.11+, and `find_spec` reports its origin as
        the string "frozen" rather than a path.
      * Extension modules live in DLLs, outside Lib entirely.

    `sys.stdlib_module_names` answers all of that correctly but only exists from
    3.10, and this tool supports 3.9, so the older path asks PathFinder to
    search the stdlib directories and nothing else.
    """
    table = getattr(sys, "stdlib_module_names", None)
    if table is not None and name in table:
        return True
    if name in sys.builtin_module_names:
        return True
    if not dirs:
        return False
    try:
        return importlib.machinery.PathFinder.find_spec(name, dirs) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def imported_names(tree: ast.AST) -> list[tuple[int, str]]:
    """Every top-level module name the file imports, with its line number."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # `from . import x` is a relative import: local by definition.
                continue
            found.append((node.lineno, (node.module or "").split(".")[0]))
    return [(line, name) for line, name in found if name]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="only report problems")
    args = parser.parse_args()

    dirs = _stdlib_dirs()

    bad: list[str] = []
    checked = 0
    for path in sorted(pathlib.Path(".").rglob("*.py")):
        if "__pycache__" in path.parts or ".git" in path.parts:
            continue
        checked += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            bad.append(f"{path}: could not be parsed: {exc}")
            continue
        for lineno, name in imported_names(tree):
            if name in EXEMPT or _is_stdlib(name, dirs):
                continue
            bad.append(f"{path}:{lineno}: {name}")

    if bad:
        print("imports that are neither stdlib nor local:")
        print("\n".join(bad))
        print(f"\nThis tool ships as one file with no dependencies. If a name above")
        print("is genuinely required, it has to be vendored into egress-broker.py,")
        print("not added as an install requirement.")
        return 1

    if not args.quiet:
        print(f"stdlib only: {checked} file(s) checked on {sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())