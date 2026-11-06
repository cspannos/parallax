#!/usr/bin/env python3
"""Dependency provenance audit for Parallax (see docs/PROVENANCE.md).

Checks every third-party package in the three Cargo workspaces (the main
workspace, zkvm/risc0, zkvm/sp1) and the RISC Zero guest lockfiles:

- each package comes from crates.io or an allow-listed public GitHub repo
- each package declares a license, and that license (or one of its OR
  alternatives) is an open-source license on the allow list

Prints a summary and exits non-zero on any violation. Needs only python3 and
cargo; `cargo metadata` may download crate metadata on first run.

    python3 scripts/audit-dependencies.py
"""

import json
import pathlib
import re
import subprocess
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKSPACES = ["Cargo.toml", "zkvm/risc0/Cargo.toml", "zkvm/sp1/Cargo.toml"]
GUEST_LOCKS = sorted((ROOT / "zkvm/risc0/methods").glob("*/Cargo.lock"))

ALLOWED_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "git+https://github.com/circlefin/malachite.git",  # Malachite v0.8.0 tag
    "git+https://github.com/risc0/RustCrypto-hashes",  # RISC Zero's accelerated sha2
    "git+https://github.com/sp1-patches/RustCrypto-hashes",  # SP1's accelerated sha2
}

# OSI-approved or equivalent permissive licenses, plus MPL-2.0 (file-level
# copyleft, used unmodified). A package passes if any OR-alternative passes.
ALLOWED_LICENSES = {
    "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause",
    "BSD-3-Clause", "BSD-1-Clause", "0BSD", "ISC", "Zlib", "Unlicense", "CC0-1.0",
    "MIT-0", "BSL-1.0", "Unicode-3.0", "Unicode-DFS-2016", "CDLA-Permissive-2.0",
    "MPL-2.0",
}


def base_source(src):
    return re.split(r"[?#]", src)[0]


def license_ok(expr):
    """True if the SPDX expression is satisfiable from ALLOWED_LICENSES."""
    expr = expr.replace("/", " OR ")
    # Every AND-term must be satisfied; within a term, one OR-alternative suffices.
    for term in re.split(r"\s+AND\s+", expr.replace("(", "").replace(")", "")):
        alts = [a.strip() for a in re.split(r"\s+OR\s+", term)]
        if not any(a in ALLOWED_LICENSES for a in alts):
            return False
    return True


def main():
    packages = {}
    local = set()
    for ws in WORKSPACES:
        out = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", str(ROOT / ws)],
            check=True, capture_output=True, text=True,
        ).stdout
        for p in json.loads(out)["packages"]:
            if p["source"] is None:
                local.add(p["name"])
            else:
                packages[(p["name"], p["version"], p["source"])] = p.get("license")

    guest_sources = Counter()
    for lock in GUEST_LOCKS:
        for src in re.findall(r'^source = "([^"]+)"', lock.read_text(), re.M):
            guest_sources[base_source(src)] += 1

    problems = []
    sources = Counter(base_source(s) for (_, _, s) in packages)
    for src in set(sources) | set(guest_sources):
        if src not in ALLOWED_SOURCES:
            problems.append(f"source not allow-listed: {src}")
    licenses = Counter()
    for (name, version, _), lic in sorted(packages.items()):
        licenses[lic or "NONE"] += 1
        if not lic:
            problems.append(f"no license declared: {name} {version}")
        elif not license_ok(lic):
            problems.append(f"license not allow-listed: {name} {version} ({lic})")

    print(f"Parallax crates (this repository): {len(local)}")
    print(f"Third-party packages (host workspaces): {len(packages)}")
    print("Sources:")
    for s, n in sources.most_common():
        print(f"  {n:5}  {s}")
    print(f"Guest lockfile sources ({len(GUEST_LOCKS)} lockfiles):")
    for s, n in guest_sources.most_common():
        print(f"  {n:5}  {s}")
    print("Licenses:")
    for l, n in licenses.most_common():
        print(f"  {n:5}  {l}")
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  " + p)
        sys.exit(1)
    print("\nOK: every dependency is public and under an allow-listed open-source license.")


if __name__ == "__main__":
    main()
