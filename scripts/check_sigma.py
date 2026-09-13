#!/usr/bin/env python3
"""Validate every Sigma rule under sigma-rules/ in two stages.

Stage 1 is a gate. A rule that cannot be parsed, or cannot be converted to a
query by any configured backend, can never fire no matter where it is deployed.
That is a build failure.

Stage 2 is advisory. `sigma check` reports schema, tag and field-name issues
against SigmaHQ's own conventions. Some of those conventions do not apply to
this repository on purpose (the directory layout and the custom
`detection.maturity.*` tags), so they are counted and printed but never fail
the build.

The two stages answer different questions. Stage 2 asks whether a rule is a
well-formed document. Stage 1 asks whether it can become a query, which is the
question that decides whether it can ever run.

Three outcomes, and NOT CHECKED is never folded into PASS. A file that yields
neither a query nor an error was not measured, and saying so is the point.

Exit codes:  0 = every rule converted   1 = at least one failed
             2 = nothing failed but something could not be checked

Usage:
  python scripts/check_sigma.py [--rules-dir sigma-rules] [--targets eql,lucene]
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# pySigma emits this on every invocation when its remote validator config 404s.
# It is unrelated to the rule under test and must not be read as a failure.
NOISE = "sigmahq_windows_validator"

# Progress chatter sigma-cli prints around its real output. Stripping it is how
# "a query came back" is told apart from "nothing came back", which is the
# difference between a pass and a file that was never measured.
CHATTER = ("Parsing Sigma rules", "Checking Sigma rules")

# Absolute paths in a CI log are noise; the filename is printed on the line above.
PATH_RE = re.compile(r"\s*in\s+\S*[/\\][^\s]*")


def run(cmd, timeout=300):
    """Returns (rc, filtered_output). rc is None if the command could not run."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as e:
        return None, str(e)
    out = "\n".join(l for l in (p.stdout + p.stderr).splitlines() if NOISE not in l)
    return p.returncode, out.strip()


def substance(text):
    """The output lines that are not progress chatter."""
    return [l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith(CHATTER)]


def reason(text):
    """The most informative line of a failure, with absolute paths scrubbed.

    sigma-cli reports the specific problem as a `* ...` bullet under a generic
    "Errors found in Sigma rules:" header, so the bullet is what a reader needs.
    Anything else falls back to the first non-chatter line.
    """
    lines = substance(text)
    if not lines:
        return "no output"
    pick = next((l for l in lines if l.startswith("*")), lines[0])
    return PATH_RE.sub("", pick.lstrip("* ").removeprefix("Error: ")).strip()


def convert(path, targets, pipeline):
    """Try each backend in order.

    Returns ("ok", backend) if a query came back, ("fail", reason) if a backend
    reported an error, or ("nothing", reason) if the file produced neither,
    which is what an empty or rule-less .yml does.
    """
    errors = []
    saw_clean_empty = False
    for t in targets:
        rc, out = run(["sigma", "convert", "-t", t, "-p", pipeline, str(path)])
        if rc == 0 and substance(out):
            return "ok", t
        if rc == 0:
            saw_clean_empty = True          # parsed without error, produced no query
            continue
        errors.append(f"{t}: {reason(out)}")
    if errors:
        return "fail", " | ".join(errors)
    if saw_clean_empty:
        return "nothing", "no Sigma rule found in file (no query, no error)"
    return "nothing", "backend produced no result"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules-dir", default="sigma-rules")
    ap.add_argument("--targets", default="eql,lucene",
                    help="comma-separated backends, tried in order")
    ap.add_argument("--pipeline", default="sysmon")
    a = ap.parse_args(argv)

    if not shutil.which("sigma"):
        print("NOT CHECKED  sigma-cli is not on PATH. Install with: pip install "
              "sigma-cli pySigma-backend-elasticsearch pySigma-pipeline-sysmon "
              "pySigma-validators-sigmahq")
        return 2

    root = Path(a.rules_dir)
    rules = sorted(p for p in root.rglob("*") if p.suffix in (".yml", ".yaml"))
    if not rules:
        print(f"NOT CHECKED  no .yml or .yaml files found under {root}/")
        return 2

    targets = [t.strip() for t in a.targets.split(",") if t.strip()]

    # ---- Stage 1: the gate --------------------------------------------------
    ok, failed, unchecked = {}, [], []
    for r in rules:
        verdict, detail = convert(r, targets, a.pipeline)
        rel = r.relative_to(root)
        if verdict == "ok":
            ok[detail] = ok.get(detail, 0) + 1
        elif verdict == "fail":
            failed.append((rel, detail))
        else:
            unchecked.append((rel, detail))

    total = len(rules)
    print(f"Stage 1 (gate): {sum(ok.values())}/{total} files convert to a query")
    for t, n in sorted(ok.items()):
        print(f"    {n:>3} via {t}")
    for rel, detail in failed:
        print(f"    FAIL         {rel}\n                 {detail}")
    for rel, detail in unchecked:
        print(f"    NOT CHECKED  {rel}\n                 {detail}")

    # ---- Stage 2: advisory --------------------------------------------------
    # `sigma check` exits 1 both when it finds issues and when it dies, so the
    # exit code cannot tell those apart. A crash leaves a Python traceback and a
    # completed run does not, which is the signal that can.
    rc, out = run(["sigma", "check", str(root)])
    crashed = rc is None or rc not in (0, 1) or "Traceback (most recent call last)" in out
    if crashed or not substance(out):
        print(f"\nStage 2 (advisory): NOT CHECKED  sigma check did not complete "
              f"({reason(out) if out else 'no output'})")
    else:
        n = sum(1 for l in out.splitlines() if l.startswith("issue="))
        print(f"\nStage 2 (advisory): {n} validation issues, not a build failure. "
              f"Run `sigma check {root}/` for detail.")

    # Stage 2 never decides the exit code; only stage 1 does.
    if failed:
        print(f"\nFAIL  {len(failed)} file(s) cannot become a query on any of: "
              f"{', '.join(targets)}")
        return 1
    if unchecked:
        print(f"\nNOT CHECKED  {len(unchecked)} file(s) yielded no rule and no error")
        return 2
    print(f"\nPASS  every rule under {root}/ converts to a query")
    return 0


if __name__ == "__main__":
    sys.exit(main())
