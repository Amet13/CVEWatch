#!/usr/bin/env python3
"""Agent evals for unpatched: does the kit (skills) help an agent do the job?

Single file, standard library only. See evals/README.md.

  python3 evals/run.py --dry-run
  python3 evals/run.py --agent "claude -p {prompt} --permission-mode acceptEdits" \
      --label claude-code --model "<model>" --runs 3
"""

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASKS_DIR = os.path.join(ROOT, "evals", "tasks")
SKILLS_DIR = os.path.join(ROOT, "skills")
SMOKE_DB = os.path.join(ROOT, "fixtures", "smoke", "unpatched-db.sqlite")
VARIANTS = ("bare", "skills")
KINDS = ("config", "answer")

PRELUDE = (
    "\n\nThe vulnerability database for this task is at {db}. "
    "Pass it to unpatched commands with --db {db}. "
    "Do not use the network."
)


class TaskError(Exception):
    pass


# ---------------------------------------------------------------- tasks


def load_tasks(only=None):
    tasks = []
    for name in sorted(os.listdir(TASKS_DIR)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(TASKS_DIR, name)
        try:
            with open(path, encoding="utf-8") as f:
                task = json.load(f)
        except (OSError, ValueError) as e:
            raise TaskError(f"{name}: cannot read: {e}")
        validate_task(task, name)
        if only and task["id"] not in only:
            continue
        tasks.append(task)
    if only:
        missing = set(only) - {t["id"] for t in tasks}
        if missing:
            raise TaskError(f"unknown task id(s): {', '.join(sorted(missing))}")
    if not tasks:
        raise TaskError("no tasks found")
    return tasks


def need(cond, name, msg):
    if not cond:
        raise TaskError(f"{name}: {msg}")


def check_regex(pattern, name, where):
    need(isinstance(pattern, str), name, f"{where}: pattern must be a string")
    try:
        re.compile(pattern)
    except re.error as e:
        raise TaskError(f"{name}: {where}: bad regex {pattern!r}: {e}")


def safe_rel(path, name):
    need(isinstance(path, str) and path, name, "file paths must be non-empty strings")
    need(
        not os.path.isabs(path) and ".." not in path.split("/"),
        name,
        f"unsafe path {path!r}",
    )


def validate_task(t, name):
    need(isinstance(t, dict), name, "must be a JSON object")
    for key in ("id", "title", "prompt", "kind", "expect"):
        need(key in t, name, f"missing {key!r}")
    need(re.fullmatch(r"[a-z0-9-]+", t["id"]), name, "id must be kebab-case")
    need(name == t["id"] + ".json", name, "file name must be <id>.json")
    need(t["kind"] in KINDS, name, f"kind must be one of {KINDS}")
    need(isinstance(t["prompt"], str) and t["prompt"].strip(), name, "empty prompt")
    for path, text in t.get("files", {}).items():
        safe_rel(path, name)
        need(isinstance(text, str), name, f"file {path!r} must be text")
    ex = t["expect"]
    need(isinstance(ex, dict), name, "expect must be an object")
    if t["kind"] == "config":
        need(isinstance(t.get("config", "unpatched.yml"), str), name, "config path")
        for s in ex.get("stack", []):
            need("product" in s and "version" in s, name, "stack entries need product and version")
        for s in ex.get("stackExcludes", []):
            check_regex(s, name, "stackExcludes")
        for f in ex.get("findings", []):
            need("vuln" in f and "verdict" in f, name, "findings need vuln and verdict")
        for path in ex.get("files", []):
            safe_rel(path, name)
        for c in ex.get("fileContains", []):
            need("file" in c and "pattern" in c, name, "fileContains needs file and pattern")
            safe_rel(c["file"], name)
            check_regex(c["pattern"], name, "fileContains")
        for c in ex.get("fileNotContains", []):
            need("file" in c and "pattern" in c, name, "fileNotContains needs file and pattern")
            safe_rel(c["file"], name)
            check_regex(c["pattern"], name, "fileNotContains")
        need(
            ex.get("stack") or ex.get("findings") or ex.get("files"),
            name,
            "a config task must expect something",
        )
    else:
        need(ex.get("matches"), name, "an answer task needs expect.matches")
        for k in ("matches", "notMatches"):
            for p in ex.get(k, []):
                check_regex(p, name, k)
        order = ex.get("order", [])
        need(not order or len(order) >= 2, name, "order needs two or more patterns")
        for p in order:
            check_regex(p, name, "order")
    ref = t.get("reference")
    if ref is not None:
        need(isinstance(ref, dict), name, "reference must map paths to text")
        for path, text in ref.items():
            safe_rel(path, name)
            need(isinstance(text, str), name, f"reference {path!r} must be text")


# ------------------------------------------------------------ workdirs


def write_files(root, files):
    for path, text in files.items():
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def prepare(task, variant, keep_root):
    """A fresh project folder for one run."""
    work = tempfile.mkdtemp(prefix=f"unpatched-eval-{task['id']}-{variant}-", dir=keep_root)
    write_files(work, task.get("files", {}))
    if variant == "skills":
        for dest in (".claude/skills", ".agents/skills"):
            target = os.path.join(work, dest)
            os.makedirs(target, exist_ok=True)
            for entry in sorted(os.listdir(SKILLS_DIR)):
                src = os.path.join(SKILLS_DIR, entry)
                if os.path.isdir(src):
                    shutil.copytree(src, os.path.join(target, entry))
        with open(os.path.join(work, "AGENTS.md"), "w", encoding="utf-8") as f:
            f.write(
                "# unpatched\n\nSkills for this folder are in `.agents/skills/`. "
                "Read the one that matches the task before you start.\n"
            )
    return work


def snapshot(work):
    out = {}
    for base, dirs, names in os.walk(work):
        dirs[:] = [d for d in dirs if d not in (".git", ".claude", ".agents")]
        for n in names:
            p = os.path.join(base, n)
            try:
                with open(p, encoding="utf-8") as f:
                    out[os.path.relpath(p, work).replace(os.sep, "/")] = f.read()
            except (OSError, UnicodeDecodeError):
                pass
    return out


# ------------------------------------------------------------- scoring


def unpatched_bin(args):
    return args.unpatched or os.environ.get("UNPATCHED_BIN") or shutil.which("unpatched")


def score(task, work, answer, args, binary):
    """Return (passed, [problems])."""
    ex = task["expect"]
    problems = []
    if task["kind"] == "answer":
        for p in ex.get("matches", []):
            if not re.search(p, answer):
                problems.append(f"answer lacks /{p}/")
        for p in ex.get("notMatches", []):
            if re.search(p, answer):
                problems.append(f"answer must not match /{p}/")
        order = ex.get("order", [])
        if order:
            at = []
            for p in order:
                m = re.search(p, answer)
                at.append(m.start() if m else None)
            if None in at or at != sorted(at):
                problems.append("answer does not mention the items in the expected order")
        return not problems, problems

    # kind == config
    for path in ex.get("files", []):
        if not os.path.isfile(os.path.join(work, path)):
            problems.append(f"missing file {path}")
    files = snapshot(work)
    for c in ex.get("fileContains", []):
        if not re.search(c["pattern"], files.get(c["file"], "")):
            problems.append(f"{c['file']} lacks /{c['pattern']}/")
    for c in ex.get("fileNotContains", []):
        if re.search(c["pattern"], files.get(c["file"], "")):
            problems.append(f"{c['file']} must not match /{c['pattern']}/")
    cfg = task.get("config", "unpatched.yml")
    cfg_path = os.path.join(work, cfg)
    if not os.path.isfile(cfg_path):
        problems.append(f"missing {cfg}")
        return False, problems
    if not binary:
        problems.append("unpatched is not on PATH (use --unpatched or UNPATCHED_BIN)")
        return False, problems
    proc = subprocess.run(
        [binary, "check", "--offline", "--format", "json", "--db", SMOKE_DB, "--config", cfg_path],
        capture_output=True,
        text=True,
        cwd=work,
    )
    try:
        report = json.loads(proc.stdout)
    except ValueError:
        problems.append(f"`unpatched check` gave no JSON (exit {proc.returncode}): {proc.stderr.strip()[:300]}")
        return False, problems
    notes = [n for n in report.get("notes", []) if "database is" not in n or "old" not in n]
    if ex.get("noNotes", True) and notes:
        problems.append(f"report notes: {notes}")
    text = open(cfg_path, encoding="utf-8").read()
    for s in ex.get("stack", []):
        if not stack_has(text, s):
            problems.append(f"stack lacks {s}")
    for pat in ex.get("stackExcludes", []):
        if re.search(pat, text):
            problems.append(f"stack must not match /{pat}/")
    for f in ex.get("findings", []):
        hit = [
            x
            for x in report.get("findings", [])
            if x.get("vuln") == f["vuln"] and x.get("verdict") == f["verdict"]
            and (("bucket" not in f) or x.get("bucket") == f["bucket"])
            and (("fixed_in" not in f) or x.get("fixed_in") == f["fixed_in"])
        ]
        if not hit:
            problems.append(f"report lacks finding {f}")
    return not problems, problems


def stack_has(text, want):
    """Cheap check on the YAML text without a YAML parser: find the item block."""
    blocks = re.split(r"(?m)^\s*-\s+(?=\w+:)", text)
    for b in blocks:
        prod = re.search(r"(?m)^\s*(?:-\s+)?product:\s*['\"]?([^'\"\n#]+?)['\"]?\s*(?:#.*)?$", b)
        ver = re.search(r"(?m)^\s*version:\s*['\"]?([^'\"\n#]+?)['\"]?\s*(?:#.*)?$", b)
        exp = re.search(r"(?m)^\s*exposure:\s*['\"]?([^'\"\n#]+?)['\"]?\s*(?:#.*)?$", b)
        if not prod or not ver:
            continue
        if prod.group(1) != want["product"] or ver.group(1) != str(want["version"]):
            continue
        if "exposure" in want and (exp.group(1) if exp else "internal") != want["exposure"]:
            continue
        return True
    return False


# -------------------------------------------------------------- runner


def dry_run(tasks, args):
    binary = unpatched_bin(args)
    bad = 0
    for t in tasks:
        for v in args.variants:
            root = tempfile.mkdtemp(prefix="unpatched-eval-dry-")
            try:
                work = prepare(t, v, root)
                if v == "skills":
                    assert os.path.isfile(os.path.join(work, ".claude/skills/set-up-unpatched/SKILL.md")), "skills not copied"
                else:
                    assert not os.path.exists(os.path.join(work, ".claude")), "bare run has skills"
                note = ""
                ref = t.get("reference")
                if ref is not None and binary and t["kind"] == "config":
                    write_files(work, ref)
                    ok, problems = score(t, work, "", args, binary)
                    note = " reference scores " + ("pass" if ok else f"FAIL {problems}")
                    if not ok:
                        bad += 1
                elif ref is not None and t["kind"] == "answer":
                    ok, problems = score(t, work, ref.get("answer.md", ""), args, binary)
                    note = " reference scores " + ("pass" if ok else f"FAIL {problems}")
                    if not ok:
                        bad += 1
                elif ref is not None:
                    note = " (reference not scored: unpatched not found)"
                print(f"ok   {t['id']:<28} {v:<7}{note}")
            except (AssertionError, OSError) as e:
                bad += 1
                print(f"FAIL {t['id']:<28} {v:<7} {e}")
            finally:
                shutil.rmtree(root, ignore_errors=True)
    print(f"\n{len(tasks)} task(s), {len(args.variants)} variant(s): " + ("all valid" if not bad else f"{bad} problem(s)"))
    return 1 if bad else 0


def run_agent(command, prompt, work, timeout):
    cmd = command.replace("{prompt}", shlex.quote(prompt))
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, shell=True, cwd=work, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.returncode, time.time() - started
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        return out, 124, time.time() - started


def real_run(tasks, args):
    binary = unpatched_bin(args)
    if not binary:
        sys.exit("error: unpatched is not on PATH; use --unpatched <path> or UNPATCHED_BIN")
    results = []
    keep_root = tempfile.mkdtemp(prefix="unpatched-evals-")
    for t in tasks:
        for v in args.variants:
            for n in range(args.runs):
                work = prepare(t, v, keep_root)
                prompt = t["prompt"] + PRELUDE.format(db=SMOKE_DB)
                answer, code, secs = run_agent(args.agent, prompt, work, args.timeout)
                ok, problems = score(t, work, answer, args, binary)
                results.append(
                    {
                        "task": t["id"],
                        "variant": v,
                        "run": n + 1,
                        "pass": ok,
                        "problems": problems,
                        "exitCode": code,
                        "seconds": round(secs, 1),
                    }
                )
                print(f"{'pass' if ok else 'FAIL'} {t['id']} {v} #{n + 1} ({secs:.0f}s)")
                if not args.keep:
                    shutil.rmtree(work, ignore_errors=True)
    if not args.keep:
        shutil.rmtree(keep_root, ignore_errors=True)
    else:
        print(f"working directories kept in {keep_root}")
    summary = {}
    for r in results:
        s = summary.setdefault(f"{r['task']}/{r['variant']}", {"n": 0, "pass": 0})
        s["n"] += 1
        s["pass"] += 1 if r["pass"] else 0
    date = datetime.date.today().isoformat()
    out = {
        "date": date,
        "label": args.label,
        "model": args.model,
        "agentCommand": args.agent,
        "runsPerCell": args.runs,
        "variants": args.variants,
        "tasks": [t["id"] for t in tasks],
        "summary": summary,
        "results": results,
    }
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"{date}-{args.label}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"results written to {path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="validate tasks and prepare folders; call no agent")
    ap.add_argument("--agent", help='agent command; "{prompt}" is replaced by the quoted prompt')
    ap.add_argument("--label", help="short name of the agent setup (file name of the results)")
    ap.add_argument("--model", default="", help="free text, recorded as given")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--variant", default="all", help="bare, skills, a comma list, or all")
    ap.add_argument("--task", action="append", help="only this task id (repeatable)")
    ap.add_argument("--unpatched", help="path to the unpatched binary used for scoring")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per agent run")
    ap.add_argument("--keep", action="store_true", help="keep working directories")
    ap.add_argument("--out", default=os.path.join(ROOT, "evals", "results"))
    args = ap.parse_args()

    args.variants = list(VARIANTS) if args.variant == "all" else args.variant.split(",")
    for v in args.variants:
        if v not in VARIANTS:
            ap.error(f"unknown variant {v!r}; use {', '.join(VARIANTS)}")
    if not os.path.isfile(SMOKE_DB):
        sys.exit(f"error: {SMOKE_DB} is missing")
    try:
        tasks = load_tasks(args.task)
    except TaskError as e:
        sys.exit(f"error: {e}")
    if args.dry_run:
        sys.exit(dry_run(tasks, args))
    if not args.agent or not args.label:
        ap.error("--agent and --label are required (or use --dry-run)")
    if "{prompt}" not in args.agent:
        ap.error('--agent must contain "{prompt}"')
    sys.exit(real_run(tasks, args))


if __name__ == "__main__":
    main()
