"""Runs fuzzing campaigns: every (target, fuzzer, repetition) for a fixed time, many at once.

    python eval/campaign.py single   --time 900 --reps 3 --jobs 14 --out results/raw/single
    python eval/campaign.py parallel --time 600 --workers 8 --jobs 2 --out results/raw/parallel

Fuzzers (single core):
    sleuth         Sleuth: coverage feedback, input-to-state, checksum repair, dictionary
    sleuth-nocmp   Sleuth without the comparison feedback (no input-to-state, no repair, no
                   learned tokens): the ablation
    blind          the same mutations without any coverage feedback: the baseline
    libfuzzer      libFuzzer from the same clang (-fork=1 -ignore_crashes=1, so that it keeps
                   going after a crash like the others), same dictionary, same seeds
Fuzzers (parallel, --workers cores each):
    sleuth-par     sleuth-parallel (Rust supervisor, shared curated corpus)
    libfuzzer-par  libFuzzer -fork=N

Every run gets its own directory <out>/<target>/<fuzzer>/rep<k>/ with meta.json (command, start
and end time), bugs.log (the canary log, see targets/BUGS.md) and the fuzzer's own output.
eval/analyze.py turns those into coverage curves and bug tables.
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if platform.system() == "Windows" else ""
TARGETS = ["png", "xml", "der", "json", "vm"]
SINGLE = ["sleuth", "sleuth-nocmp", "blind", "libfuzzer"]
PARALLEL = ["sleuth-par", "libfuzzer-par"]


def paths(target):
    b = os.path.join(ROOT, "build")
    return {
        "sleuth": os.path.join(b, "sleuth" + EXE),
        "target": os.path.join(b, target, "sleuth" + EXE),
        "libfuzzer": os.path.join(b, target, "libfuzzer" + EXE),
        "seeds": os.path.join(ROOT, "targets", target, "seeds"),
        "dict": os.path.join(ROOT, "targets", target, "dict"),
        "parallel": os.path.join(ROOT, "parallel", "target", "release", "sleuth-parallel" + EXE),
    }


def command(fuzzer, target, run_dir, seconds, seed, workers):
    p = paths(target)
    out = os.path.join(run_dir, "out")
    if fuzzer in ("sleuth", "sleuth-nocmp", "blind"):
        cmd = [p["sleuth"], "fuzz", "-t", p["target"], "-i", p["seeds"], "-o", out, "--time", str(seconds),
               "--dict", p["dict"], "--seed", str(seed), "--quiet"]
        if fuzzer == "sleuth-nocmp":
            cmd.append("--no-cmp")
        if fuzzer == "blind":
            cmd.append("--blind")
        return cmd, 1
    if fuzzer in ("libfuzzer", "libfuzzer-par"):
        n = 1 if fuzzer == "libfuzzer" else workers
        corpus, crashes = os.path.join(run_dir, "corpus"), os.path.join(run_dir, "crashes")
        os.makedirs(corpus, exist_ok=True)
        os.makedirs(crashes, exist_ok=True)
        cmd = [p["libfuzzer"], f"-fork={n}", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1", "-max_len=4096",
               "-timeout=1", f"-max_total_time={seconds}", f"-dict={p['dict']}", f"-seed={seed}",
               f"-artifact_prefix={crashes}{os.sep}", "-print_final_stats=1", corpus, p["seeds"]]
        return cmd, n
    if fuzzer == "sleuth-par":
        cmd = [p["parallel"], "--fuzzer", p["sleuth"], "-t", p["target"], "-i", p["seeds"], "-o", out,
               "--workers", str(workers), "--time", str(seconds), "--dict", p["dict"], "--", "--quiet"]
        return cmd, workers
    raise ValueError(fuzzer)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["single", "parallel"])
    ap.add_argument("--time", type=int, default=900, help="seconds per run")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2), help="cores to use at once")
    ap.add_argument("--workers", type=int, default=8, help="cores per parallel run")
    ap.add_argument("--targets", nargs="*", default=TARGETS)
    ap.add_argument("--fuzzers", nargs="*")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    args.out = os.path.abspath(args.out)  # every run works in its own directory
    fuzzers = args.fuzzers or (SINGLE if args.mode == "single" else PARALLEL)
    for t in args.targets:
        for k, v in paths(t).items():
            if k != "parallel" and not os.path.exists(v):
                sys.exit(f"missing {v}: run python build.py (and python targets/make_inputs.py)")
    if args.mode == "parallel" and "sleuth-par" in fuzzers and not os.path.exists(paths(TARGETS[0])["parallel"]):
        sys.exit("missing sleuth-parallel: run cargo build --release in parallel/")

    # Interleave fuzzers and targets so that each wave of runs mixes them (the machine's load
    # then affects every fuzzer alike).
    runs = []
    for rep in range(args.reps):
        for t in args.targets:
            for f in fuzzers:
                runs.append((t, f, rep))
    pending = list(runs)
    active = []  # (proc, cores, run_dir, meta, logfile)
    used = 0
    t0 = time.time()
    while pending or active:
        # Start what fits.
        i = 0
        while i < len(pending):
            t, f, rep = pending[i]
            run_dir = os.path.join(args.out, t, f, f"rep{rep}")
            seed = 1000 * (rep + 1) + TARGETS.index(t)
            cmd, cores = command(f, t, run_dir, args.time, seed, args.workers)
            if used + cores > args.jobs and active:
                i += 1
                continue
            pending.pop(i)
            if os.path.exists(os.path.join(run_dir, "meta.json")):
                print(f"skip (done): {run_dir}")
                continue
            if os.path.exists(run_dir):
                shutil.rmtree(run_dir)
            os.makedirs(run_dir)
            cmd, cores = command(f, t, run_dir, args.time, seed, args.workers)  # recreate dirs it needs
            if args.dry_run:
                print(" ".join(cmd))
                continue
            env = dict(os.environ, SLEUTH_BUG_LOG=os.path.join(run_dir, "bugs.log"))
            log = open(os.path.join(run_dir, "log.txt"), "w")
            meta = {"target": t, "fuzzer": f, "rep": rep, "seconds": args.time, "seed": seed, "cores": cores,
                    "cmd": cmd, "start_ms": int(time.time() * 1000)}
            proc = subprocess.Popen(cmd, cwd=run_dir, env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            active.append((proc, cores, run_dir, meta, log))
            used += cores
            print(f"[{time.time() - t0:7.0f}s] start {t} {f} rep{rep} ({used}/{args.jobs} cores, {len(pending)} pending)", flush=True)
        if args.dry_run:
            break
        time.sleep(2)
        still = []
        for proc, cores, run_dir, meta, log in active:
            elapsed = time.time() - meta["start_ms"] / 1000
            if proc.poll() is None and elapsed > args.time + 300:
                proc.kill()  # should not happen: every fuzzer has its own time limit
            if proc.poll() is None:
                still.append((proc, cores, run_dir, meta, log))
                continue
            log.close()
            meta["end_ms"] = int(time.time() * 1000)
            meta["exit_code"] = proc.returncode
            with open(os.path.join(run_dir, "meta.json"), "w") as fh:
                json.dump(meta, fh, indent=1)
            used -= cores
            print(f"[{time.time() - t0:7.0f}s] done  {meta['target']} {meta['fuzzer']} rep{meta['rep']} (exit {proc.returncode})", flush=True)
        active = still
    print(f"all {len(runs)} runs finished in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
