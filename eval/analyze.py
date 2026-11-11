"""Turns campaign runs (eval/campaign.py) into coverage curves and bug tables.

    python eval/analyze.py results/raw/single results/raw/parallel --out results

Coverage is measured the same way for every fuzzer: the inputs each one saved (Sleuth's queue,
libFuzzer's corpus, plus the seeds at time 0) are replayed in the order they were written
through the Sleuth build of the target (`--replay`), and the number of distinct edges reached by
time t is the union over the inputs saved by then. Blind mode keeps (but does not use) the
inputs that reached something new, so it is measured the same way too.

Bugs, per run, from the canary log (targets/BUGS.md): the first time each bug was reached and
triggered; and detected = the first crash whose input triggers it (every saved crash input is run
again alone with a canary log of its own; the last bug it triggers is the one it crashed on).

Writes <out>/summary.json, <out>/bugs.md, <out>/coverage.png (and coverage_parallel.png), and a
copy of the summary for the dashboard (web/public/campaign.json).
"""
import argparse
import glob
import json
import os
import platform
import statistics
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = ".exe" if platform.system() == "Windows" else ""
TARGETS = ["png", "xml", "der", "json", "vm"]
BUGS = {"png": [1, 2, 3, 4, 5], "xml": [6, 7, 8, 9], "der": [10, 11, 12, 13], "json": [14, 15, 16], "vm": [17, 18, 19, 20]}
ORDER = ["sleuth", "sleuth-nocmp", "blind", "libfuzzer", "sleuth-par", "libfuzzer-par"]
# Categorical slots in fixed order (the validated reference palette, light mode); a fuzzer keeps
# its colour in every chart (the parallel runs reuse their single-core counterparts' colours).
COLOR = {"sleuth": "#2a78d6", "sleuth-nocmp": "#eb6834", "blind": "#1baf7a", "libfuzzer": "#eda100",
         "sleuth-par": "#2a78d6", "libfuzzer-par": "#eda100"}
STEP = 30  # seconds between points of the coverage curves


def target_bin(target):
    return os.path.join(ROOT, "build", target, "sleuth" + EXE)


def saved_inputs(run_dir, fuzzer):
    """(mtime, path) of every input the fuzzer saved, plus the seeds."""
    if fuzzer.startswith("libfuzzer"):
        files = glob.glob(os.path.join(run_dir, "corpus", "*"))
    elif fuzzer == "sleuth-par":
        files = glob.glob(os.path.join(run_dir, "out", "corpus", "*"))
    else:
        files = glob.glob(os.path.join(run_dir, "out", "queue", "*"))
    return sorted((os.path.getmtime(f), f) for f in files if os.path.isfile(f))


def replay(target, files):
    """Edges per file, via the target's --replay mode (in batches, for the command line)."""
    out = {}
    batch = 100
    for i in range(0, len(files), batch):
        chunk = files[i:i + batch]
        r = subprocess.run([target_bin(target), "--replay", *chunk], capture_output=True, text=True,
                           env=dict(os.environ, ASAN_OPTIONS="symbolize=0"))
        got = {}
        for line in r.stdout.splitlines():
            # "<path> e1 e2 ..." (the path may contain spaces: match it against the batch)
            for f in chunk:
                if line.startswith(f + " ") or line == f:
                    got[f] = set(map(int, line[len(f):].split()))
                    break
        if len(got) < len(chunk):
            # Something in the batch crashed the replay: one by one for the rest.
            for f in chunk:
                if f in got:
                    continue
                r1 = subprocess.run([target_bin(target), "--replay", f], capture_output=True, text=True,
                                    env=dict(os.environ, ASAN_OPTIONS="symbolize=0"))
                line = r1.stdout.strip()
                got[f] = set(map(int, line[len(f):].split())) if line.startswith(f) else set()
        out.update(got)
    return out


def coverage_curve(run_dir, meta):
    target, start = meta["target"], meta["start_ms"] / 1000
    seeds = sorted(glob.glob(os.path.join(ROOT, "targets", target, "seeds", "*")))
    entries = [(start, f) for f in seeds] + saved_inputs(run_dir, meta["fuzzer"])
    edges = replay(target, [f for _, f in entries])
    covered, curve = set(), []
    times = [max(0.0, t - start) for t, _ in entries]
    idx = 0
    for t in range(0, meta["seconds"] + 1, STEP):
        while idx < len(entries) and times[idx] <= t:
            covered |= edges.get(entries[idx][1], set())
            idx += 1
        curve.append(len(covered))
    while idx < len(entries):  # written during shutdown
        covered |= edges.get(entries[idx][1], set())
        idx += 1
    curve[-1] = len(covered)
    return curve


def read_bug_log(path, start_ms):
    reached, triggered = {}, {}
    if not os.path.exists(path):
        return reached, triggered
    with open(path, errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) != 3 or parts[0] not in "RT":
                continue
            try:
                bug, t = int(parts[1]), (int(parts[2]) - start_ms) / 1000
            except ValueError:
                continue
            d = reached if parts[0] == "R" else triggered
            d[bug] = min(d.get(bug, t), t)
    return reached, triggered


def crash_files(run_dir, fuzzer):
    if fuzzer.startswith("libfuzzer"):
        files = glob.glob(os.path.join(run_dir, "crashes", "crash-*"))
    elif fuzzer == "sleuth-par":
        files = glob.glob(os.path.join(run_dir, "out", "worker-*", "crashes", "crash-*"))
    else:
        files = glob.glob(os.path.join(run_dir, "out", "crashes", "crash-*"))
    return sorted((os.path.getmtime(f), f) for f in files if not f.endswith((".txt", ".min")))


def bug_of_crash(target, path):
    """The bug a crash input crashes on: the last one its canary log shows triggered."""
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "bugs.log")
        subprocess.run([target_bin(target), path], capture_output=True,
                       env=dict(os.environ, SLEUTH_BUG_LOG=log, ASAN_OPTIONS="symbolize=0"), timeout=60)
        last = None
        if os.path.exists(log):
            for line in open(log):
                p = line.split()
                if len(p) == 3 and p[0] == "T":
                    last = int(p[1])
        return last


def detections(run_dir, meta, pool):
    start = meta["start_ms"] / 1000
    files = crash_files(run_dir, meta["fuzzer"])
    # libFuzzer saves every crashing input; most repeat a known bug. They are tried in the
    # order found and a bug's first detection is kept.
    bugs = list(pool.map(lambda f: bug_of_crash(meta["target"], f[1]), files))
    detected = {}
    for (t, _), b in zip(files, bugs):
        if b is not None:
            detected[b] = min(detected.get(b, t - start), t - start)
    return detected, len(files)


def fuzzer_stats(run_dir, meta):
    """Executions and the fuzzer's own crash count, where the fuzzer reports them."""
    s = {}
    if meta["fuzzer"] in ("sleuth", "sleuth-nocmp", "blind"):
        p = os.path.join(run_dir, "out", "stats.json")
        if os.path.exists(p):
            d = json.load(open(p))
            s = {"execs": d["execs"], "execs_per_s": d["execs_per_s"], "unique_crashes": d["crashes_unique"],
                 "crash_execs": d.get("crash_execs", 0)}
    elif meta["fuzzer"] == "sleuth-par":
        p = os.path.join(run_dir, "out", "summary.json")
        if os.path.exists(p):
            d = json.load(open(p))
            s = {"execs": d["execs"], "execs_per_s": d["execs"] / max(d["elapsed_s"], 1), "unique_crashes": d["crashes_unique"]}
    else:
        log = os.path.join(run_dir, "log.txt")
        execs = 0
        if os.path.exists(log):
            for line in open(log, errors="replace"):
                # "#115127: cov: 68 ft: 83 corp: 41 exec/s: 0 ..." (fork mode status lines)
                if line.startswith("#") and "cov:" in line:
                    try:
                        execs = max(execs, int(line[1:line.index(":")]))
                    except ValueError:
                        pass
        s = {"execs": execs, "execs_per_s": execs / meta["seconds"]}
    return s


def analyze_run(run_dir, pool):
    meta = json.load(open(os.path.join(run_dir, "meta.json")))
    reached, triggered = read_bug_log(os.path.join(run_dir, "bugs.log"), meta["start_ms"])
    detected, n_crash_files = detections(run_dir, meta, pool)
    return {
        "target": meta["target"], "fuzzer": meta["fuzzer"], "rep": meta["rep"], "seconds": meta["seconds"],
        "cores": meta.get("cores", 1), "coverage": coverage_curve(run_dir, meta),
        "reached": reached, "triggered": triggered, "detected": detected, "crash_files": n_crash_files,
        **fuzzer_stats(run_dir, meta),
    }


def summarize(runs):
    out = {}
    for r in runs:
        out.setdefault(r["target"], {}).setdefault(r["fuzzer"], []).append(r)
    summary = {"step_s": STEP, "targets": {}}
    for target, by_f in out.items():
        tsum = {}
        for f, rs in by_f.items():
            curves = [r["coverage"] for r in rs]
            n = min(len(c) for c in curves)
            finals = [c[n - 1] for c in curves]
            bugs = {}
            for b in BUGS[target]:
                row = {}
                for level in ("reached", "triggered", "detected"):
                    times = [r[level].get(b, r[level].get(str(b))) for r in rs]
                    found = sorted(t for t in times if t is not None)
                    # Median time over the repetitions, counting a miss as "after the end": only
                    # defined when at least half of the runs found the bug.
                    med = None
                    if len(found) * 2 >= len(rs) and found:
                        padded = found + [float("inf")] * (len(rs) - len(found))
                        med = statistics.median(padded)
                        med = None if med == float("inf") else round(med, 1)
                    row[level] = {"runs": len(found), "of": len(rs), "median_s": med, "times": [None if t is None else round(t, 1) for t in times]}
                bugs[str(b)] = row
            tsum[f] = {
                "reps": len(rs), "seconds": rs[0]["seconds"], "cores": rs[0]["cores"],
                "coverage_median": [statistics.median(c[i] for c in curves) for i in range(n)],
                "coverage_min": [min(c[i] for c in curves) for i in range(n)],
                "coverage_max": [max(c[i] for c in curves) for i in range(n)],
                "final_edges": finals,
                "execs_per_s": [round(r.get("execs_per_s", 0)) for r in rs],
                "unique_crashes": [r.get("unique_crashes") for r in rs],
                "crash_files": [r["crash_files"] for r in rs],
                "bugs": bugs,
            }
        summary["targets"][target] = tsum
    return summary


def edges_total(target):
    r = subprocess.run([target_bin(target), "--edges"], capture_output=True, text=True)
    return int(r.stdout.strip() or 0)


def plot(summary, fuzzers, path, title):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    targets = [t for t in TARGETS if t in summary["targets"] and any(f in summary["targets"][t] for f in fuzzers)]
    if not targets:
        return
    fig, axes = plt.subplots(1, len(targets), figsize=(3.4 * len(targets), 3.3), squeeze=False)
    for ax, t in zip(axes[0], targets):
        for f in fuzzers:
            d = summary["targets"][t].get(f)
            if not d:
                continue
            xs = [i * summary["step_s"] / 60 for i in range(len(d["coverage_median"]))]
            ax.fill_between(xs, d["coverage_min"], d["coverage_max"], color=COLOR[f], alpha=0.15, linewidth=0)
            ax.plot(xs, d["coverage_median"], color=COLOR[f], linewidth=2, label=f)
        ax.set_title(f"{t} ({summary['edges_total'][t]} edges)", fontsize=10)
        ax.set_xlabel("minutes", fontsize=9)
        ax.grid(color="#e5e5e5", linewidth=0.6)
        ax.tick_params(labelsize=8)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
    axes[0][0].set_ylabel("edges covered (median, min-max band)", fontsize=9)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False, fontsize=9)
    fig.suptitle(title, fontsize=11)
    fig.tight_layout(rect=(0, 0.08, 1, 0.95))
    fig.savefig(path, dpi=130)
    plt.close(fig)


def bug_table(summary, fuzzers):
    lines = []
    present = [f for f in fuzzers if any(f in summary["targets"].get(t, {}) for t in TARGETS)]
    head = "| bug | target | " + " | ".join(present) + " |"
    lines += [head, "|" + "---|" * (len(present) + 2)]
    for t in TARGETS:
        if t not in summary["targets"]:
            continue
        for b in BUGS[t]:
            cells = []
            for f in present:
                d = summary["targets"][t].get(f)
                if not d:
                    cells.append("")
                    continue
                trig, det = d["bugs"][str(b)]["triggered"], d["bugs"][str(b)]["detected"]

                def fmt(x):
                    if x["runs"] == 0:
                        return "-"
                    m = x["median_s"]
                    return f"{x['runs']}/{x['of']}" + (f" ({m:.0f}s)" if m is not None else "")
                cells.append(f"T {fmt(trig)}, D {fmt(det)}")
            lines.append(f"| {b} | {t} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("raw", nargs="+", help="campaign output directories")
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    ap.add_argument("--web", default=os.path.join(ROOT, "web", "public", "campaign.json"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    run_dirs = sorted(os.path.dirname(m) for raw in args.raw for m in glob.glob(os.path.join(raw, "*", "*", "rep*", "meta.json")))
    print(f"{len(run_dirs)} runs")
    runs = []
    with ThreadPoolExecutor(max_workers=max(2, (os.cpu_count() or 4) - 2)) as pool:
        for i, d in enumerate(run_dirs):
            runs.append(analyze_run(d, pool))
            print(f"  [{i + 1}/{len(run_dirs)}] {d}: {runs[-1]['coverage'][-1]} edges, "
                  f"triggered {sorted(map(int, runs[-1]['triggered']))}, detected {sorted(runs[-1]['detected'])}", flush=True)
    summary = summarize(runs)
    summary["edges_total"] = {t: edges_total(t) for t in summary["targets"]}
    summary["runs"] = [{k: v for k, v in r.items() if k != "coverage"} | {"final_edges": r["coverage"][-1]} for r in runs]
    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    if args.web:
        os.makedirs(os.path.dirname(args.web), exist_ok=True)
        with open(args.web, "w") as fh:
            json.dump(summary, fh)
    single = [f for f in ORDER[:4]]
    par = ORDER[4:]
    plot(summary, single, os.path.join(args.out, "coverage.png"), "Coverage over time, one core each")
    plot(summary, par, os.path.join(args.out, "coverage_parallel.png"), "Coverage over time, parallel")
    with open(os.path.join(args.out, "bugs.md"), "w") as fh:
        fh.write("T = triggered, D = detected (crash reported); runs that found it / runs, median time over runs\n\n")
        fh.write(bug_table(summary, ORDER) + "\n")
    print(open(os.path.join(args.out, "bugs.md")).read())


if __name__ == "__main__":
    main()
