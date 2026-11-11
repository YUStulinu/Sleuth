"""End-to-end tests against the built targets and controller (python build.py first).

    python -m pytest tests -q
"""
import glob
import json
import os
import platform
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
import analyze  # noqa: E402

EXE = ".exe" if platform.system() == "Windows" else ""
BUILD = os.path.join(ROOT, "build")
SLEUTH = os.path.join(BUILD, "sleuth" + EXE)
PARALLEL = os.path.join(ROOT, "parallel", "target", "release", "sleuth-parallel" + EXE)
TARGETS = ["png", "xml", "der", "json", "vm"]
BUGS = analyze.BUGS

needs_build = pytest.mark.skipif(not os.path.exists(SLEUTH), reason="run python build.py first")


def target(t, flavour="sleuth"):
    return os.path.join(BUILD, t, flavour + EXE)


def run_with_log(exe, path, tmp_path, *args):
    log = tmp_path / "bugs.log"
    if log.exists():
        log.unlink()
    r = subprocess.run([exe, *args, path], capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, SLEUTH_BUG_LOG=str(log)))
    events = log.read_text().split("\n") if log.exists() else []
    trig = {int(e.split()[1]) for e in events if e.startswith("T ")}
    reached = {int(e.split()[1]) for e in events if e.startswith("R ")}
    return r, reached, trig


@needs_build
@pytest.mark.parametrize("t", TARGETS)
def test_seeds_are_clean(t, tmp_path):
    """Seeds parse without crashing and trigger no bug."""
    for seed in sorted(glob.glob(os.path.join(ROOT, "targets", t, "seeds", "*"))):
        r, _, trig = run_with_log(target(t), seed, tmp_path)
        assert r.returncode == 0, (seed, r.stderr[-2000:])
        assert trig == set(), seed


@needs_build
@pytest.mark.parametrize("bug", [b for t in TARGETS for b in BUGS[t]])
@pytest.mark.parametrize("flavour", ["sleuth", "libfuzzer"])
def test_every_planted_bug_triggers_and_is_detected(bug, flavour, tmp_path):
    t = next(t for t in TARGETS if bug in BUGS[t])
    exe = target(t, flavour)
    if not os.path.exists(exe):
        pytest.skip(f"no {flavour} build")
    poc = os.path.join(ROOT, "targets", t, "pocs", f"bug{bug}")
    r, reached, trig = run_with_log(exe, poc, tmp_path)
    assert bug in reached and bug in trig
    assert r.returncode != 0
    assert "ERROR: AddressSanitizer" in r.stderr, r.stderr[-2000:]
    # The analysis attributes the crash to this bug.
    assert analyze.bug_of_crash(t, poc) == bug


@needs_build
def test_replay_reports_edges():
    seeds = sorted(glob.glob(os.path.join(ROOT, "targets", "json", "seeds", "*")))
    edges = analyze.replay("json", seeds)
    assert set(edges) == set(seeds)
    assert all(len(e) > 10 for e in edges.values())
    total = analyze.edges_total("json")
    assert all(max(e) <= total for e in edges.values())


@needs_build
def test_fuzz_finds_new_coverage_and_a_bug(tmp_path):
    out = tmp_path / "out"
    log = tmp_path / "bugs.log"
    r = subprocess.run([SLEUTH, "fuzz", "-t", target("json"), "-i", os.path.join(ROOT, "targets", "json", "seeds"), "-o", str(out),
                        "--time", "60", "--execs", "60000", "--seed", "7", "--quiet",
                        "--dict", os.path.join(ROOT, "targets", "json", "dict")],
                       capture_output=True, text=True, timeout=300, env=dict(os.environ, SLEUTH_BUG_LOG=str(log)))
    assert r.returncode == 0, r.stderr
    stats = json.loads((out / "stats.json").read_text())
    assert stats["done"] and stats["execs"] >= 1000
    assert stats["corpus"] > 3  # grew beyond the seeds
    seeds_cov = len(set().union(*analyze.replay("json", sorted(glob.glob(os.path.join(ROOT, "targets", "json", "seeds", "*")))).values()))
    assert stats["edges_covered"] > seeds_cov
    crashes = json.loads((out / "crashes.json").read_text())
    assert crashes, "bug 15 (1e309) is found within seconds"
    for c in crashes:
        assert os.path.exists(out / "crashes" / c["file"])
        assert c["kind"] and c["frames"]
    assert (out / "plot.csv").read_text().startswith("elapsed_s,execs,edges,corpus,unique_crashes")
    queue = os.listdir(out / "queue")
    assert len(queue) == stats["corpus"]


@needs_build
def test_blind_mode_does_not_grow_the_corpus(tmp_path):
    out = tmp_path / "out"
    subprocess.run([SLEUTH, "fuzz", "-t", target("xml"), "-i", os.path.join(ROOT, "targets", "xml", "seeds"), "-o", str(out),
                    "--execs", "20000", "--blind", "--quiet", "--seed", "3"], check=True, timeout=300)
    stats = json.loads((out / "stats.json").read_text())
    assert stats["mode"] == "blind"
    assert stats["corpus"] == len(os.listdir(os.path.join(ROOT, "targets", "xml", "seeds")))
    # The inputs that reached something new are kept for measurement only.
    assert any(f.endswith("-blind") for f in os.listdir(out / "queue"))


@needs_build
def test_tmin_keeps_the_signature(tmp_path):
    poc = os.path.join(ROOT, "targets", "xml", "pocs", "bug7")
    out = tmp_path / "min"
    r = subprocess.run([SLEUTH, "tmin", "-t", target("xml"), "-i", poc, "-o", str(out), "--max-execs", "400"],
                       capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr
    assert out.stat().st_size < os.path.getsize(poc)
    tri = subprocess.run([SLEUTH, "triage", "-t", target("xml"), poc, str(out)], capture_output=True, text=True, timeout=120)
    lines = [json.loads(x) for x in tri.stdout.splitlines()]
    assert [x["status"] for x in lines] == ["crash", "crash"]
    assert lines[0]["key"] == lines[1]["key"]
    assert "element" in lines[0]["frames"][0]


@needs_build
def test_triage_reports_ok_inputs(tmp_path):
    seed = os.path.join(ROOT, "targets", "vm", "seeds", "loop.svm")
    tri = subprocess.run([SLEUTH, "triage", "-t", target("vm"), seed], capture_output=True, text=True, timeout=60)
    assert json.loads(tri.stdout)["status"] == "ok"


@needs_build
@pytest.mark.skipif(not os.path.exists(PARALLEL), reason="cargo build --release in parallel/ first")
def test_parallel_supervisor_shares_a_corpus(tmp_path):
    out = tmp_path / "par"
    r = subprocess.run([PARALLEL, "--fuzzer", SLEUTH, "-t", target("json"), "-i", os.path.join(ROOT, "targets", "json", "seeds"),
                        "-o", str(out), "--workers", "2", "--time", "12"], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    s = json.loads((out / "summary.json").read_text())
    assert s["workers"] == 2 and s["workers_done"] == 2
    assert s["corpus_global"] > 0 and s["offered"] >= s["corpus_global"]
    assert s["edges_global"] >= s["edges_best_worker"]
    assert len(os.listdir(out / "corpus")) == s["corpus_global"]
    timeline = json.loads((out / "timeline.json").read_text())
    assert timeline and timeline[-1]["edges"] == s["edges_global"]
    # Each worker imported inputs found by the other.
    imported = [f for k in (0, 1) for f in os.listdir(out / f"worker-{k}" / "queue") if f.endswith("-sync")]
    assert imported


# ---------------------------------------------------------------- analysis (no build needed)

def test_bug_log_parsing(tmp_path):
    p = tmp_path / "bugs.log"
    p.write_text("R 3 1000500\nT 3 1001500\nR 3 1000400\ngarbage\nT 9 999000\n")
    reached, triggered = analyze.read_bug_log(str(p), 1000000)
    assert reached == {3: 0.4}
    assert triggered == {3: 1.5, 9: -1.0}
    assert analyze.read_bug_log(str(tmp_path / "missing"), 0) == ({}, {})


def test_summary_medians_count_misses_as_after_the_end():
    def run(rep, t17, cov):
        return {"target": "vm", "fuzzer": "sleuth", "rep": rep, "seconds": 60, "cores": 1, "coverage": cov,
                "reached": {17: 0.1}, "triggered": {} if t17 is None else {17: t17}, "detected": {}, "crash_files": 0}
    s = analyze.summarize([run(0, 10.0, [5, 9, 10]), run(1, 30.0, [5, 7, 12]), run(2, None, [5, 8, 11])])
    d = s["targets"]["vm"]["sleuth"]
    assert d["coverage_median"] == [5, 8, 11]
    assert d["coverage_min"] == [5, 7, 10] and d["coverage_max"] == [5, 9, 12]
    b = d["bugs"]["17"]
    assert b["triggered"]["runs"] == 2 and b["triggered"]["median_s"] == 30.0  # median of 10, 30, inf
    assert b["reached"]["median_s"] == 0.1
    assert b["detected"]["runs"] == 0 and b["detected"]["median_s"] is None
    s1 = analyze.summarize([run(0, 10.0, [1]), run(1, None, [1]), run(2, None, [1])])
    assert s1["targets"]["vm"]["sleuth"]["bugs"]["17"]["triggered"]["median_s"] is None  # found in 1 of 3


def test_campaign_dry_run(tmp_path):
    if not os.path.exists(SLEUTH):
        pytest.skip("run python build.py first")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "eval", "campaign.py"), "single", "--time", "5", "--reps", "1",
                        "--targets", "vm", "--out", str(tmp_path / "c"), "--dry-run"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lines = [x for x in r.stdout.strip().splitlines() if not x.startswith("all ")]
    assert len(lines) == 4
    assert any("-fork=1" in x and "-ignore_crashes=1" in x for x in lines)
    assert any("--blind" in x for x in lines) and any("--no-cmp" in x for x in lines)
    shutil.rmtree(tmp_path / "c", ignore_errors=True)
