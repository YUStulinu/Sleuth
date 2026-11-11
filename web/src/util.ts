// Data shapes and pure helpers for the dashboard (tested in util.test.ts).

/** /api/summary from sleuth-parallel. */
export interface Summary {
  elapsed_s: number;
  workers: number;
  workers_done: number;
  execs: number;
  execs_per_s: number;
  edges_global: number;
  edges_total: number;
  edges_best_worker: number;
  corpus_global: number;
  offered: number;
  crashes_unique: number;
  timeouts: number;
}

export interface TimelinePoint {
  t: number;
  execs: number;
  edges: number;
  corpus: number;
  crashes: number;
}

export interface CrashGroup {
  kind: string;
  frames: string[];
  first_worker: number;
  file: string;
  size: number;
  found_s: number;
  hits: number;
  workers: number[];
}

/** One bug level (reached / triggered / detected) over the repetitions. */
export interface BugLevel {
  runs: number;
  of: number;
  median_s: number | null;
  times: (number | null)[];
}

export interface FuzzerResult {
  reps: number;
  seconds: number;
  cores: number;
  coverage_median: number[];
  coverage_min: number[];
  coverage_max: number[];
  final_edges: number[];
  execs_per_s: number[];
  unique_crashes: (number | null)[];
  crash_files: number[];
  bugs: Record<string, { reached: BugLevel; triggered: BugLevel; detected: BugLevel }>;
}

/** campaign.json, written by eval/analyze.py. */
export interface Campaign {
  step_s: number;
  edges_total: Record<string, number>;
  targets: Record<string, Record<string, FuzzerResult>>;
}

export const TARGETS = ["png", "xml", "der", "json", "vm"];
export const SINGLE = ["sleuth", "sleuth-nocmp", "blind", "libfuzzer"];
export const PARALLEL = ["sleuth-par", "libfuzzer-par"];

/** Colour token per fuzzer: a fuzzer keeps its colour everywhere (parallel = its single twin). */
export function colorVar(fuzzer: string): string {
  const base = fuzzer.replace(/-par$/, "");
  const slot = { sleuth: 1, "sleuth-nocmp": 2, blind: 3, libfuzzer: 4 }[base] ?? 1;
  return `var(--series-${slot})`;
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString("en-US");
}

/** 0.4 -> "0.4 s", 75 -> "1 min 15 s", 3700 -> "1 h 1 min". */
export function fmtDuration(s: number | null | undefined): string {
  if (s == null || !Number.isFinite(s)) return "–";
  if (s < 10) return `${s.toFixed(1)} s`;
  if (s < 60) return `${Math.round(s)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) {
    const rest = Math.round(s - m * 60);
    return rest ? `${m} min ${rest} s` : `${m} min`;
  }
  const h = Math.floor(m / 60);
  const rm = m - h * 60;
  return rm ? `${h} h ${rm} min` : `${h} h`;
}

export function median(xs: number[]): number {
  if (!xs.length) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/** "3/3 · 42 s" — runs that found the bug and the median time (when at least half did). */
export function fmtBug(level: BugLevel | undefined): string {
  if (!level || level.runs === 0) return "–";
  const t = level.median_s == null ? "" : ` · ${fmtDuration(level.median_s)}`;
  return `${level.runs}/${level.of}${t}`;
}

/** Bug ids of a target in a campaign, sorted numerically. */
export function bugIds(c: Campaign, target: string): string[] {
  const ids = new Set<string>();
  for (const r of Object.values(c.targets[target] ?? {})) for (const id of Object.keys(r.bugs)) ids.add(id);
  return [...ids].sort((a, b) => Number(a) - Number(b));
}

/** Nice axis ticks covering [0, max]. */
export function ticks(max: number, count = 5): number[] {
  if (!(max > 0)) return [0];
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((k) => k * mag).find((s) => s >= raw) ?? raw;
  const out: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) out.push(Math.round(v * 1e6) / 1e6);
  if (out[out.length - 1] < max) out.push(out[out.length - 1] + step);
  return out;
}

/** Index of the point nearest to x in a sorted array. */
export function nearest(xs: number[], x: number): number {
  if (!xs.length) return -1;
  let lo = 0;
  let hi = xs.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (xs[mid] <= x) lo = mid;
    else hi = mid;
  }
  return Math.abs(xs[lo] - x) <= Math.abs(xs[hi] - x) ? lo : hi;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
