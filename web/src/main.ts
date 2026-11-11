// Sleuth dashboard. Two views:
//   Live      a running sleuth-parallel campaign (polls /api/summary, /api/timeline, /api/crashes)
//   Results   the measured campaigns (campaign.json, written by eval/analyze.py)
import "./style.css";
import { lineChart } from "./chart";
import {
  type Campaign,
  type CrashGroup,
  type Summary,
  type TimelinePoint,
  PARALLEL,
  SINGLE,
  TARGETS,
  bugIds,
  colorVar,
  escapeHtml,
  fmtBug,
  fmtDuration,
  fmtInt,
  median,
} from "./util";

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;

let view: "live" | "results" = "results";
let campaign: Campaign | null = null;
let target = "png";
let group: "single" | "parallel" = "single";
let liveTimer: number | undefined;

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return (await r.json()) as T;
}

// ------------------------------------------------------------------ live

async function refreshLive(): Promise<void> {
  const root = $("#live");
  try {
    const [s, tl, crashes] = await Promise.all([
      getJson<Summary>("api/summary"),
      getJson<TimelinePoint[]>("api/timeline"),
      getJson<CrashGroup[]>("api/crashes"),
    ]);
    $("#status").textContent = s.workers_done === s.workers && s.workers > 0 ? "finished" : "running";
    root.querySelector(".stats")!.innerHTML = [
      ["elapsed", fmtDuration(s.elapsed_s)],
      ["workers", `${s.workers - s.workers_done} running / ${s.workers}`],
      ["executions", fmtInt(s.execs)],
      ["per second", fmtInt(s.execs_per_s)],
      ["edges (all workers)", `${fmtInt(s.edges_global)} / ${fmtInt(s.edges_total)}`],
      ["shared corpus", `${fmtInt(s.corpus_global)} of ${fmtInt(s.offered)} offered`],
      ["unique crashes", fmtInt(s.crashes_unique)],
      ["timeouts", fmtInt(s.timeouts)],
    ]
      .map(([k, v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`)
      .join("");
    const xs = tl.map((p) => p.t / 60);
    lineChart(
      root.querySelector<HTMLElement>("#live-cov")!,
      [{ name: "edges covered", color: colorVar("sleuth"), xs, ys: tl.map((p) => p.edges) }],
      { xLabel: "minutes", yLabel: "edges", formatX: (x) => `${x.toFixed(1)} min`, yMax: s.edges_total, yMaxLabel: "instrumented edges" },
    );
    root.querySelector("#live-crashes")!.innerHTML = crashTable(crashes);
  } catch {
    $("#status").textContent = "no live campaign";
    root.querySelector(".stats")!.innerHTML =
      `<div class="empty">No campaign is running here. Start one with <code>sleuth-parallel ... --port 8700</code> and open its address, or look at the measured results.</div>`;
    root.querySelector("#live-cov")!.innerHTML = "";
    root.querySelector("#live-crashes")!.innerHTML = "";
  }
}

function crashTable(crashes: CrashGroup[]): string {
  if (!crashes.length) return `<p class="muted">No crashes yet.</p>`;
  const rows = crashes
    .map(
      (c) => `<tr>
        <td>${fmtDuration(c.found_s)}</td>
        <td><b>${escapeHtml(c.kind)}</b></td>
        <td class="frames">${c.frames.map((f) => `<div>${escapeHtml(f)}</div>`).join("")}</td>
        <td class="num">${fmtInt(c.hits)}</td>
        <td class="num">${c.workers.length}</td>
        <td><code>w${c.first_worker}/${escapeHtml(c.file)}</code> (${c.size} B)</td>
      </tr>`,
    )
    .join("");
  return `<table><thead><tr><th>found after</th><th>kind</th><th>top frames</th><th class="num">hits</th><th class="num">workers</th><th>first input</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ------------------------------------------------------------------ results

function renderResults(): void {
  const root = $("#results");
  if (!campaign) {
    root.innerHTML = `<div class="empty">No campaign results (campaign.json) found. Run <code>python eval/analyze.py</code>.</div>`;
    return;
  }
  const c = campaign;
  const fuzzers = (group === "single" ? SINGLE : PARALLEL).filter((f) => c.targets[target]?.[f]);
  const tabs = TARGETS.filter((t) => c.targets[t])
    .map((t) => `<button class="tab ${t === target ? "on" : ""}" data-target="${t}">${t}</button>`)
    .join("");
  const groups = (["single", "parallel"] as const)
    .map((g) => `<button class="tab ${g === group ? "on" : ""}" data-group="${g}">${g === "single" ? "one core each" : "parallel"}</button>`)
    .join("");
  root.innerHTML = `
    <div class="toolbar"><div class="tabs">${tabs}</div><div class="tabs">${groups}</div></div>
    <section class="panel"><h2>Coverage over time — ${target}</h2>
      <p class="muted">Edges reached by the inputs each fuzzer saved, replayed through the same instrumented build. Line: median of the runs; band: min–max.</p>
      <div id="res-cov"></div></section>
    <section class="panel"><h2>Planted bugs — ${target}</h2>
      <p class="muted">Runs that triggered / detected each bug, and the median time (shown when at least half of the runs found it). See targets/BUGS.md.</p>
      <div id="res-bugs"></div></section>
    <section class="panel"><h2>Runs</h2><div id="res-runs"></div></section>`;
  root.querySelectorAll<HTMLButtonElement>("[data-target]").forEach((b) =>
    b.addEventListener("click", () => {
      target = b.dataset.target!;
      renderResults();
    }),
  );
  root.querySelectorAll<HTMLButtonElement>("[data-group]").forEach((b) =>
    b.addEventListener("click", () => {
      group = b.dataset.group as "single" | "parallel";
      renderResults();
    }),
  );
  if (!fuzzers.length) {
    $("#res-cov").innerHTML = `<p class="muted">No ${group} runs for ${target}.</p>`;
    return;
  }
  const step = c.step_s / 60;
  lineChart(
    $("#res-cov"),
    fuzzers.map((f) => {
      const r = c.targets[target][f];
      return { name: f, color: colorVar(f), xs: r.coverage_median.map((_, i) => i * step), ys: r.coverage_median, lo: r.coverage_min, hi: r.coverage_max };
    }),
    { xLabel: "minutes", yLabel: "edges covered", formatX: (x) => `${x.toFixed(1)} min`, yMax: c.edges_total[target], yMaxLabel: "instrumented edges", height: 300 },
  );
  const ids = bugIds(c, target);
  const head = fuzzers.map((f) => `<th colspan="2"><i class="key" style="background:${colorVar(f)}"></i>${f}</th>`).join("");
  const sub = fuzzers.map(() => `<th>triggered</th><th>detected</th>`).join("");
  const body = ids
    .map((id) => {
      const cells = fuzzers
        .map((f) => {
          const b = c.targets[target][f].bugs[id];
          return `<td class="num ${b?.triggered.runs ? "" : "miss"}">${fmtBug(b?.triggered)}</td><td class="num ${b?.detected.runs ? "" : "miss"}">${fmtBug(b?.detected)}</td>`;
        })
        .join("");
      return `<tr><td>bug ${id}</td>${cells}</tr>`;
    })
    .join("");
  $("#res-bugs").innerHTML = `<div class="scroll"><table><thead><tr><th></th>${head}</tr><tr><th></th>${sub}</tr></thead><tbody>${body}</tbody></table></div>`;
  const runs = fuzzers
    .map((f) => {
      const r = c.targets[target][f];
      const crashes = r.unique_crashes.filter((x): x is number => x != null);
      return `<tr><td><i class="key" style="background:${colorVar(f)}"></i>${f}</td><td class="num">${r.reps}</td><td class="num">${fmtDuration(r.seconds)}</td><td class="num">${r.cores}</td>
        <td class="num">${fmtInt(median(r.final_edges))}</td><td class="num">${fmtInt(median(r.execs_per_s))}</td>
        <td class="num">${crashes.length ? fmtInt(median(crashes)) : "–"}</td><td class="num">${fmtInt(median(r.crash_files))}</td></tr>`;
    })
    .join("");
  $("#res-runs").innerHTML = `<div class="scroll"><table><thead><tr><th>fuzzer</th><th class="num">runs</th><th class="num">length</th><th class="num">cores</th><th class="num">final edges (median)</th><th class="num">execs/s (median)</th><th class="num">unique crash signatures</th><th class="num">crash files saved</th></tr></thead><tbody>${runs}</tbody></table></div>`;
}

// ------------------------------------------------------------------ shell

function show(v: "live" | "results"): void {
  view = v;
  $("#live").hidden = v !== "live";
  $("#results").hidden = v !== "results";
  document.querySelectorAll<HTMLButtonElement>("nav button").forEach((b) => b.classList.toggle("on", b.dataset.view === v));
  window.clearInterval(liveTimer);
  if (v === "live") {
    void refreshLive();
    liveTimer = window.setInterval(() => void refreshLive(), 2000);
  } else {
    renderResults();
  }
}

async function start(): Promise<void> {
  document.querySelectorAll<HTMLButtonElement>("nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view as "live" | "results")));
  try {
    campaign = await getJson<Campaign>("campaign.json");
  } catch {
    campaign = null;
  }
  // Open on the live view when a campaign is being served from here.
  let live = false;
  try {
    await getJson<Summary>("api/summary");
    live = true;
  } catch {
    live = false;
  }
  show(live ? "live" : "results");
  let last = window.innerWidth;
  window.addEventListener("resize", () => {
    if (Math.abs(window.innerWidth - last) < 40) return;
    last = window.innerWidth;
    if (view === "results") renderResults();
    else void refreshLive();
  });
}

void start();
