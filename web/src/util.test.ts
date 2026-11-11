import { describe, expect, it } from "vitest";
import { type Campaign, bugIds, colorVar, escapeHtml, fmtBug, fmtDuration, fmtInt, median, nearest, ticks } from "./util";

describe("formatting", () => {
  it("formats durations", () => {
    expect(fmtDuration(0.42)).toBe("0.4 s");
    expect(fmtDuration(42)).toBe("42 s");
    expect(fmtDuration(75)).toBe("1 min 15 s");
    expect(fmtDuration(900)).toBe("15 min");
    expect(fmtDuration(3720)).toBe("1 h 2 min");
    expect(fmtDuration(null)).toBe("–");
    expect(fmtDuration(Infinity)).toBe("–");
  });
  it("formats integers and bug levels", () => {
    expect(fmtInt(1234567.4)).toBe("1,234,567");
    expect(fmtBug({ runs: 3, of: 3, median_s: 42, times: [40, 42, 50] })).toBe("3/3 · 42 s");
    expect(fmtBug({ runs: 1, of: 3, median_s: null, times: [null, 12, null] })).toBe("1/3");
    expect(fmtBug({ runs: 0, of: 3, median_s: null, times: [null, null, null] })).toBe("–");
    expect(fmtBug(undefined)).toBe("–");
  });
  it("escapes html", () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe("&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
  });
});

describe("numbers", () => {
  it("computes medians", () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(median([4, 1, 2, 3])).toBe(2.5);
    expect(median([])).toBeNaN();
  });
  it("makes nice ticks that cover the maximum", () => {
    expect(ticks(364)).toEqual([0, 100, 200, 300, 400]);
    expect(ticks(10, 5)).toEqual([0, 2, 4, 6, 8, 10]);
    expect(ticks(0)).toEqual([0]);
    const t = ticks(15.5, 4);
    expect(t[t.length - 1]).toBeGreaterThanOrEqual(15.5);
  });
  it("finds the nearest point", () => {
    expect(nearest([0, 1, 2, 3], 1.4)).toBe(1);
    expect(nearest([0, 1, 2, 3], 1.6)).toBe(2);
    expect(nearest([0, 1, 2, 3], -5)).toBe(0);
    expect(nearest([0, 1, 2, 3], 50)).toBe(3);
    expect(nearest([], 1)).toBe(-1);
  });
});

describe("campaign data", () => {
  it("keeps one colour per fuzzer, parallel runs included", () => {
    expect(colorVar("sleuth")).toBe("var(--series-1)");
    expect(colorVar("sleuth-par")).toBe("var(--series-1)");
    expect(colorVar("libfuzzer-par")).toBe(colorVar("libfuzzer"));
    expect(new Set(["sleuth", "sleuth-nocmp", "blind", "libfuzzer"].map(colorVar)).size).toBe(4);
  });
  it("lists the bug ids of a target in numeric order", () => {
    const lvl = { runs: 0, of: 1, median_s: null, times: [null] };
    const bug = { reached: lvl, triggered: lvl, detected: lvl };
    const r = { reps: 1, seconds: 60, cores: 1, coverage_median: [], coverage_min: [], coverage_max: [], final_edges: [], execs_per_s: [], unique_crashes: [], crash_files: [] };
    const c: Campaign = {
      step_s: 30,
      edges_total: { vm: 65 },
      targets: { vm: { sleuth: { ...r, bugs: { "20": bug, "17": bug } }, blind: { ...r, bugs: { "18": bug } } } },
    };
    expect(bugIds(c, "vm")).toEqual(["17", "18", "20"]);
    expect(bugIds(c, "png")).toEqual([]);
  });
});
