// A small SVG line chart: one line per series, an optional min-max band, a recessive grid, a
// legend for two or more series, an optional dashed reference line, and a crosshair tooltip.
import { escapeHtml, nearest, ticks } from "./util";

export interface Series {
  name: string;
  color: string; // a CSS colour or var(--...)
  xs: number[];
  ys: number[];
  lo?: number[];
  hi?: number[];
}

export interface ChartOptions {
  xLabel: string;
  yLabel: string;
  height?: number;
  formatX?: (x: number) => string;
  formatY?: (y: number) => string;
  yMax?: number; // e.g. the total number of edges, drawn as a dashed reference line
  yMaxLabel?: string;
}

const NS = "http://www.w3.org/2000/svg";

function el<K extends keyof SVGElementTagNameMap>(name: K, attrs: Record<string, string | number>, parent?: Element): SVGElementTagNameMap[K] {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  parent?.appendChild(e);
  return e;
}

export function lineChart(host: HTMLElement, series: Series[], o: ChartOptions): void {
  host.innerHTML = "";
  host.classList.add("chart");
  const width = Math.max(280, host.clientWidth || 600);
  const height = o.height ?? 260;
  const m = { l: 52, r: 16, t: 12, b: 36 };
  const w = width - m.l - m.r;
  const h = height - m.t - m.b;
  const fx = o.formatX ?? ((x) => String(x));
  const fy = o.formatY ?? ((y) => String(Math.round(y)));
  const xMax = Math.max(1, ...series.flatMap((s) => s.xs));
  const yTop = Math.max(1, o.yMax ?? 0, ...series.flatMap((s) => [...s.ys, ...(s.hi ?? [])]));
  const yt = ticks(yTop, 5);
  const yMaxAxis = yt[yt.length - 1];
  const X = (x: number) => m.l + (x / xMax) * w;
  const Y = (y: number) => m.t + h - (y / yMaxAxis) * h;

  const svg = el("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${o.yLabel} by ${o.xLabel}` }, host);
  for (const v of yt) {
    el("line", { x1: m.l, x2: m.l + w, y1: Y(v), y2: Y(v), class: "grid" }, svg);
    const t = el("text", { x: m.l - 6, y: Y(v) + 4, class: "tick", "text-anchor": "end" }, svg);
    t.textContent = fy(v);
  }
  for (const v of ticks(xMax, Math.max(2, Math.floor(w / 90)))) {
    if (v > xMax) continue;
    const t = el("text", { x: X(v), y: m.t + h + 16, class: "tick", "text-anchor": "middle" }, svg);
    t.textContent = fx(v);
  }
  el("line", { x1: m.l, x2: m.l + w, y1: m.t + h, y2: m.t + h, class: "axis" }, svg);
  const xl = el("text", { x: m.l + w / 2, y: height - 4, class: "label", "text-anchor": "middle" }, svg);
  xl.textContent = o.xLabel;
  const yl = el("text", { x: 12, y: m.t + h / 2, class: "label", "text-anchor": "middle", transform: `rotate(-90 12 ${m.t + h / 2})` }, svg);
  yl.textContent = o.yLabel;
  if (o.yMax) {
    el("line", { x1: m.l, x2: m.l + w, y1: Y(o.yMax), y2: Y(o.yMax), class: "ref" }, svg);
    if (o.yMaxLabel) {
      const t = el("text", { x: m.l + w - 4, y: Y(o.yMax) - 5, class: "tick", "text-anchor": "end" }, svg);
      t.textContent = o.yMaxLabel;
    }
  }
  for (const s of series) {
    if (s.lo && s.hi && s.xs.length) {
      const top = s.xs.map((x, i) => `${X(x)},${Y(s.hi![i])}`);
      const bottom = s.xs.map((x, i) => `${X(x)},${Y(s.lo![i])}`).reverse();
      el("polygon", { points: [...top, ...bottom].join(" "), fill: s.color, class: "band" }, svg);
    }
  }
  for (const s of series) {
    if (!s.xs.length) continue;
    el("polyline", { points: s.xs.map((x, i) => `${X(x)},${Y(s.ys[i])}`).join(" "), stroke: s.color, class: "line" }, svg);
  }

  // Crosshair + tooltip.
  const cross = el("line", { y1: m.t, y2: m.t + h, class: "cross", visibility: "hidden" }, svg);
  const dots = series.map((s) => el("circle", { r: 4, fill: s.color, class: "dot", visibility: "hidden" }, svg));
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  host.appendChild(tip);
  const hit = el("rect", { x: m.l, y: m.t, width: w, height: h, fill: "transparent" }, svg);
  const xsAll = series.find((s) => s.xs.length)?.xs ?? [];
  hit.addEventListener("pointermove", (ev) => {
    const box = svg.getBoundingClientRect();
    const x = ((ev.clientX - box.left - m.l) / w) * xMax;
    const i = nearest(xsAll, x);
    if (i < 0) return;
    const px = X(xsAll[i]);
    cross.setAttribute("x1", String(px));
    cross.setAttribute("x2", String(px));
    cross.setAttribute("visibility", "visible");
    const rows = series
      .map((s, k) => {
        const y = s.ys[i];
        if (y == null) {
          dots[k].setAttribute("visibility", "hidden");
          return "";
        }
        dots[k].setAttribute("cx", String(px));
        dots[k].setAttribute("cy", String(Y(y)));
        dots[k].setAttribute("visibility", "visible");
        const range = s.lo && s.hi ? ` <span class="muted">(${fy(s.lo[i])}–${fy(s.hi[i])})</span>` : "";
        return `<div><i style="background:${s.color}"></i>${escapeHtml(s.name)} <b>${fy(y)}</b>${range}</div>`;
      })
      .join("");
    tip.innerHTML = `<div class="muted">${escapeHtml(fx(xsAll[i]))}</div>${rows}`;
    tip.hidden = false;
    const left = Math.min(px + 12, width - tip.offsetWidth - 4);
    tip.style.left = `${Math.max(4, left)}px`;
    tip.style.top = `${m.t + 4}px`;
  });
  hit.addEventListener("pointerleave", () => {
    tip.hidden = true;
    cross.setAttribute("visibility", "hidden");
    dots.forEach((d) => d.setAttribute("visibility", "hidden"));
  });

  if (series.length >= 2) {
    const legend = document.createElement("div");
    legend.className = "legend";
    legend.innerHTML = series.map((s) => `<span><i style="background:${s.color}"></i>${escapeHtml(s.name)}</span>`).join("");
    host.prepend(legend);
  }
}
