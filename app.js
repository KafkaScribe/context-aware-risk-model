"use strict";

/* =================================================================
 *  CONTEXT-AWARE RISK SCORING MODEL  — tweak everything here
 * =================================================================
 *
 *  Context-Aware Risk Score (0–10) =
 *      10 * ( w1*severity + w2*exploit + w3*criticality + w4*exposure )
 *
 *    severity    = CVSS base score / 10     (0–1)  technical severity
 *    exploit     = EPSS-style probability    (0–1)  real-world exploit activity
 *    criticality = institutional asset value (0–1)  how much we depend on it
 *    exposure    = network reachability      (0–1)  how reachable it is
 *
 *    w1..w4 are AHP-derived weights that SUM TO 1.
 *
 *  To change the model: edit DEFAULT_WEIGHTS, contextAwareRisk(), the
 *  RISK_BANDS thresholds, or the VULNS / PRESETS example data below.
 * ================================================================= */

// --- Default (AHP-derived) weights -----------------------------------------
const DEFAULT_WEIGHTS = { w1: 0.30, w2: 0.30, w3: 0.25, w4: 0.15 };

// --- Default inputs (the OpenSSL-in-library scenario) ----------------------
const DEFAULT_INPUTS = { cvss: 9.8, epss: 0.05, crit: 0.20, exp: 0.30 };

/**
 * Core scoring function. Returns a rich object so every consumer
 * (headline number, breakdown table, stacked bar, narration) reads
 * from ONE source of truth — nothing is recomputed ad-hoc.
 *
 * @param {{cvss:number, epss:number, crit:number, exp:number}} v
 * @param {{w1:number, w2:number, w3:number, w4:number}} w  (auto-normalised)
 */
function contextAwareRisk(v, w) {
  const severity = v.cvss / 10;                      // CVSS (0–10) → 0–1
  const sum = w.w1 + w.w2 + w.w3 + w.w4 || 1;        // guard all-zero
  const nw = { w1: w.w1 / sum, w2: w.w2 / sum, w3: w.w3 / sum, w4: w.w4 / sum };

  // Per-component contribution to the final 0–10 score.
  // contribution = weight * input * 10
  const parts = {
    sev:  { input: severity, weight: nw.w1, contribution: nw.w1 * severity * 10 },
    exp:  { input: v.epss,   weight: nw.w2, contribution: nw.w2 * v.epss   * 10 },
    crit: { input: v.crit,   weight: nw.w3, contribution: nw.w3 * v.crit   * 10 },
    expo: { input: v.exp,    weight: nw.w4, contribution: nw.w4 * v.exp    * 10 },
  };

  const score = parts.sev.contribution + parts.exp.contribution
              + parts.crit.contribution + parts.expo.contribution;

  return { score, parts, nw, severity };
}

// CVSS-only "score" is simply the base score itself (already 0–10).
const cvssOnly = (v) => v.cvss;

/* =================================================================
 *  RISK BANDS — plain-language verdict from the 0–10 score
 * ================================================================= */
const RISK_BANDS = [
  { min: 7.5, key: "critical", label: "CRITICAL", cls: "risk-critical",
    desc: "Drop everything — high real-world risk to a valuable, reachable asset." },
  { min: 5.0, key: "high", label: "HIGH", cls: "risk-high",
    desc: "Prioritise this cycle — context makes it a genuine threat, not just a loud one." },
  { min: 2.5, key: "medium", label: "MEDIUM", cls: "risk-medium",
    desc: "Moderate priority — fix during the normal patch cycle, monitor for change." },
  { min: 0.0, key: "low", label: "LOW", cls: "risk-low",
    desc: "Low priority — little real exposure or impact; safe to schedule routinely." },
];
const bandFor = (score) => RISK_BANDS.find((b) => score >= b.min);

/* =================================================================
 *  COMPONENT METADATA (labels + colours, shared everywhere)
 * ================================================================= */
const COMPONENTS = [
  { key: "sev",  name: "Severity",    color: "var(--c-sev)"  },
  { key: "exp",  name: "Exploit",     color: "var(--c-exp)"  },
  { key: "crit", name: "Criticality", color: "var(--c-crit)" },
  { key: "expo", name: "Exposure",    color: "var(--c-expo)" },
];

/* =================================================================
 *  PRESET SCENARIOS (Section 02) — one-click stories
 * ================================================================= */
const PRESETS = [
  { id: "openssl", label: "OpenSSL · library catalogue", cvss: 9.8, epss: 0.05, crit: 0.20, exp: 0.30 },
  { id: "sqli",    label: "SQLi · student records",      cvss: 7.5, epss: 0.60, crit: 0.95, exp: 0.90 },
  { id: "xss",     label: "XSS · admissions portal",     cvss: 6.1, epss: 0.70, crit: 0.60, exp: 0.95 },
  { id: "dos",     label: "DoS · internal print server", cvss: 5.3, epss: 0.02, crit: 0.15, exp: 0.10 },
];

/* =================================================================
 *  EXAMPLE VULNERABILITY SET (Section 03) — exact thesis values
 * ================================================================= */
const VULNS = [
  { name: "OpenSSL flaw in library catalogue",      short: "OpenSSL · library catalogue", cvss: 9.8, epss: 0.05, crit: 0.20, exp: 0.30 },
  { name: "SQL injection in student records (SIS)",  short: "SQLi · student records",      cvss: 7.5, epss: 0.60, crit: 0.95, exp: 0.90 },
  { name: "RCE in SSO authentication gateway",       short: "RCE · SSO gateway",           cvss: 8.8, epss: 0.40, crit: 0.90, exp: 0.85 },
  { name: "Privilege escalation on lab workstation", short: "PrivEsc · lab workstation",   cvss: 7.8, epss: 0.10, crit: 0.30, exp: 0.20 },
  { name: "XSS in public admissions portal",         short: "XSS · admissions portal",     cvss: 6.1, epss: 0.70, crit: 0.60, exp: 0.95 },
  { name: "DoS in internal print server",            short: "DoS · print server",          cvss: 5.3, epss: 0.02, crit: 0.15, exp: 0.10 },
];

/* =================================================================
 *  CAPABILITY MATRIX (Section 04)   v=full · p=partial · x=absent
 * ================================================================= */
const MATRIX = [
  { sys: "CVSS",     row: ["v", "x", "x", "x", "x"], mine: false },
  { sys: "EPSS",     row: ["x", "v", "x", "p", "x"], mine: false },
  { sys: "SSVC",     row: ["p", "p", "p", "v", "x"], mine: false },
  { sys: "NIST CSF", row: ["x", "x", "p", "p", "v"], mine: false },
  { sys: "My model", row: ["v", "v", "v", "v", "v"], mine: true  },
];

/* =================================================================
 *  DOM helpers + refs
 * ================================================================= */
const $ = (id) => document.getElementById(id);
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const inputs  = { cvss: $("cvss"), epss: $("epss"), crit: $("crit"), exp: $("exp") };
const weights = { w1: $("w1"), w2: $("w2"), w3: $("w3"), w4: $("w4") };

/* =================================================================
 *  WEIGHT NORMALISATION
 *  Sliders hold raw preferences; everything renders/scores with the
 *  normalised set so w1+w2+w3+w4 = 1 on every change.
 * ================================================================= */
function normalisedWeights() {
  const raw = {
    w1: parseFloat(weights.w1.value), w2: parseFloat(weights.w2.value),
    w3: parseFloat(weights.w3.value), w4: parseFloat(weights.w4.value),
  };
  const sum = raw.w1 + raw.w2 + raw.w3 + raw.w4;
  if (sum === 0) return { w1: 0.25, w2: 0.25, w3: 0.25, w4: 0.25 };
  return { w1: raw.w1 / sum, w2: raw.w2 / sum, w3: raw.w3 / sum, w4: raw.w4 / sum };
}

/* =================================================================
 *  PLAIN-ENGLISH NARRATION
 * ================================================================= */
function buildExplanation(v, cvss, ctx) {
  const delta = ctx - cvss;
  const hi = (x) => x >= 0.66, lo = (x) => x <= 0.34;
  const sevWord = v.cvss >= 7 ? "high-severity" : v.cvss >= 4 ? "medium-severity" : "low-severity";
  const critWord = hi(v.crit) ? "high-criticality" : lo(v.crit) ? "low-criticality" : "moderate-criticality";
  const expoWord = hi(v.exp)  ? "high-exposure"    : lo(v.exp)  ? "low-exposure"    : "moderate-exposure";
  const exploitWord = hi(v.epss) ? "actively exploited" : lo(v.epss) ? "rarely exploited" : "occasionally exploited";
  const ctxBits = `${critWord}, ${expoWord}`;

  if (delta <= -1.0) {
    return `This is a ${sevWord} flaw, but it sits on a ${ctxBits} asset and is ${exploitWord} — so the real risk (${ctx.toFixed(1)}) lands well below what CVSS (${cvss.toFixed(1)}) would have you believe. Severity is loud; risk is quiet here.`;
  }
  if (delta >= 1.0) {
    return `CVSS rates this only ${cvss.toFixed(1)}, but on a ${ctxBits} asset that is ${exploitWord}, context-aware risk climbs to ${ctx.toFixed(1)}. It deserves more urgency than its severity score alone suggests.`;
  }
  return `Severity and context broadly agree here: a ${sevWord}, ${exploitWord} issue on a ${ctxBits} asset gives a context-aware risk of ${ctx.toFixed(1)}, close to its CVSS of ${cvss.toFixed(1)}.`;
}

/* =================================================================
 *  RENDER · interactive section
 * ================================================================= */
function renderInteractive() {
  const v = {
    cvss: parseFloat(inputs.cvss.value),
    epss: parseFloat(inputs.epss.value),
    crit: parseFloat(inputs.crit.value),
    exp:  parseFloat(inputs.exp.value),
  };
  const w = normalisedWeights();
  const result = contextAwareRisk(v, w);
  const cvss = cvssOnly(v);
  const ctx = result.score;

  // --- echo inputs ---
  $("cvss-val").textContent = v.cvss.toFixed(1);
  $("epss-val").textContent = v.epss.toFixed(2);
  $("crit-val").textContent = v.crit.toFixed(2);
  $("exp-val").textContent  = v.exp.toFixed(2);

  // --- echo normalised weights ---
  $("w1-val").textContent = result.nw.w1.toFixed(3);
  $("w2-val").textContent = result.nw.w2.toFixed(3);
  $("w3-val").textContent = result.nw.w3.toFixed(3);
  $("w4-val").textContent = result.nw.w4.toFixed(3);

  // --- headline numbers ---
  $("cvss-score").textContent = cvss.toFixed(1);
  $("ctx-score").textContent  = ctx.toFixed(2);

  // --- risk band verdict ---
  const band = bandFor(ctx);
  const bandEl = $("risk-band");
  bandEl.textContent = band.label;
  bandEl.className = `risk-band ${band.cls} mt-2`;
  $("risk-band-desc").textContent = band.desc;

  // --- delta vs CVSS ---
  const delta = ctx - cvss;
  const deltaEl = $("delta");
  deltaEl.textContent = (delta >= 0 ? "+" : "−") + Math.abs(delta).toFixed(2);
  deltaEl.style.color = delta < -0.05 ? "var(--green)" : delta > 0.05 ? "#b45309" : "var(--navy)";
  $("delta-desc").textContent = delta < -0.05
    ? "Context-aware risk is LOWER than CVSS suggests."
    : delta > 0.05
      ? "Context-aware risk is HIGHER than CVSS suggests."
      : "Context-aware risk roughly matches CVSS.";

  renderBreakdown(result, ctx);
  renderStackBar(result, ctx);
  $("explain").textContent = buildExplanation(v, cvss, ctx);
}

/* --- calculation breakdown table --- */
function renderBreakdown(result, ctx) {
  const p = result.parts;
  const set = (id, val) => { $(id).textContent = val; };

  set("bd-sev-in",  p.sev.input.toFixed(2));
  set("bd-sev-w",   p.sev.weight.toFixed(3));
  set("bd-sev-c",   p.sev.contribution.toFixed(3));
  set("bd-exp-in",  p.exp.input.toFixed(2));
  set("bd-exp-w",   p.exp.weight.toFixed(3));
  set("bd-exp-c",   p.exp.contribution.toFixed(3));
  set("bd-crit-in", p.crit.input.toFixed(2));
  set("bd-crit-w",  p.crit.weight.toFixed(3));
  set("bd-crit-c",  p.crit.contribution.toFixed(3));
  set("bd-expo-in", p.expo.input.toFixed(2));
  set("bd-expo-w",  p.expo.weight.toFixed(3));
  set("bd-expo-c",  p.expo.contribution.toFixed(3));

  set("bd-sum",   (ctx / 10).toFixed(3));
  set("bd-final", ctx.toFixed(2));

  // highlight the dominant driver row
  const driver = COMPONENTS
    .map((c) => ({ key: c.key, c: p[c.key].contribution }))
    .sort((a, b) => b.c - a.c)[0];
  document.querySelectorAll(".bd-row").forEach((row) => {
    row.classList.toggle("is-driver", row.dataset.key === driver.key && driver.c > 0);
  });
}

/* --- stacked contribution bar + legend --- */
function renderStackBar(result, ctx) {
  const p = result.parts;
  const pct = (c) => `${(c / 10) * 100}%`;

  document.querySelector(".seg-sev").style.width  = pct(p.sev.contribution);
  document.querySelector(".seg-exp").style.width  = pct(p.exp.contribution);
  document.querySelector(".seg-crit").style.width = pct(p.crit.contribution);
  document.querySelector(".seg-expo").style.width = pct(p.expo.contribution);
  $("stack-rest").style.width = pct(10 - ctx);

  // only label a segment if it's wide enough to read
  const labelSeg = (sel, c) => {
    const span = document.querySelector(`${sel} span`);
    span.textContent = (c / 10) * 100 >= 9 ? c.toFixed(1) : "";
  };
  labelSeg(".seg-sev",  p.sev.contribution);
  labelSeg(".seg-exp",  p.exp.contribution);
  labelSeg(".seg-crit", p.crit.contribution);
  labelSeg(".seg-expo", p.expo.contribution);

  // legend with each component's share of the score
  const total = ctx || 1;
  $("stack-legend").innerHTML = COMPONENTS.map((c) => {
    const contribution = p[c.key].contribution;
    const share = Math.round((contribution / total) * 100);
    return `<li>
      <span class="swatch" style="background:${c.color}"></span>
      ${c.name}
      <span class="lv">${contribution.toFixed(1)} · ${share}%</span>
    </li>`;
  }).join("");
}

/* =================================================================
 *  RENDER · preset chips
 * ================================================================= */
function renderPresets() {
  $("presets").innerHTML = PRESETS.map((p) =>
    `<button type="button" class="preset-chip" data-id="${p.id}" aria-pressed="false">${p.label}</button>`
  ).join("");

  $("presets").addEventListener("click", (e) => {
    const btn = e.target.closest(".preset-chip");
    if (!btn) return;
    const preset = PRESETS.find((p) => p.id === btn.dataset.id);
    if (!preset) return;
    inputs.cvss.value = preset.cvss;
    inputs.epss.value = preset.epss;
    inputs.crit.value = preset.crit;
    inputs.exp.value  = preset.exp;
    syncPresetPressed();
    renderInteractive();
  });
}

// reflect which preset (if any) matches the current inputs
function syncPresetPressed() {
  const cur = {
    cvss: parseFloat(inputs.cvss.value), epss: parseFloat(inputs.epss.value),
    crit: parseFloat(inputs.crit.value), exp: parseFloat(inputs.exp.value),
  };
  document.querySelectorAll(".preset-chip").forEach((btn) => {
    const p = PRESETS.find((x) => x.id === btn.dataset.id);
    const match = p && p.cvss === cur.cvss && p.epss === cur.epss && p.crit === cur.crit && p.exp === cur.exp;
    btn.setAttribute("aria-pressed", match ? "true" : "false");
  });
}

/* =================================================================
 *  RENDER · prioritisation table (Section 03)
 *  Uses DEFAULT weights so the example matches the thesis figures.
 * ================================================================= */
function scoredVulns() {
  return VULNS.map((x) => ({
    ...x,
    risk: contextAwareRisk(x, { w1: DEFAULT_WEIGHTS.w1, w2: DEFAULT_WEIGHTS.w2, w3: DEFAULT_WEIGHTS.w3, w4: DEFAULT_WEIGHTS.w4 }).score,
  }));
}

function renderVulnTable() {
  const scored = scoredVulns().sort((a, b) => b.risk - a.risk); // show in risk order
  $("vuln-table").innerHTML = scored.map((x) => `
    <tr>
      <td class="name">${x.name}</td>
      <td>${x.cvss.toFixed(1)}</td>
      <td>${x.epss.toFixed(2)}</td>
      <td>${x.crit.toFixed(2)}</td>
      <td>${x.exp.toFixed(2)}</td>
      <td class="risk">${x.risk.toFixed(2)}</td>
    </tr>`).join("");
}

/* =================================================================
 *  RENDER · slope chart (Section 03)
 *  Draws CVSS rank → context rank as connecting lines (SVG).
 * ================================================================= */
function renderSlopeChart() {
  const scored = scoredVulns();
  const n = scored.length;

  const byCvss = [...scored].sort((a, b) => b.cvss - a.cvss);
  const byCtx  = [...scored].sort((a, b) => b.risk - a.risk);
  const cvssRank = new Map(byCvss.map((x, i) => [x.name, i + 1]));
  const ctxRank  = new Map(byCtx.map((x, i) => [x.name, i + 1]));

  // SVG geometry
  const W = 760, rowH = 46, padTop = 40, padBottom = 16;
  const H = padTop + rowH * n + padBottom;
  const xL = 250, xR = W - 250; // left/right column x-positions for the rank nodes
  const y = (rank) => padTop + (rank - 1) * rowH + rowH / 2;

  const colorFor = (move) => move > 0 ? "var(--green)" : move < 0 ? "var(--amber)" : "rgba(31,56,100,0.35)";
  const arrow = (move) => move > 0 ? `▲${move}` : move < 0 ? `▼${-move}` : "—";

  let lines = "";
  scored.forEach((x) => {
    const r1 = cvssRank.get(x.name), r2 = ctxRank.get(x.name);
    const move = r1 - r2; // +ve = moved up
    const col = colorFor(move);
    const y1 = y(r1), y2 = y(r2);
    lines += `
      <g class="slope-row">
        <path class="slope-line" d="M ${xL} ${y1} C ${(xL + xR) / 2} ${y1}, ${(xL + xR) / 2} ${y2}, ${xR} ${y2}" stroke="${col}"/>
        <circle class="slope-dot" cx="${xL}" cy="${y1}" r="4.5" fill="${col}"/>
        <circle class="slope-dot" cx="${xR}" cy="${y2}" r="4.5" fill="${col}"/>
        <text class="slope-label" x="${xL - 12}" y="${y1}" dominant-baseline="middle" text-anchor="end">${x.short}</text>
        <text class="slope-rank" x="${xR + 14}" y="${y2}" dominant-baseline="middle" text-anchor="start" fill="${col}">${arrow(move)} · ${x.risk.toFixed(2)}</text>
      </g>`;
  });

  // rank guides (1..n) down each column
  let guides = "";
  for (let r = 1; r <= n; r++) {
    guides += `
      <text class="slope-rank" x="${xL - 2}" y="${y(r)}" dominant-baseline="middle" text-anchor="end" fill="rgba(31,56,100,0.3)" dx="-92">${r}</text>
      <text class="slope-rank" x="${xR + 2}" y="${y(r)}" dominant-baseline="middle" text-anchor="start" fill="rgba(31,56,100,0.3)" dx="92">${r}</text>`;
  }

  $("slope-chart").innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Rank movement from CVSS to context-aware risk">
      <text class="slope-col-h" x="${xL}" y="20" text-anchor="end">Ranked by CVSS</text>
      <text class="slope-col-h" x="${xR}" y="20" text-anchor="start">Ranked by context risk</text>
      <line x1="${xL}" y1="32" x2="${xL}" y2="${H - padBottom}" stroke="rgba(31,56,100,0.1)"/>
      <line x1="${xR}" y1="32" x2="${xR}" y2="${H - padBottom}" stroke="rgba(31,56,100,0.1)"/>
      ${lines}
    </svg>`;
}

/* =================================================================
 *  RENDER · capability matrix (Section 04)
 * ================================================================= */
function renderMatrix() {
  const mark = (m) =>
    m === "v" ? `<span class="text-green font-600" aria-label="full">✓</span>` :
    m === "p" ? `<span class="text-amber font-600" aria-label="partial">◐</span>` :
                `<span class="text-navy/30" aria-label="absent">—</span>`;

  $("matrix-body").innerHTML = MATRIX.map((r) => `
    <tr class="${r.mine ? "mine" : ""}">
      <td class="sys">${r.sys}${r.mine ? '<span class="tag">proposed</span>' : ""}</td>
      ${r.row.map((m) => `<td>${mark(m)}</td>`).join("")}
    </tr>`).join("");
}

/* =================================================================
 *  WIRING
 * ================================================================= */
function onAnyInput() { renderInteractive(); syncPresetPressed(); }

Object.values(inputs).forEach((el)  => el.addEventListener("input", onAnyInput));
Object.values(weights).forEach((el) => el.addEventListener("input", onAnyInput));

$("reset").addEventListener("click", () => {
  inputs.cvss.value = DEFAULT_INPUTS.cvss;
  inputs.epss.value = DEFAULT_INPUTS.epss;
  inputs.crit.value = DEFAULT_INPUTS.crit;
  inputs.exp.value  = DEFAULT_INPUTS.exp;
  weights.w1.value = DEFAULT_WEIGHTS.w1;
  weights.w2.value = DEFAULT_WEIGHTS.w2;
  weights.w3.value = DEFAULT_WEIGHTS.w3;
  weights.w4.value = DEFAULT_WEIGHTS.w4;
  onAnyInput();
});

/* =================================================================
 *  PREFILL FROM ASSESSMENT PAGE
 *  assessment.html links here as  index.html?crit=0.xx&exp=0.yy#try
 *  so a measured asset profile flows straight into the calculator.
 * ================================================================= */
function applyUrlParams() {
  const p = new URLSearchParams(window.location.search);
  const clamp01 = (v) => Math.max(0, Math.min(1, v));
  if (p.has("crit")) {
    const c = parseFloat(p.get("crit"));
    if (!Number.isNaN(c)) inputs.crit.value = clamp01(c);
  }
  if (p.has("exp")) {
    const x = parseFloat(p.get("exp"));
    if (!Number.isNaN(x)) inputs.exp.value = clamp01(x);
  }
}

/* =================================================================
 *  INIT
 * ================================================================= */
applyUrlParams();
renderPresets();
renderInteractive();
syncPresetPressed();
renderVulnTable();
renderSlopeChart();
renderMatrix();
