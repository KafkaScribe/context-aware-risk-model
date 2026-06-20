"use strict";

/* =================================================================
 *  INSTITUTIONAL SELF-ASSESSMENT
 *  Implements the thesis maturity framework + the criticality and
 *  exposure questionnaires that feed the context-aware risk model.
 *
 *  Three outputs, all computed live in the browser:
 *    1. Maturity  — per-dimension and overall level on a 0–5 scale
 *    2. Criticality (c) — 0–1, an input to the risk score
 *    3. Exposure (x)    — 0–1, an input to the risk score
 *
 *  Everything below is data-driven — edit the arrays to match the
 *  final, expert-validated version of your thesis instrument.
 * ================================================================= */

/* -----------------------------------------------------------------
 *  MATURITY SCALE (thesis §4.3) — six cumulative levels, 0–5
 * ----------------------------------------------------------------- */
const MATURITY_LEVELS = [
  { n: 0, label: "Incomplete",              desc: "Ad hoc and unknown; the practice may or may not happen." },
  { n: 1, label: "Initial",                 desc: "Reactive and unpredictable; done but inconsistent." },
  { n: 2, label: "Managed",                 desc: "Planned, performed, and controlled." },
  { n: 3, label: "Defined",                 desc: "Standardised institution-wide; proactive." },
  { n: 4, label: "Quantitatively Managed",  desc: "Measured and data-driven, with metrics." },
  { n: 5, label: "Optimising",              desc: "Continuous improvement; threat-informed." },
];

/* -----------------------------------------------------------------
 *  MATURITY DIMENSIONS (thesis §4.2) — 7 dimensions and their
 *  indicators, tagged with an (illustrative) NIST function group.
 * ----------------------------------------------------------------- */
const DIMENSIONS = [
  {
    id: "gov", name: "Governance & Risk Management", fn: "Identify",
    indicators: [
      "Security policy approved by leadership",
      "Defined security roles & responsibilities",
      "Maintained risk register / risk process",
      "Dedicated security budget",
      "Vendor / third-party risk management",
    ],
  },
  {
    id: "iam", name: "Identity & Access Management", fn: "Protect & Detect",
    indicators: [
      "Multi-factor authentication (MFA) coverage",
      "Role-based access control",
      "Account lifecycle for students & staff",
      "Privileged access management",
    ],
  },
  {
    id: "net", name: "Network & Infrastructure Security", fn: "Protect & Detect",
    indicators: [
      "Network segmentation",
      "Endpoint protection",
      "BYOD controls",
      "Patch management",
    ],
  },
  {
    id: "data", name: "Data Protection & Compliance", fn: "Protect & Detect",
    indicators: [
      "Data classification",
      "Encryption at rest and in transit",
      "Student-data privacy controls",
      "Backup & recovery",
      "Local-law / regulatory compliance",
    ],
  },
  {
    id: "aware", name: "Security Awareness & Training", fn: "Protect & Detect",
    indicators: [
      "Role-segmented awareness programme",
      "Phishing simulations",
      "Onboarding security training",
      "Coverage metrics",
    ],
  },
  {
    id: "ir", name: "Threat Detection & Incident Response", fn: "Respond & Recover",
    indicators: [
      "Logging & monitoring",
      "Documented incident-response plan",
      "Detection capability",
      "IR drills / tabletop exercises",
      "Post-incident review",
    ],
  },
  {
    id: "research", name: "Research & IP Protection", fn: "Identify",
    indicators: [
      "Research-data classification",
      "Access control for research / HPC",
      "IP protection in collaborations",
    ],
  },
];

/* -----------------------------------------------------------------
 *  CRITICALITY QUESTIONS  → criticality (c), 0–1
 *  Each answer carries a 0–1 value; the score is the mean.
 * ----------------------------------------------------------------- */
const CRIT_QUESTIONS = [
  {
    id: "data", q: "How sensitive is the most sensitive data this asset holds or processes?",
    options: [
      { label: "Public information only", value: 0.10 },
      { label: "Internal / operational data", value: 0.40 },
      { label: "Personal data (student or staff PII)", value: 0.75 },
      { label: "Highly sensitive (financial, health, research IP)", value: 1.00 },
    ],
  },
  {
    id: "depend", q: "How much of the institution depends on this asset?",
    options: [
      { label: "A few individuals", value: 0.20 },
      { label: "A single department", value: 0.50 },
      { label: "A whole faculty or campus", value: 0.80 },
      { label: "The entire institution", value: 1.00 },
    ],
  },
  {
    id: "downtime", q: "If it went down, how soon would operations be harmed?",
    options: [
      { label: "Tolerable for several days", value: 0.20 },
      { label: "Tolerable for about a day", value: 0.50 },
      { label: "Only a few hours", value: 0.80 },
      { label: "Immediately — mission critical", value: 1.00 },
    ],
  },
  {
    id: "reg", q: "Does regulation or law govern the data it handles?",
    options: [
      { label: "No specific regulation", value: 0.10 },
      { label: "Internal policy only", value: 0.45 },
      { label: "Sector / privacy regulation applies", value: 0.80 },
      { label: "Strict legal mandate (privacy or financial law)", value: 1.00 },
    ],
  },
];

/* -----------------------------------------------------------------
 *  EXPOSURE QUESTIONS  → exposure (x), 0–1
 * ----------------------------------------------------------------- */
const EXP_QUESTIONS = [
  {
    id: "reach", q: "Where can this asset be reached from?",
    options: [
      { label: "Air-gapped / isolated", value: 0.10 },
      { label: "Internal network only", value: 0.35 },
      { label: "Remotely, via VPN", value: 0.55 },
      { label: "Public internet, behind a login", value: 0.80 },
      { label: "Public internet, openly reachable", value: 1.00 },
    ],
  },
  {
    id: "auth", q: "How strong is the authentication in front of it?",
    options: [
      { label: "MFA enforced", value: 0.15 },
      { label: "SSO / strong passwords", value: 0.45 },
      { label: "Basic passwords only", value: 0.75 },
      { label: "No authentication / anonymous", value: 1.00 },
    ],
  },
  {
    id: "seg", q: "How well is it isolated from the rest of the network?",
    options: [
      { label: "Strongly segmented (own zone)", value: 0.20 },
      { label: "Partially segmented", value: 0.50 },
      { label: "Flat network — broadly reachable", value: 0.90 },
    ],
  },
  {
    id: "surface", q: "How large is its exposed attack surface?",
    options: [
      { label: "Minimal — hardened and fully patched", value: 0.20 },
      { label: "Moderate — some open services", value: 0.50 },
      { label: "Large or legacy — unpatched services", value: 0.90 },
    ],
  },
];

/* =================================================================
 *  STATE
 *  maturityAnswers[`${dimId}:${indicatorIndex}`] = level (0–5)
 *  Defaults to 0 (Incomplete) for every indicator.
 * ================================================================= */
const maturityAnswers = {};
DIMENSIONS.forEach((d) => d.indicators.forEach((_, i) => { maturityAnswers[`${d.id}:${i}`] = 0; }));

const critAnswers = {}; // critAnswers[qid] = value (0–1)
const expAnswers  = {};

const $ = (id) => document.getElementById(id);

/* =================================================================
 *  BUILD · maturity scale reference cards
 * ================================================================= */
function buildScaleCards() {
  $("scale-cards").innerHTML = MATURITY_LEVELS.map((l) => `
    <div class="scale-card" data-lvl="${l.n}">
      <div class="scale-n">${l.n}</div>
      <div class="scale-label">${l.label}</div>
      <p class="scale-desc">${l.desc}</p>
    </div>`).join("");
}

/* =================================================================
 *  BUILD · maturity questionnaire
 *  One panel per dimension; each indicator gets a 0–5 segmented
 *  radio control. Uses real radio inputs for keyboard accessibility.
 * ================================================================= */
function buildMaturityDims() {
  $("maturity-dims").innerHTML = DIMENSIONS.map((d, di) => `
    <div class="panel dim-panel" id="dim-${d.id}">
      <div class="dim-head">
        <div>
          <span class="fn-tag">${d.fn}</span>
          <h3 class="panel-h mt-1">${di + 1}. ${d.name}</h3>
        </div>
        <output class="dim-score" id="dimscore-${d.id}">0.0</output>
      </div>
      <div class="indicators mt-4">
        ${d.indicators.map((ind, ii) => `
          <div class="indicator">
            <span class="ind-label">${ind}</span>
            <div class="seg" role="radiogroup" aria-label="${ind} — maturity level 0 to 5">
              ${MATURITY_LEVELS.map((l) => `
                <input type="radio" class="seg-input" name="m_${d.id}_${ii}"
                       id="m_${d.id}_${ii}_${l.n}" value="${l.n}"
                       data-key="${d.id}:${ii}" ${l.n === 0 ? "checked" : ""} />
                <label class="seg-label" for="m_${d.id}_${ii}_${l.n}"
                       title="${l.n} · ${l.label}: ${l.desc}">${l.n}</label>`).join("")}
            </div>
          </div>`).join("")}
      </div>
    </div>`).join("");

  // event delegation for all maturity radios
  $("maturity-dims").addEventListener("change", (e) => {
    const t = e.target;
    if (!t.classList.contains("seg-input")) return;
    maturityAnswers[t.dataset.key] = parseInt(t.value, 10);
    renderMaturity();
  });
}

/* =================================================================
 *  BUILD · criticality & exposure questionnaires
 * ================================================================= */
function buildQuestionSet(containerId, questions, store, onChange) {
  $(containerId).innerHTML = questions.map((q, qi) => `
    <fieldset class="qblock">
      <legend class="qlabel">${q.q}</legend>
      <div class="qoptions">
        ${q.options.map((o, oi) => `
          <label class="qopt">
            <input type="radio" name="${containerId}_${q.id}" value="${o.value}"
                   data-qid="${q.id}" ${oi === 0 ? "checked" : ""} />
            <span>${o.label}</span>
          </label>`).join("")}
      </div>
    </fieldset>`).join("");

  // seed defaults (first option) into the store
  questions.forEach((q) => { store[q.id] = q.options[0].value; });

  $(containerId).addEventListener("change", (e) => {
    const t = e.target;
    if (t.type !== "radio") return;
    store[t.dataset.qid] = parseFloat(t.value);
    onChange();
  });
}

/* =================================================================
 *  SCORING
 * ================================================================= */
// average of an array
const mean = (arr) => arr.reduce((a, b) => a + b, 0) / (arr.length || 1);

// one dimension's maturity = mean of its indicator levels (0–5)
function dimensionScore(d) {
  return mean(d.indicators.map((_, i) => maturityAnswers[`${d.id}:${i}`]));
}

// overall maturity = mean of the 7 dimension scores (equal weight)
function overallMaturity() {
  return mean(DIMENSIONS.map(dimensionScore));
}

const criticalityScore = () => mean(CRIT_QUESTIONS.map((q) => critAnswers[q.id]));
const exposureScore    = () => mean(EXP_QUESTIONS.map((q) => expAnswers[q.id]));

// colour ramp for a 0–5 maturity value
function maturityColor(v) {
  if (v < 1.5) return "#b91c1c";          // red    — incomplete/initial
  if (v < 2.5) return "var(--amber)";     // amber  — managed
  if (v < 3.5) return "var(--blue)";      // blue   — defined
  if (v < 4.5) return "var(--teal)";      // teal   — quantitatively managed
  return "var(--green)";                   // green  — optimising
}

/* =================================================================
 *  RENDER · maturity results
 * ================================================================= */
function renderMaturity() {
  // per-dimension score chips
  DIMENSIONS.forEach((d) => { $(`dimscore-${d.id}`).textContent = dimensionScore(d).toFixed(1); });

  const overall = overallMaturity();
  $("mat-overall").textContent = overall.toFixed(1);

  // headline level = floor (cumulative scale: you're "at" a level once reached)
  const lvlIndex = Math.max(0, Math.min(5, Math.floor(overall + 1e-9)));
  const lvl = MATURITY_LEVELS[lvlIndex];
  const badge = $("mat-level");
  badge.textContent = `LEVEL ${lvl.n} · ${lvl.label.toUpperCase()}`;
  badge.className = "risk-band mt-3 " +
    (lvlIndex <= 1 ? "risk-critical" : lvlIndex === 2 ? "risk-high" : lvlIndex === 3 ? "risk-medium" : "risk-low");
  $("mat-level-desc").textContent =
    `${lvl.desc} Overall score ${overall.toFixed(1)} / 5 across the seven dimensions.`;

  // priority focus = lowest-scoring dimension
  const ranked = [...DIMENSIONS].map((d) => ({ d, s: dimensionScore(d) })).sort((a, b) => a.s - b.s);
  const weakest = ranked[0];
  $("mat-priority").textContent = weakest.s >= 5
    ? "Every dimension is at Optimising — focus on sustaining continuous improvement."
    : `“${weakest.d.name}” is your lowest dimension (${weakest.s.toFixed(1)} / 5). Raising it would lift your overall maturity the most.`;

  // per-dimension bars
  $("mat-bars").innerHTML = DIMENSIONS.map((d) => {
    const s = dimensionScore(d);
    const pct = (s / 5) * 100;
    return `<div class="mbar-row">
      <div class="mbar-label">${d.name}</div>
      <div class="mbar-track"><div class="mbar-fill" style="width:${pct}%;background:${maturityColor(s)}"></div></div>
      <div class="mbar-val">${s.toFixed(1)}</div>
    </div>`;
  }).join("");
}

/* =================================================================
 *  RENDER · criticality, exposure, and the feed-through readout
 * ================================================================= */
function renderAsset() {
  const c = criticalityScore();
  const x = exposureScore();

  $("crit-score").textContent = c.toFixed(2);
  $("exp-score").textContent  = x.toFixed(2);
  $("crit-meter").style.width = `${c * 100}%`;
  $("exp-meter").style.width  = `${x * 100}%`;

  $("feed-crit").textContent = c.toFixed(2);
  $("feed-exp").textContent  = x.toFixed(2);

  // carry values to the risk calculator via query params (app.js reads them)
  $("feed-link").href = `index.html?crit=${c.toFixed(2)}&exp=${x.toFixed(2)}#try`;
}

/* =================================================================
 *  RESET
 * ================================================================= */
function resetMaturity() {
  DIMENSIONS.forEach((d) => d.indicators.forEach((_, i) => {
    maturityAnswers[`${d.id}:${i}`] = 0;
    const el = $(`m_${d.id}_${i}_0`);
    if (el) el.checked = true;
  }));
  renderMaturity();
}

/* =================================================================
 *  INIT
 * ================================================================= */
buildScaleCards();
buildMaturityDims();
buildQuestionSet("crit-questions", CRIT_QUESTIONS, critAnswers, renderAsset);
buildQuestionSet("exp-questions",  EXP_QUESTIONS,  expAnswers,  renderAsset);

$("mat-reset").addEventListener("click", resetMaturity);

renderMaturity();
renderAsset();
