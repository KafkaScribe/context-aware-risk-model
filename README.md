# Beyond CVSS: A Context-Aware Risk-Rating Model

Single-page, self-contained demonstration of a context-aware cybersecurity
risk-scoring model from a thesis on a **cybersecurity maturity framework for
higher-education institutions**.

> Severity is not the same as risk.

## The model

```
Context-Aware Risk Score (0–10) = 10 × ( w1·severity + w2·exploit + w3·criticality + w4·exposure )

  severity    = CVSS base score / 10      (0–1)
  exploit     = EPSS-style probability     (0–1)
  criticality = institutional asset value  (0–1)
  exposure    = network reachability       (0–1)
  w1..w4      = AHP-derived weights, sum to 1   (defaults: 0.30, 0.30, 0.25, 0.15)
```

## Run it

No build step. Either open `index.html` directly, or serve it:

```bash
python -m http.server 5173
# → http://localhost:5173/
```

## Stack

One self-contained `index.html`: HTML + Tailwind (Play CDN) + Chart.js + vanilla JS.
The scoring logic lives in a commented block at the top of the `<script>` —
edit `DEFAULT_WEIGHTS`, `contextAwareRisk()`, or the `VULNS` example set to tweak.
