# Posture, for attorneys

The posture-coherence family archives one small `*.coherence.json` per
negotiation round (from `analyze --posture --emit-coherence`) and can answer, from
the archive alone, how your position held across a deal. There are 29 commands
with engineer names — volatility, relapse, tenure, settling — but a deal lawyer
only needs three questions answered. `posture-review` answers all three at once,
in deal language:

```
vaulytica posture-review round-1.coherence.json round-2.coherence.json … [--format markdown|json]
```

| Your question | The view | Drill-down commands |
| --- | --- | --- |
| **Did our position slip between drafts?** | **Position drift** — per front, whether it improved, held, whipsawed (dipped below floor and recovered), or steadily regressed, first-vs-last and round-to-round. | `coherence-trend`, `compare-coherence` |
| **Were there rounds where every stated position was below our floor?** | **Exposure map** — the round × front heatmap with the blackout verdict (a round where every stated front sat below your acceptable floor). | `coherence-matrix` |
| **Which front is weakest, and where?** | **Weakest front** — the dimension that binds your exposure and the documents it binds in. | `coherence-weak-front`, `coherence-exposure` |

## What it does and does not do

- **No new computation.** `posture-review` composes the three existing report
  modules over the same hash-verified rounds every sibling command uses; each
  section names the command to drill into for the full detail. `--format json`
  nests the three sibling reports verbatim under one `posture_review` document
  with a `posture_review_hash`.
- **The floor is binary.** "Below your acceptable floor" is the only sub-floor
  state; intermediate rungs (if your playbook defines them) refine the *above*
  detail but never change the floor verdict. Every round archive is
  hash-verified on load — a tampered round is a hard error — and a mixed-ladder
  archive is refused (comparing binding floors across different ladders is
  meaningless).
- It reports where your **stated** positions sat against **your** ladder. It is
  not legal advice and does not judge whether a position is wise — only whether
  the drafts held the line you set.
