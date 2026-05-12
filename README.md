# Vaulytica

> The free, deterministic, runs-entirely-in-your-browser contract checker. A linter for legal documents. No login, no API key, no telemetry, no server. Drop in a contract, get back a Word document you can cite. That is the entire product.

**Vaulytica is the second pair of eyes you can cite.**

## What happened to the older project? 

The Google Workspace & Microsoft 365 DSPM tooling has been rolled into [Mantissa Log](https://github.com/clay-good/mantissa-log) and [Mantissa Stance](https://github.com/clay-good/mantissa-stance). 

## What I check

Vaulytica runs ~80 deterministic rules across ten categories — structural, financial, temporal, obligations, risk allocation, choice and venue, termination, IP and data, personnel, and dark patterns — against PDF or DOCX contracts you drop onto the page. The output is a Microsoft Word document with findings, an obligations ledger, an extracted-data appendix, and a full audit trail naming every rule, every data source, and the dataset version that produced the result.

## What I do not do

- I do not give you legal advice. I am a software tool. If something here matters, hire a lawyer.
- I do not replace your judgment. I find mechanical things consistently. The hard calls are still yours.
- I do not use AI. Not a model, not a copilot, not "powered by." A probabilistic answer cannot be cited. The whole point of this is the opposite.
- I do not see your data. There is no server. Your contract never leaves the tab. Open DevTools and watch the network panel if you want to confirm.

## Quick start

```
git clone https://github.com/claygood/vaulytica.git
cd vaulytica
npm install
npm run dev
```

Then open the printed URL.

## Build

```
npm run build       # static site to dist/
npm run test        # vitest
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
```

## How the DKB stays current

The Deterministic Knowledge Base (DKB) is rebuilt weekly via a GitHub Action that fetches from SEC EDGAR, the US Code, the eCFR, govinfo, Common Paper, CUAD, LEDGAR, the ULC, and other free public sources. The rebuild runs a regression check against fixed test contracts before publishing. See [`docs/data-sources.md`](docs/data-sources.md).

## Why no AI

Every other contract tool you can find right now leans on a language model. The output is fluent and confident and changes every time you run it. A senior partner cannot sign off on it. An auditor cannot trace it. A client cannot reproduce it. Vaulytica gives the same answer every time, and you can point to the rule that produced it.

## Docs

- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Determinism + result-hash reproducibility: [`docs/determinism.md`](docs/determinism.md)
- Privacy posture + threat model: [`docs/threat-model.md`](docs/threat-model.md)
- Data sources: [`docs/data-sources.md`](docs/data-sources.md)
- Adding a rule: [`docs/adding-a-rule.md`](docs/adding-a-rule.md)
- Adding a playbook: [`docs/adding-a-playbook.md`](docs/adding-a-playbook.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

MIT. See [`LICENSE`](LICENSE).

## Disclaimer

Vaulytica is a software tool. It is not a lawyer, it does not give legal advice, and using it does not create an attorney-client relationship with anyone. If something here matters, hire a lawyer.
