# Detection Threat Landscape Reporting Standard v2

## Purpose

This standard turns every repository package into a traceable detection-engineering product rather than a news summary. It applies to endpoint, identity, cloud, application, network, appliance and OT telemetry.

The repository publishes the strongest implementation that the available evidence supports. It never promotes a query because a threat is important, and it never implies validation that did not occur.

## Core principles

1. **Evidence before narrative.** Every material technical claim has a stable claim ID and maps to one or more sources.
2. **Telemetry before language.** Select the observable behavior and verified schema first. Use the native query language for the primary platform. Use Sigma only when the behavior and log source are genuinely portable.
3. **Facts, analysis and assumptions remain separate.** Source-confirmed observations, analyst inference and unverified assumptions must not be blended.
4. **No forced implementation.** When parser, schema or telemetry is unknown, publish a validation query or detection concept instead of pseudocode presented as a rule.
5. **Operational usefulness.** Every query states what a match proves, what it does not prove, triage steps, false positives, visibility gaps and a promotion gate.
6. **Visual consistency.** Every `threat-analysis.pdf` uses the same embedded typography, grid, colors and eight-page structure. Only the campaign-specific illustration on the right side of the cover changes. Artwork is selected by threat domain and deterministically varied per report, while remaining blended into the continuous gradient.

## Package contract

Each detection directory contains:

```text
<classification>/
├── report.json          # canonical, machine-readable report source
├── evidence.json        # claim-level provenance and evidence maturity
├── references.json      # normalized source ledger
├── validation.md        # validation plan or recorded results
├── <query file>         # one primary native implementation
├── references.txt       # human-readable compatibility file
└── threat-analysis.pdf  # canonical eight-page operational dossier
```

Every repository package is now v2-complete. Packages converted mechanically from the previous layout include a `migration` record with `provenance_status: legacy-review-required`, the SHA-256 of the previous PDF and query, and `query_conditions_changed: false`. Repository QA recomputes the query-body hash after removing the managed v2 header and fails if the original logic changed.

Mechanical migration standardizes structure and visual design; it does not upgrade evidence maturity. Legacy narrative claims remain `analyst-inference` until a reviewer atomically remaps each statement to the normalized source ledger.

## Evidence maturity

| State | Meaning | Who may assign it |
| --- | --- | --- |
| `documented` | Directly stated or shown by a cited source | Research workflow |
| `analyst-inference` | Reasoned conclusion, with confirmation/refutation criteria | Research workflow |
| `static-observed` | Personally observed in static analysis with retained evidence | Human validator |
| `dynamic-observed` | Personally observed during controlled execution | Human validator |
| `exploit-reproduced` | Exploit effect reproduced safely against an authorized lab target | Human validator |
| `detection-validated` | Query produced the expected true positive on retained telemetry | Human validator |

Automated research may assign only `documented` and `analyst-inference`.

## Detection maturity

| State | Required evidence |
| --- | --- |
| `concept` | Observable hypothesis but insufficient verified schema |
| `validation` | Query intended to inspect local telemetry or schema; not an alert |
| `hunting` | Executable investigative logic supported by sources and documented fields |
| `production-candidate` | Precise alert logic with bounded overlap and a reproducible validation plan |
| `lab-validated` | Controlled true positive and negative controls retained |
| `production-validated` | Target-environment performance, tuning and ownership approved |

Directory names remain `validation`, `hunting` and `production-candidates` for compatibility. The exact maturity is stored in `report.json` and query comments.

## Selection gates

A report must pass all applicable gates:

- **Novelty:** not a duplicate unless a new behavior, variant or detection opportunity is documented.
- **Evidence:** at least one primary or original technical source.
- **Observability:** the chosen behavior is represented by identifiable telemetry.
- **Schema:** every field used by a query is documented or explicitly marked for local validation.
- **Specificity:** conditions are traceable to evidence; arbitrary thresholds are prohibited.
- **Operational value:** the result changes triage, coverage, containment or validation decisions.

Lab reproducibility is scored but is not a blocking gate. This preserves coverage for cloud services, appliances and proprietary platforms.

## Prioritization score

Each criterion is scored from 0 to 3 and multiplied by its weight.

| Criterion | Weight | 3 | 2 | 1 | 0 |
| --- | ---: | --- | --- | --- | --- |
| Exploitation / observed use | 3 | Vendor/KEV/original ITW evidence | Research-team observations | Public PoC or credible precursor | Theoretical only |
| Detection yield | 3 | New durable behavior | Material improvement | IOC/artifact-only hunt | No defensible detection |
| Evidence quality | 3 | Multiple independent primary/original sources | One primary plus corroboration | One solid source | Secondary-only |
| Observability | 2 | Direct, documented telemetry | Documented but environment-dependent | Indirect or partial | Not observable |
| Technical novelty | 2 | New technique or primitive | Significant variant | Minor evolution | Already covered |
| Exposure relevance | 2 | Broad or business-critical exposure | Meaningful segment | Niche | Marginal |
| Reproducibility | 1 | Safe test under two hours | Testable with moderate setup | Expensive/proprietary | Not reproducible |
| Freshness | 1 | Under 7 days | 7-14 days | 15-30 days | Older without new evidence |

Maximum score: 51. Scores support prioritization; they do not override a failed evidence, observability or schema gate.

## Canonical eight-page dossier

1. **Cover** - title, scope, maturity, confidence, operational value, platform and campaign-specific faded illustration.
2. **Executive Assessment** - decision, key findings, source facts, analyst assessment, assumptions and evidence boundary.
3. **Threat Mechanics** - technical background, attack chain and observable transitions.
4. **Telemetry & Evidence Model** - data contract, required fields, enrichment and visibility gaps.
5. **Detection Logic** - complete primary query or the material portion with a link to the complete file; condition evidence and match meaning.
6. **Triage & Hunting Playbook** - evidence-preserving investigation sequence and disposition rules.
7. **False Positives & Validation** - overlap model, validation procedure, success/rejection criteria and promotion gate.
8. **Analyst Assessment & References** - ATT&CK mapping, conclusion, open questions, source summary and document control.

## Query header contract

Every query starts with comments containing:

- Rule name including ATT&CK technique IDs or `NO-MITRE-MAPPING`.
- Detection maturity and validation status.
- Primary platform and required telemetry.
- Purpose and one-line logic.
- What a match proves and does not prove.
- Known false positives and coverage limits.
- References to claim IDs in `evidence.json`.

## Quality gates

Repository QA fails when:

- a v2 report references a missing claim or source;
- a query has no MITRE comment or maturity boundary;
- a source URL, publication date or source type is absent;
- a claim marked `documented` has no source;
- a non-human workflow assigns a lab evidence state;
- a PDF is not A4, has a page count other than eight, lacks embedded fonts, contains blank pages or uses a non-canonical layout version;
- the cover illustration is boxed instead of blended into the gradient;
- query and PDF maturity labels disagree.

## Publication policy

Public packages contain no customer data, secrets, live malware samples or unreviewed exploit code. URLs may remain clickable in structured source files; IOCs shown in prose are defanged. Publication records the analysis date separately from the source event date.
