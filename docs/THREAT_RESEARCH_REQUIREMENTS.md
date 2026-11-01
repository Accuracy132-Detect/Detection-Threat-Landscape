# Mandatory technical threat research — additive contract 1.0

## Purpose and scope

Every newly authored package combines the repository's existing detection engineering with an original technical threat report. The reader must understand how and why the attack works, what actually happened, which transitions the evidence supports, the consequences, and how to investigate or test the hypothesis. A list of IOCs, ATT&CK techniques or detection prerequisites is insufficient.

This is an addition to `REPORTING_STANDARD_V2.md`, not a replacement. Preserve query logic, native-platform selection, schema checks, maturity and confidence boundaries, false positives, triage, validation and the 51-point operational score. Research prose is written in formal Italian; preserve product names, commands, fields and technical identifiers in their original form. Write original analysis grounded in opened primary sources; do not copy another researcher's report or reuse their conclusions without attribution.

The contract applies to newly authored packages after its adoption. Do not bulk rewrite the existing archive, alter old queries or claim that older packages passed this editorial review. A deliberate substantive revision should apply this contract and retain the historical provenance.

## Seven required analytical dimensions

1. **Technical mechanism.** Explain the affected architecture or component, relevant normal behavior, attacker-controlled input or action, security boundary and resulting change of state. Explain why the transition is possible. Connect the mechanism to the detection surface without reducing the report to query conditions.
2. **Timeline.** Separate source publication, event/incident dates, disclosure, patches and analysis date. Preserve timezone and precision; mark approximate dates. If event times are unavailable, provide the supported relative sequence and explicitly state the temporal gap. Never turn source publication into an attack date.
3. **Root cause or enabling conditions.** State prerequisites, initial permissions, configuration, vulnerable code path or trust failure. Separate root cause, initial-access vector, execution mechanism and downstream effects. When the exact root cause is not established, describe supported enabling conditions, what remains unknown and how that limits the conclusion. Do not invent a CVE for social engineering or a software flaw for credential abuse.
4. **Execution flow.** Give a causal narrative from entry or precondition through documented actions to the observed outcome. For each important transition identify input/action, executing component or identity, privilege/trust context, output/artifact, supporting claim IDs and visibility limits. Distinguish attempted, blocked, successful, inferred and unknown stages. A hunting match does not establish the entire chain.
5. **Impact and scope.** Separate demonstrated impact from technically possible consequences. Identify affected versions/configurations, assets, identities or services when documented, prerequisite access, attack limitations and containment/mitigation implications. Distinguish source-reported population from analyst estimates. Do not label exposure as compromise.
6. **Evidence and uncertainty.** Tie every material claim to `C###` entries in `evidence.json` and opened `S###` sources in `references.json`. Retain precise locators such as source section, figure, log excerpt or official field documentation in the claim rationale or report. Separate source facts, vendor interpretation, analyst inference, assumptions, contradictions and unknowns. State what each artifact establishes and cannot establish. Explicitly disclose single-source dependence or missing raw evidence.
7. **Laboratory plan.** Describe the hypothesis, target/version or service configuration, permissions, isolated topology or authorized test tenant, telemetry configuration, test inputs/actions, expected artifacts, controlled positive, benign negative controls, success/rejection/failure conditions, collection/preservation and cleanup. Label the plan `not executed` unless retained results support otherwise. Connect steps to `validation.md` rather than duplicating inconsistent procedures. If an appliance, cloud service or OT target cannot be reproduced, give a passive/offline validation alternative and its limits; lack of affordable lab access does not itself prohibit publication.

An honest unknown is not automatically a defect. It becomes blocking when the missing information prevents a defensible account of the mechanism, leads to a contradictory chain or invalidates the detection hypothesis. State the boundary rather than filling it with speculation.

## Adaptation by report type

- **Campaign:** victim/context and objective only as evidenced; actual entry path, payload/tool roles, execution sequence, infrastructure, persistence, lateral movement and final actions only where supported. Separate different intrusion cases and avoid combining stages into a fictional single incident. Explain why each observed transition matters.
- **CVE:** affected component and versions, vulnerable versus fixed configuration, authentication/access requirements, input-to-sink or trust-boundary failure, vulnerability class, exploitation primitive and achieved capability. Separate advisory, public PoC, researcher reproduction and in-the-wild evidence. Use patch/advisory analysis only to the depth the sources support. No exploit outcome may be inferred from a version match.
- **Malware:** sample identity and analysis provenance, delivery/loader/staging flow, execution and configuration, persistence, network behavior and capabilities. Mark behavior as source-documented, statically observed or dynamically observed according to the existing evidence model. Do not claim personal sample execution from vendor screenshots.
- **Behavior or detection research:** normal baseline, malicious deviation, enabling condition or trust misuse, underlying primitive, event-generation path, scope of abstraction and adversarial/benign variants. Explain why the condition discriminates and what it misses. A representative flow is explicitly a model, not a newly observed campaign.
- **Cloud and identity:** tenant/service prerequisites, principal and permissions, token/session type, trust/authorization boundary, API or identity transition, control-plane versus data-plane activity and audit limitations. Distinguish stolen credentials, consent, privilege changes, persistence and resource access.
- **OT/appliance:** product/firmware or protocol context, asset role and zone, prerequisites, engineering/maintenance overlap and process implications. Separate management access from demonstrated process manipulation. Validation remains passive, offline or explicitly coordinated; never introduce unsafe process changes to satisfy reproducibility.

## Package artifacts and drafting order

1. Open original technical material, advisory and required logging/schema documentation. Build the claim/source ledger before drawing conclusions.
2. Draft `threat-report.md` from `templates/report-v2/threat-report.md`. Use connected explanatory prose and specific artifacts; preserve the eight required numbered headings. Depth follows the mechanism and available evidence, not a word quota.
3. Populate the existing `report.json` fields and add `threat_research_contract: "1.0"`. Set `technical_background` to the actual mechanism and enabling conditions, and `attack_chain` to causal observable transitions. Include chronological boundaries and impact in existing assessment/conclusion fields. Keep full technical detail in the Markdown report.
4. Complete the existing detection package and `validation.md` under the unchanged detection contract. A report about the whole intrusion must clearly identify the narrower behavior covered by its query.
5. Generate the PDF with the existing renderer. Keep all eight pages, fonts, geometry, palette and section order. Essential mechanism, root cause/enabling conditions, causal sequence, temporal boundary and impact must be understandable from the PDF itself. Page 7 summarizes the lab plan; the extended report contains its detailed design. Do not remove detection material, shrink fonts or rely on silent truncation.
6. Conduct a separate editorial pass after drafting and rendering. Recheck the report against the opened sources, compare the attack narrative with the query's actual scope and inspect the PDF for missing explanations. This pass may be performed by the same analyst, but must not be represented as an independent human review.
7. Record the review in `threat-review.json`, then run both applicable validators. Update README/catalog links for the research report and recorded review alongside the PDF/query.

## Separate editorial publication gate

Score each of the seven dimensions using the same anchored rubric:

- **0:** absent, contradicted, invented or technically wrong.
- **1:** generic summary, labels or assertions without a usable causal explanation.
- **2:** partially supported but a material explanatory, evidence or test-design gap remains.
- **3:** technically coherent, specific and sufficiently sourced, with actionable detail and honest boundaries.
- **4:** detailed and critically assessed, including important prerequisites, variants/limits and concrete evidence or test artifacts appropriate to that dimension.

For each dimension, record the reason for the score, the relevant numbered manuscript sections, supporting claim IDs and the canonical PDF pages where the essential account appears. A source count, polished layout, new JSON field or the existence of a query is not a justification. Score deductions must name the actual limitation; do not award a high score simply because the package passes schema validation.

Record each opened supporting source in `source_checks` as an object with `source_id`, `opened: true` and `notes` identifying the reviewed section/artifact and its limits. For example, `{"source_id": "S001", "opened": true, "notes": "Execution-flow section and process-tree figure reviewed; no raw endpoint events supplied."}`. Record actual checks only; these entries are review attestations, not automatic proof of source access.

Publication requires **at least 24/28**, **every dimension at least 3/4**, no blocking issues, completed source checks and a self-contained PDF. The total is computed by the validator; do not manufacture a total or hide a weak dimension behind an average. This score does not replace the 51-point prioritization score and does not imply a validated query, exploit reproduction or production readiness.

Always block for unsupported causal claims, invented dates/root cause, conflation of multiple incidents, demonstrated/potential impact confusion, a generic lab checklist, inconsistent claim/source references, detection-scope overstatement or a PDF that omits the essential attack explanation. If sources cannot resolve a critical gap, choose a better-supported candidate or return no publication. Do not pad the narrative to pass.

The machine check verifies artifacts, nonempty sections, claim/source references, recorded scores and review attestations. It cannot establish that a human or model actually read a source, prove technical correctness or judge narrative depth. Passing it is necessary, not sufficient: the separate source-based editorial assessment remains mandatory and must not be described as independent validation.

## Validation and handoff

Run:

```bash
python scripts/quality/validate_repository.py --strict-all
python scripts/quality/validate_threat_report.py <new-package-directory>
```

Run the second command for each newly authored package. Preserve the existing full-repository gate and all visual checks. A failed gate requires revision or no publication, regardless of the operational score.

The handoff reports the two scores separately, dimensional deductions, source/evidence boundaries, actual lab execution status, both validator outcomes, visual review, artifact links and any remaining work. Never claim that this new contract has improved historical reports or that a future scheduled run has passed before reviewing its actual output.
