# Detection Threat Landscape

A curated detection-engineering repository built from primary threat research and authoritative platform documentation.

Only high-confidence content is included. Every package separates production candidates from hunting queries and documents telemetry requirements, assumptions, false-positive considerations, validation steps, MITRE ATT&CK mappings, and source references.

> **Important:** A production candidate is not production-validated. Every query must be tested against the target environment, actual schema, retention, and legitimate activity before deployment.

## Threat landscape

Threat packages are organized chronologically using the following naming convention:

`DD-MM-YYYY - threat-name/`

```text
Detection-Threat-Landscape/
├── README.md
└── 22-07-2026 - hollowgraph/
    ├── hollowgraph-calendar-c2/
    │   └── production-candidates/
    │       ├── detection.kql
    │       ├── threat-analysis.pdf
    │       └── references.txt
    └── hollowgraph-future-calendar-access/
        └── hunting/
            ├── hunting.kql
            ├── threat-analysis.pdf
            └── references.txt
```

## Threat catalog

| Date | Threat | Platform | Content | Status |
|---|---|---|---|---|
| 22 July 2026 | [HOLLOWGRAPH](./22-07-2026%20-%20hollowgraph/) | Microsoft Graph / Sentinel | Calendar C2 detection and far-future calendar hunting | Production candidate + Hunting |

## Content classification

| Classification | Meaning |
|---|---|
| **Production candidate** | Precise, testable logic supported by source evidence and documented telemetry. Requires environmental validation before deployment. |
| **Hunting** | Investigation logic intended to establish prevalence, expected behavior, and tuning requirements. It must not be enabled as an alert without validation. |

## Package contents

Each detection or hunting package contains:

- a commented KQL, SPL, or YARA-L query;
- a visual threat-analysis PDF describing the observed behavior and detection rationale;
- primary research, official schema documentation, and MITRE ATT&CK references.

## Quality principles

- Primary sources and official platform documentation are preferred.
- Observed facts, analytical interpretation, assumptions, and detection logic remain distinct.
- Table names, fields, functions, and mappings are never invented.
- Customer data, internal identifiers, credentials, and environment-specific indicators are excluded.
- Isolated IOCs are not treated as durable behavioral detections.
- Accuracy and explainability take priority over query volume.

## Current coverage

- Microsoft Sentinel / KQL
- Splunk / SPL
- Google Chronicle / YARA-L
- Endpoint, identity, cloud, and network telemetry

Coverage expands only when the available evidence supports a precise and operationally useful detection or hunting hypothesis.
