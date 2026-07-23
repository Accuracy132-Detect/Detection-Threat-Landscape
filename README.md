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
├── 22-07-2026 - clickfix-pcalua-rundll32/
│   └── clickfix-multi-stage-execution/
│       └── production-candidates/
│           ├── detection.kql
│           ├── threat-analysis.pdf
│           └── references.txt
├── 22-07-2026 - clicklock/
│   └── clicklock-macos-kill-loop/
│       └── production-candidates/
│           ├── detection.kql
│           ├── threat-analysis.pdf
│           └── references.txt
├── 22-07-2026 - hollowgraph/
│   ├── hollowgraph-calendar-c2/
│   │   └── production-candidates/
│   │       ├── detection.kql
│   │       ├── threat-analysis.pdf
│   │       └── references.txt
│   └── hollowgraph-future-calendar-access/
│       └── hunting/
│           ├── hunting.kql
│           ├── threat-analysis.pdf
│           └── references.txt
├── 22-07-2026 - starland-rat/
│   └── pythonw-license-loader/
│       └── hunting/
│           ├── hunting.kql
│           ├── threat-analysis.pdf
│           └── references.txt
├── 22-07-2026 - studio-5000-acd-path-traversal/
│   └── studio-5000-novel-write-path/
│       └── hunting/
│           ├── hunting.kql
│           ├── threat-analysis.pdf
│           └── references.txt
├── 22-07-2026 - teleshim/
│   └── feedback-scheduled-task/
│       └── hunting/
│           ├── hunting.kql
│           ├── threat-analysis.pdf
│           └── references.txt
└── 23-07-2026 - fakeagent-sectoprat/
    └── signed-application-dll-sideloading/
        └── hunting/
            ├── hunting.kql
            ├── threat-analysis.pdf
            └── references.txt
```

## Threat catalog

| Date | Threat | Platform | Content | Status |
|---|---|---|---|---|
| 23 July 2026 | [FakeAgent / SectopRAT](./23-07-2026%20-%20fakeagent-sectoprat/) | Microsoft Defender XDR | Renamed signed applications loading source-observed DLL pairs | Hunting |
| 22 July 2026 | [ClickFix / Pcalua](./22-07-2026%20-%20clickfix-pcalua-rundll32/) | Defender XDR / Sentinel | Pcalua, hidden WMI process creation and remote Rundll32 execution | Production candidate |
| 22 July 2026 | [ClickLock](./22-07-2026%20-%20clicklock/) | Defender XDR on macOS | High-rate termination of core GUI processes | Production candidate |
| 22 July 2026 | [HOLLOWGRAPH](./22-07-2026%20-%20hollowgraph/) | Microsoft Graph / Sentinel | Calendar C2 detection and far-future calendar hunting | Production candidate + Hunting |
| 22 July 2026 | [Starland RAT](./22-07-2026%20-%20starland-rat/) | Defender XDR / Sentinel | pythonw.exe executes a compiled loader masquerading as LICENSE.txt | Hunting |
| 22 July 2026 | [Studio 5000 / CVE-2026-9108](./22-07-2026%20-%20studio-5000-acd-path-traversal/) | Defender XDR / Sentinel | ACD-associated Rockwell writes into novel device paths | Hunting / Validation |
| 22 July 2026 | [TELESHIM](./22-07-2026%20-%20teleshim/) | Defender XDR / Sentinel | Feedback scheduled task targeting ProgramData | Hunting |

## Content classification

| Classification | Meaning |
|---|---|
| **Production candidate** | Precise, testable logic supported by source evidence and documented telemetry. Requires environmental validation before deployment. |
| **Hunting** | Investigation logic intended to establish prevalence, expected behavior, and tuning requirements. It must not be enabled as an alert without validation. |
| **Validation** | A telemetry or baseline experiment used to determine whether a reliable detection can be built. A match is not evidence of confirmed exploitation. |

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
- Endpoint, identity, cloud, OT/ICS, and network telemetry

Coverage expands only when the available evidence supports a precise and operationally useful detection or hunting hypothesis.
