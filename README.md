# Detection Threat Landscape

A curated detection-engineering repository built from primary threat research and authoritative platform documentation.

Only technically defensible content is published. Every package separates production candidates from hunting or validation material and documents telemetry requirements, assumptions, false-positive considerations, validation steps, MITRE ATT&CK mappings, and source references.

> **Important:** A production candidate is not production-validated. Every query must be tested against the target environment, actual schema, retention, and legitimate activity before deployment.

## Repository structure

Threat packages are organized chronologically as `DD-MM-YYYY - threat-name/`.

```text
Detection-Threat-Landscape/
├── README.md
├── 22-07-2026 - clickfix-pcalua-rundll32/
│   └── clickfix-multi-stage-execution/production-candidates/
├── 22-07-2026 - clicklock/
│   └── clicklock-macos-kill-loop/production-candidates/
├── 22-07-2026 - hollowgraph/
│   ├── hollowgraph-calendar-c2/production-candidates/
│   └── hollowgraph-future-calendar-access/hunting/
├── 22-07-2026 - starland-rat/
│   └── pythonw-license-loader/hunting/
├── 22-07-2026 - studio-5000-acd-path-traversal/
│   └── studio-5000-novel-write-path/hunting/
├── 22-07-2026 - teleshim/
│   └── feedback-scheduled-task/hunting/
├── 23-07-2026 - fakeagent-sectoprat/
│   └── signed-application-dll-sideloading/hunting/
├── 24-07-2026 - msarat/
│   └── browser-cdp-remote-debugging/production-candidates/
│       ├── detection.kql
│       ├── references.txt
│       └── threat-analysis.pdf
└── 24-07-2026 - zimreaper/
    └── zimbra-app-password-persistence/hunting/
        ├── hunting.spl
        ├── references.txt
        └── threat-analysis.pdf
```

## Threat catalog

| Date | Threat | Primary platform | Content | Status |
|---|---|---|---|---|
| 24 July 2026 | [msaRAT](./24-07-2026%20-%20msarat/) | Microsoft Defender XDR | Headless Chrome or Edge with CDP remote debugging | Production candidate |
| 24 July 2026 | [ZimReaper](./24-07-2026%20-%20zimreaper/) | Splunk | Zimbra app-specific password persistence named `ZimbraWeb` | Hunting |
| 23 July 2026 | [FakeAgent / SectopRAT](./23-07-2026%20-%20fakeagent-sectoprat/) | Microsoft Defender XDR | Source-observed process-module pairs used for DLL sideloading | Hunting |
| 22 July 2026 | [ClickFix / Pcalua](./22-07-2026%20-%20clickfix-pcalua-rundll32/) | Defender XDR / Sentinel | Pcalua, hidden WMI process creation and remote Rundll32 execution | Production candidate |
| 22 July 2026 | [ClickLock](./22-07-2026%20-%20clicklock/) | Defender XDR on macOS | High-rate termination of core GUI processes | Production candidate |
| 22 July 2026 | [HOLLOWGRAPH](./22-07-2026%20-%20hollowgraph/) | Microsoft Graph / Sentinel | Exact-date calendar C2 candidate and generalized far-future hunting | Production candidate + Hunting |
| 22 July 2026 | [Starland RAT](./22-07-2026%20-%20starland-rat/) | Defender XDR / Sentinel | `pythonw.exe` executes a compiled loader masquerading as `LICENSE.txt` | Hunting |
| 22 July 2026 | [Studio 5000 / CVE-2026-9108](./22-07-2026%20-%20studio-5000-acd-path-traversal/) | Defender XDR / Sentinel | ACD-associated Rockwell writes into novel device paths | Hunting / Validation |
| 22 July 2026 | [TELESHIM](./22-07-2026%20-%20teleshim/) | Defender XDR / Sentinel | `Feedback` scheduled task targeting `ProgramData` | Hunting |

## Content classification

| Classification | Meaning |
|---|---|
| **Production candidate** | Precise, testable logic supported by source evidence and documented telemetry. Requires environmental validation before deployment. |
| **Hunting** | Investigation logic intended to establish prevalence, expected behavior, and tuning requirements. It must not be enabled as an alert without validation. |
| **Validation** | A telemetry or baseline experiment used to determine whether a reliable detection can be built. A match is not evidence of confirmed exploitation. |

## Package contents

Each package contains:

- a KQL, SPL, or YARA-L query for the selected Primary Platform;
- an eight-page A4 `threat-analysis.pdf`;
- `references.txt` with primary research, official schema documentation, relevant dates, and ATT&CK references.

## Visual publication standard

All dossiers use a controlled master maintained outside the public repository. The standard provides:

- a high-contrast black, white, electric-violet, magenta, and lime identity;
- consistent cover, assessment, attack-flow, telemetry, query, triage, validation, ATT&CK, and reference sections;
- a fixed eight-page A4 structure with no externally loaded report assets;
- visual quality assurance for page count, overflow, clipped query text, readable tables, correct classification, defanged references, and absence of customer data.

HTML templates, rendering sources, intermediate images, and working assets are never published.

## Quality principles

- Primary sources and official platform documentation are preferred.
- Observed facts, analytical interpretation, assumptions, and detection logic remain distinct.
- Table names, fields, functions, schemas, and mappings are never invented.
- Secondary-platform material is limited to atomic hunting, schema validation, or an explicit non-implementability statement.
- Customer data, internal identifiers, credentials, and environment-specific indicators are excluded.
- Isolated IOCs are not treated as durable behavioral detections.
- Every unexecuted query is labeled as an untested implementation sketch.
- Accuracy and explainability take priority over query volume.
