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
├── 24-07-2026 - zimreaper/
│   └── zimbra-app-password-persistence/hunting/
├── 25-07-2026 - certighost/
│   └── adcs-chase-to-non-dc/validation/
├── 28-07-2026 - sourtrade/
│   └── browser-created-large-executable/hunting/
├── 29-07-2026 - hermes-hades/
│   └── webserver-to-hadoop-service/validation/
├── 30-07-2026 - joyfill/
│   └── developer-tool-runtime-modification/hunting/
├── 31-07-2026 - xmrig-covert-ops/
│   └── root-context-user-switching/hunting/
├── 31-07-2026 - cve-2023-23397/
│   └── outlook-forced-ntlm-authentication/hunting/
├── 02-08-2026 - stac4749/
│   └── teams-vishing-powershell-payload/hunting/
├── 03-08-2026 - n-central-cve-2026-18577/
│   └── cloudflared-service-registration/hunting/
├── 04-08-2026 - mirage-kitten/
│   └── appvshnotify-sspicli-sideloading/production-candidates/
├── 05-08-2026 - quickfox/
│   └── fdmtp-csmonitor-dll-sideloading/hunting/
├── 06-08-2026 - chaindrop/
│   └── node-setup-bun-execution/hunting/
├── 07-08-2026 - interlock/
│   └── volatility-credential-plugins/production-candidates/
├── 08-08-2026 - unc6671/
│   └── scripted-sharepoint-file-access/hunting/
├── 09-08-2026 - npm-cooldown/
│   └── npmrc-file-event-coverage/validation/
│       ├── validation.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 10-08-2026 - mac-crypto-drainer/
│   └── softwareupdated-launchagent-bootstrap/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 11-08-2026 - gunra/
│   └── wmic-shadowcopy-deletion/production-candidates/
│       ├── detection.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 12-08-2026 - operation-dream-job/
│   └── securitypdf-temp-child-execution/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 13-08-2026 - head-mare/
│   └── phantomgraph-temp-batch-services/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 14-08-2026 - armored-likho/
│   └── still-toolkit-service-installation/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 15-08-2026 - honeymyte/
│   └── coolclient-msagent-driver-service/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 15-08-2026 - cve-2026-8452/
│   └── netscaler-nsppe-crash-signals/validation/
│       ├── validation.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 16-08-2026 - evooo1bot/
│   └── cron-download-pipe-shell/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 17-08-2026 - patchcord/
│   └── beaconbrowserhijack-run-key/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 18-08-2026 - jewelbug/
│   └── com-microsoft-runedge-native-messaging-host/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 19-08-2026 - medusa/
│   └── mimilib-lsa-security-package/production-candidates/
│       ├── detection.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 20-08-2026 - grandoreiro/
│   └── dff-dupfdll-mingwm10-sideload/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 21-08-2026 - uat-10147/
│   └── iis-defender-exclusion/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 22-08-2026 - cve-2026-73570/
│   └── zimbra-service-status-log-signals/validation/
│       ├── validation.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 23-08-2026 - rust-crate-supply-chain/
│   └── proc-macro1-cargo-cache/hunting/
│       ├── hunting.kql
│       ├── references.txt
│       └── threat-analysis.pdf
├── 24-08-2026 - btr-reforged/
│   └── btr-cli-driver-dat-ads/validation/
│       ├── validation.kql
│       ├── references.txt
│       └── threat-analysis.pdf
└── 25-08-2026 - fake-codex-clickfix/
    └── xattr-tmp-helper-quarantine-clear/hunting/
        ├── hunting.kql
        ├── references.txt
        └── threat-analysis.pdf
```

## Threat catalog

| Date | Threat | Primary platform | Content | Status |
|---|---|---|---|---|
| 25 August 2026 | [Fake Codex ClickFix](./25-08-2026%20-%20fake-codex-clickfix/) | Microsoft Defender XDR | Source-observed `xattr -c` against the staged `/tmp/helper` Mach-O before permission change and execution | Hunting |
| 24 August 2026 | [BTR Reforged](./24-08-2026%20-%20btr-reforged/) | Microsoft Sentinel | Validate the current BTR_CLI-specific secondary `.dat` ADS on a `.sys` driver through Sysmon Event ID 15; a match does not establish malicious BTR execution | Validation |
| 23 August 2026 | [Rust crate supply-chain attack](./23-08-2026%20-%20rust-crate-supply-chain/) | Microsoft Defender XDR | Officially listed compromised and attacker-owned `.crate` artifacts observed in Cargo registry caches on developer or CI systems | Hunting |
| 22 August 2026 | [Zimbra / CVE-2026-73570](./22-08-2026%20-%20cve-2026-73570/) | Microsoft Sentinel | Validate whether source-recommended Zimbra `Service status change` records are retained in `Syslog`; a match does not establish exploitation | Validation |
| 21 August 2026 | [UAT-10147](./21-08-2026%20-%20uat-10147/) | Microsoft Defender XDR | Source-observed PowerShell or Registry commands add the standard IIS `inetsrv` directories to Microsoft Defender exclusions | Hunting |
| 20 August 2026 | [Grandoreiro](./20-08-2026%20-%20grandoreiro/) | Microsoft Defender XDR | One renamed process loads the source-observed co-located `dupfdll.dll` and `mingwm10.dll` Duplicate Files Finder sideload chain | Hunting |
| 19 August 2026 | [Medusa ransomware](./19-08-2026%20-%20medusa/) | Microsoft Defender XDR | LSA `Security Packages` Registry value modified to load the source-observed Mimikatz `mimilib` credential-stealing SSP | Production candidate |
| 18 August 2026 | [Jewelbug / XG-Web](./18-08-2026%20-%20jewelbug/) | Microsoft Defender XDR | Source-observed Chrome native-messaging host key `com.microsoft.runedge` used to bridge a malicious browser extension to a Windows helper | Hunting |
| 17 August 2026 | [PATCHCORD](./17-08-2026%20-%20patchcord/) | Microsoft Defender XDR | Source-observed `BeaconBrowserHijack` value written under the current user's Windows `Run` key | Hunting |
| 16 August 2026 | [Evooo1Bot](./16-08-2026%20-%20evooo1bot/) | Microsoft Defender XDR | Source-observed recurring Linux `wget`/`curl` downloader pipeline executed through `/bin/sh` with output suppressed | Hunting |
| 15 August 2026 | [NetScaler / CVE-2026-8452](./15-08-2026%20-%20cve-2026-8452/) | Microsoft Sentinel | Validate whether NetScaler `nsppe` crash, core, abort or restart signals are retained in `Syslog`; a match does not establish exploitation | Validation |
| 15 August 2026 | [HoneyMyte / CoolClient](./15-08-2026%20-%20honeymyte/) | Microsoft Sentinel | Windows Security Event 4697 records the source-observed `msagent` service pointing to `msagent.sys` before kernel-rootkit behavior | Hunting |
| 14 August 2026 | [Armored Likho / Still Toolkit](./14-08-2026%20-%20armored-likho/) | Microsoft Sentinel | Windows Security Event 4697 records source-observed `TReload` or `auxhost` service installation | Hunting |
| 13 August 2026 | [Head Mare / PhantomGraph](./13-08-2026%20-%20head-mare/) | Microsoft Sentinel | Windows Security Event 4697 records source-observed `SysExcSvc` or `SysReadSvc` installation through `cmd /c` and a temporary `cmd_cmd_*.bat` file | Hunting |
| 12 August 2026 | [Operation Dream Job / SecurityPDF](./12-08-2026%20-%20operation-dream-job/) | Microsoft Defender XDR | Source-observed `SecurityPDF.exe` creates and launches `%TEMP%\\new.exe` after opening a crafted PDF | Hunting |
| 11 August 2026 | [Gunra ransomware](./11-08-2026%20-%20gunra/) | Microsoft Defender XDR | `WMIC.exe` deletes volume shadow copies through the source-observed `shadowcopy ... delete` command pattern | Production candidate |
| 10 August 2026 | [macOS ClickFix crypto drainer](./10-08-2026%20-%20mac-crypto-drainer/) | Microsoft Defender XDR | `launchctl bootstrap` registers the source-observed `com.apple.softwareupdated.plist` user LaunchAgent | Hunting |
| 9 August 2026 | [npm cooldown posture](./09-08-2026%20-%20npm-cooldown/) | Microsoft Defender XDR | Validate whether `.npmrc` file activity and initiating-process context are visible before designing state-based monitoring | Validation |
| 8 August 2026 | [UNC6671 / REDACT](./08-08-2026%20-%20unc6671/) | Microsoft Sentinel | SharePoint or OneDrive `FileAccessed` activity generated by source-observed scripting clients | Hunting |
| 7 August 2026 | [Interlock / GOLD EMBRACE](./07-08-2026%20-%20interlock/) | Microsoft Defender XDR | Volatility3 invokes the SAM hashdump or cached domain credential extraction plugin | Production candidate |
| 6 August 2026 | [CHAINDROP / Shai-Hulud](./06-08-2026%20-%20chaindrop/) | Microsoft Defender XDR | `node setup.mjs` launches Bun from a temporary `bun-dl-` path or against content under `node_modules` | Hunting |
| 5 August 2026 | [QuickFox / FDMTP](./05-08-2026%20-%20quickfox/) | Microsoft Defender XDR | `csmonitor.exe` loads a co-located `Microsoft.ServiceHosting.Tools.dll` from the source-observed `quickfox\updated` directory | Hunting |
| 4 August 2026 | [Mirage Kitten / NightLedger](./04-08-2026%20-%20mirage-kitten/) | Microsoft Defender XDR | `AppVShNotify.exe` loads a co-located `SspiCli.dll` from outside the Windows directory | Production candidate |
| 3 August 2026 | [N-central / CVE-2026-18577](./03-08-2026%20-%20n-central-cve-2026-18577/) | Microsoft Defender XDR | Source-confirmed `cloudflared` Windows service registration on N-central-managed endpoints | Hunting |
| 2 August 2026 | [STAC4749](./02-08-2026%20-%20stac4749/) | Microsoft Defender XDR | PowerShell retrieves an AppData payload and launches it with the source-observed `--token-raw` argument | Hunting |
| 31 July 2026 | [CVE-2023-23397](./31-07-2026%20-%20cve-2023-23397/) | Microsoft Defender XDR | CVE-specific MDO alert validation, public outbound SMB hunting, and WebDAV fallback evidence | Hunting |
| 31 July 2026 | [XMRig covert operations](./31-07-2026%20-%20xmrig-covert-ops/) | Microsoft Defender XDR | Root-context Linux `su` process execution for identity-distribution hunting | Hunting |
| 30 July 2026 | [Joyfill npm compromise](./30-07-2026%20-%20joyfill/) | Microsoft Defender XDR | Node.js file events against source-observed developer-tool runtime files | Hunting |
| 29 July 2026 | [Hermes / Hades](./29-07-2026%20-%20hermes-hades/) | Microsoft Defender XDR | Web-server connectivity to inventoried HiveServer2 or WebHDFS nodes | Validation |
| 28 July 2026 | [SourTrade](./28-07-2026%20-%20sourtrade/) | Microsoft Defender XDR | Browser-created Windows executable at least 600 MB in size | Hunting |
| 25 July 2026 | [Certighost / CVE-2026-54121](./25-07-2026%20-%20certighost/) | Microsoft Defender XDR | Enterprise CA SMB/LDAP chase traffic to non-approved Domain Controller destinations | Validation |
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
