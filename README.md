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
│   └── T1218.011-clickfix-multi-stage-execution/production-candidates/
├── 22-07-2026 - clicklock/
│   └── T1562.001-T1056.002-T1543.001-clicklock-macos-kill-loop/production-candidates/
├── 22-07-2026 - hollowgraph/
│   ├── T1102.002-T1071.001-hollowgraph-calendar-c2/production-candidates/
│   └── T1102.002-T1071.001-hollowgraph-future-calendar-access/hunting/
├── 22-07-2026 - starland-rat/
│   └── T1059.006-T1036.008-pythonw-license-loader/hunting/
├── 22-07-2026 - studio-5000-acd-path-traversal/
│   └── NO-MITRE-MAPPING-studio-5000-novel-write-path/hunting/
├── 22-07-2026 - teleshim/
│   └── T1053.005-T1574.002-feedback-scheduled-task/hunting/
├── 23-07-2026 - fakeagent-sectoprat/
│   └── T1574.002-T1036-T1053.005-signed-application-dll-sideloading/hunting/
├── 24-07-2026 - msarat/
│   └── T1219-browser-cdp-remote-debugging/production-candidates/
├── 24-07-2026 - zimreaper/
│   └── T1098-zimbra-app-password-persistence/hunting/
├── 25-07-2026 - certighost/
│   └── T1649-adcs-chase-to-non-dc/validation/
├── 28-07-2026 - sourtrade/
│   └── T1204.002-browser-created-large-executable/hunting/
├── 29-07-2026 - hermes-hades/
│   └── T1505.003-T1059-webserver-to-hadoop-service/validation/
├── 30-07-2026 - joyfill/
│   └── T1195.002-T1059.007-T1546-developer-tool-runtime-modification/hunting/
├── 31-07-2026 - xmrig-covert-ops/
│   └── T1078-T1562.001-T1564.013-root-context-user-switching/hunting/
├── 31-07-2026 - cve-2023-23397/
│   └── T1187-outlook-forced-ntlm-authentication/hunting/
├── 02-08-2026 - stac4749/
│   └── T1059.001-T1105-teams-vishing-powershell-payload/hunting/
├── 03-08-2026 - n-central-cve-2026-18577/
│   └── T1543.003-cloudflared-service-registration/hunting/
├── 04-08-2026 - mirage-kitten/
│   └── T1574.001-appvshnotify-sspicli-sideloading/production-candidates/
├── 05-08-2026 - quickfox/
│   └── T1574.001-fdmtp-csmonitor-dll-sideloading/hunting/
├── 06-08-2026 - chaindrop/
│   └── T1059.007-node-setup-bun-execution/hunting/
├── 07-08-2026 - interlock/
│   └── T1003.002-T1003.005-volatility-credential-plugins/production-candidates/
├── 08-08-2026 - unc6671/
│   └── T1213.002-scripted-sharepoint-file-access/hunting/
├── 09-08-2026 - npm-cooldown/
│   └── T1195.001-npmrc-file-event-coverage/validation/
├── 10-08-2026 - mac-crypto-drainer/
│   └── T1543.001-softwareupdated-launchagent-bootstrap/hunting/
├── 11-08-2026 - gunra/
│   └── T1490-wmic-shadowcopy-deletion/production-candidates/
├── 12-08-2026 - operation-dream-job/
│   └── T1204-securitypdf-temp-child-execution/hunting/
├── 13-08-2026 - head-mare/
│   └── T1543.003-phantomgraph-temp-batch-services/hunting/
├── 14-08-2026 - armored-likho/
│   └── T1543.003-still-toolkit-service-installation/hunting/
├── 15-08-2026 - honeymyte/
│   └── T1543.003-coolclient-msagent-driver-service/hunting/
├── 15-08-2026 - cve-2026-8452/
│   └── T1190-netscaler-nsppe-crash-signals/validation/
├── 16-08-2026 - evooo1bot/
│   └── T1059.004-T1053.003-cron-download-pipe-shell/hunting/
├── 17-08-2026 - patchcord/
│   └── T1060-beaconbrowserhijack-run-key/hunting/
├── 18-08-2026 - jewelbug/
│   └── T1176-com-microsoft-runedge-native-messaging-host/hunting/
├── 19-08-2026 - medusa/
│   └── T1547.005-T1003.001-mimilib-lsa-security-package/production-candidates/
├── 20-08-2026 - grandoreiro/
│   └── T1574.002-dff-dupfdll-mingwm10-sideload/hunting/
├── 21-08-2026 - uat-10147/
│   └── T1685-iis-defender-exclusion/hunting/
├── 22-08-2026 - cve-2026-73570/
│   └── T1190-zimbra-service-status-log-signals/validation/
├── 23-08-2026 - rust-crate-supply-chain/
│   └── T1195.001-proc-macro1-cargo-cache/hunting/
├── 24-08-2026 - btr-reforged/
│   └── T1564.004-btr-cli-driver-dat-ads/validation/
├── 25-08-2026 - fake-codex-clickfix/
│   └── T1553.001-xattr-tmp-helper-quarantine-clear/hunting/
├── 27-08-2026 - spectre/
│   └── T1543.002-hardware-monitor-systemd-persistence/hunting/
├── 29-08-2026 - aurora/
│   └── T1486-sap-encryptor-flags/hunting/
├── 30-08-2026 - terminalfix/
│   └── T1574.002-lockscreencontentserver-dui70-sideload/hunting/
├── 31-08-2026 - darklantern/
│   └── NO-MITRE-MAPPING-udp-9992-firewall-visibility/validation/
├── 01-09-2026 - valleyrat/
│   └── T1027.013-qnwallpaper-peloader/hunting/
├── 02-09-2026 - noderabbit/
│   └── T1547.001-microsoftedgeupdate-run-key/hunting/
├── 05-09-2026 - ascii-smuggling/
│   └── T1566-T1027-finance-envelope-fingerprint/hunting/
├── 06-09-2026 - rogue-screenconnect/
│   └── T1059.005-T1219.002-screenconnect-wscript-vbs-chain/hunting/
├── 07-09-2026 - teams-helpdesk-intrusion/
│   └── T1059.007-T1036-node-wscript-localappdata-loader/hunting/
├── 09-09-2026 - clearfake/
│   └── T1218.011-webdav-rundll32-ordinal/hunting/
├── 11-09-2026 - gtg-20006/
│   └── NO-MITRE-MAPPING-actor-controlled-device-registration/validation/
├── 12-09-2026 - papercut-agentic-campaign/
│   ├── T1098.007-domain-admins-membership-addition/production-candidates/
│   └── T1003.004-registry-hive-staging/hunting/
├── 13-09-2026 - bluemoon/
│   └── T1059.003-T1105-browser-cmd-curl-chain/production-candidates/
├── 13-09-2026 - cisco-fmc-exploitation/
│   └── T1059-package-info-license-tmp/hunting/
├── 14-09-2026 - passkey-cloud-compromise/
│   ├── T1098.005-mfa-method-addition/hunting/
│   └── T1213.002-python-httpx-cloud-collection/hunting/
├── 15-09-2026 - gitlab-cve-2026-85706/
│   └── T1190-T1552.001-anonymous-file-path-secret-target/production-candidates/
├── 16-09-2026 - chosen-brick/
│   └── T1547.001-spaced-windows-run-key/hunting/
├── 17-09-2026 - amos/
│   └── T1059.004-T1036-hidden-application-support-execution/hunting/
├── 17-09-2026 - ghostcode/
│   └── T1528-device-code-python-requests-correlation/hunting/
├── 18-09-2026 - nighteagle/
│   └── T1021.001-T1090-rdp-virtual-channel-schema/validation/
├── 22-09-2026 - waterplum/
│   └── T1204.002-vscode-trusted-project-child-process/validation/
├── 24-09-2026 - exvicy/
│   └── T1059.001-T1105-clickfix-invokescript-download/hunting/
├── 25-09-2026 - cleangulp/
│   └── T1105-T1053.005-localappdata-microsoft-ime-file/hunting/
├── 26-09-2026 - carbonato/
│   └── T1611-T1059.004-nsenter-pid1-host-namespace/hunting/
├── 27-09-2026 - defender-cve-2026-50656/
│   └── NO-MITRE-MAPPING-defender-engine-exposure/validation/
├── 28-09-2026 - payload-ransomware/
│   └── T1484.001-domain-root-gpo-change/validation/
├── 29-09-2026 - peoplesoft-cve-2026-35273/
│   └── T1059.003-T1059.004-weblogic-java-shell-child/hunting/
├── 30-09-2026 - dual-rmm-abuse/
│   └── T1219-T1059.001-T1218.007-msp360-powershell-msiexec/hunting/
├── 30-09-2026 - star-blizzard-redflick/
│   └── T1021.004-T1059.003-ssh-local-command/hunting/
├── 01-10-2026 - storm-3168/
│   └── T1485-azure-multi-resource-deletion/hunting/
├── 02-10-2026 - zimbra-cve-2026-73570/
│   └── T1190-T1059.004-swatchdog-snmp-shell-injection/production-candidates/
└── 05-10-2026 - citrix-netscaler-cve-2026-88771-88772/
    ├── T1190-T1059.004-netscaler-log-poisoning-shell-injection/production-candidates/
    └── T1190-netscaler-dtls-fragment-volume/validation/
        ├── validation.kql
        ├── references.txt
        └── threat-analysis.pdf
```

## Threat catalog

| Date | Threat | Primary platform | Content | Status |
|---|---|---|---|---|
| 5 October 2026 | [Citrix NetScaler CVE-2026-88772](./05-10-2026%20-%20citrix-netscaler-cve-2026-88771-88772/T1190-netscaler-dtls-fragment-volume/validation/) | Microsoft Sentinel | **[T1190] DTLS fragment-volume validation** — identifies the exact public laboratory traffic shape of 120 records or 176,640 bytes toward inventoried NetScaler destinations; aggregated CEF cannot establish malformed fragments, memory corruption, RCE, or DoS | Validation |
| 5 October 2026 | [Citrix NetScaler CVE-2026-88771](./05-10-2026%20-%20citrix-netscaler-cve-2026-88771-88772/T1190-T1059.004-netscaler-log-poisoning-shell-injection/production-candidates/) | Microsoft Sentinel | **[T1190][T1059.004] Exploit-shaped log poisoning** — detects the source-documented fake Pitboss/NSPPE failure grammar plus shell metacharacters in untruncated NetScaler logs; a match supports an exploitation attempt, not deferred command execution or compromise | Production candidate |
| 2 October 2026 | [Zimbra CVE-2026-73570](./02-10-2026%20-%20zimbra-cve-2026-73570/) | Microsoft Defender XDR | **[T1190][T1059.004] Zimbra swatchdog/SNMP shell injection boundary** — Perl `.swatchdog_script` launches a Unix shell containing the documented `snmptrap -c` grammar, Zimbra service markers, and shell metacharacters; a match confirms shell-mediated execution but not downstream payload outcomes | Production candidate |
| 1 October 2026 | [Storm-3168](./01-10-2026%20-%20storm-3168/) | Microsoft Sentinel | **[T1485] Azure control-plane multi-resource deletion** — hunts administrative deletion operations for Storage Accounts, Key Vaults, Function Apps, App Services, and App Service plans; a match does not prove compromise, successful deletion, data loss, or Storm-3168 attribution | Hunting |
| 30 September 2026 | [Dual-RMM abuse](./30-09-2026%20-%20dual-rmm-abuse/) | Microsoft Defender XDR | **[T1219][T1059.001][T1218.007] MSP360 RMM Agent to PowerShell and MSIExec** — MSP360 RMM Agent launches PowerShell and PowerShell with an MSP360 parent starts an MSI from Temp; a match does not prove phishing, malicious ScreenConnect use, credential access, or attribution | Hunting |
| 30 September 2026 | [Star Blizzard / RedFlick](./30-09-2026%20-%20star-blizzard-redflick/) | Microsoft Defender XDR | **[T1021.004][T1059.003] SSH PermitLocalCommand to Local CMD Execution** — `ssh.exe` receives both `PermitLocalCommand=yes` and `LocalCommand=cmd.exe`; a match does not prove a successful connection, MSI execution, CosmicPulse installation, or actor attribution | Hunting |
| 29 September 2026 | [Oracle PeopleSoft CVE-2026-35273](./29-09-2026%20-%20peoplesoft-cve-2026-35273/) | Microsoft Defender XDR | Source-observed `cmd.exe`, `sh`, or `bash` spawned directly by a WebLogic Java process on an explicitly inventoried PeopleSoft web-tier node; a match does not prove exploitation, web-shell deployment, data theft, or UNC6240 attribution | Hunting |
| 28 September 2026 | [PAYLOAD ransomware](./28-09-2026%20-%20payload-ransomware/) | Microsoft Sentinel | Validates ingestion and raw representation of Active Directory Event IDs 5136/5137 before detecting source-observed `groupPolicyContainer` creation or domain-root `gPLink` changes; a row does not prove malicious GPO activity, impact, or attribution | Validation |
| 27 September 2026 | [Microsoft Defender CVE-2026-50656](./27-09-2026%20-%20defender-cve-2026-50656/) | Microsoft Defender XDR | Validates whether Defender Vulnerability Management currently reports devices exposed to the local privilege-escalation vulnerability fixed in Windows Antivirus Engine/Platform 1.1.26060.3008 / 4.18.26060.3008; a row is assessment state, not evidence of exploitation | Validation |
| 26 September 2026 | [CARBONATO](./26-09-2026%20-%20carbonato/) | Microsoft Defender XDR | Source-recovered `nsenter -t 1 -m -u -n -i sh -c id` execution from a privileged container to enter PID 1 host namespaces; a match does not prove exposed-Docker exploitation, successful host entry, persistence, C2, malware identity or attribution | Hunting |
| 25 September 2026 | [CLEANGULP](./25-09-2026%20-%20cleangulp/) | Microsoft Defender XDR | Source-observed `MicrosoftIME.exe` file activity under the Microsoft IME-like LocalAppData directory; a match does not prove exploitation, execution, scheduled-task persistence, C2, malware identity or attribution | Hunting |
| 24 September 2026 | [Exvicy](./24-09-2026%20-%20exvicy/) | Microsoft Defender XDR | Source-observed PowerShell download with `irm` followed by in-memory execution through `ExecutionContext.InvokeCommand.InvokeScript`; a match does not prove ClickFix delivery, malicious content, successful execution or attribution | Hunting |
| 22 September 2026 | [WaterPlum / Contagious Interview](./22-09-2026%20-%20waterplum/) | Microsoft Defender XDR | Validates whether processes launched by trusted Visual Studio Code project tasks are represented with a direct `Code.exe` parent and sufficient command-line context; results are normal developer activity until provenance and task evidence prove otherwise | Validation |
| 18 September 2026 | [NightEagle](./18-09-2026%20-%20nighteagle/) | Microsoft Sentinel | Validates ingestion and raw field representation for RdpCoreTS Operational Event IDs 132 and 148 before any channel-name detection; a match proves telemetry availability, not `rdp2tcp` use or attribution | Validation |
| 17 September 2026 | [GhostCode](./17-09-2026%20-%20ghostcode/) | Microsoft Sentinel | Successful device-code authentication followed by non-interactive `python-requests` token use for the same UPN within the source-supported 10-minute window; a match does not prove compromise | Hunting |
| 17 September 2026 | [Atomic macOS Stealer](./17-09-2026%20-%20amos/) | Microsoft Defender XDR | Source-observed `AccountsHelper` or `mdworker_shared` execution from hidden Apple-lookalike Application Support paths; mutable artifact coverage, not durable family detection | Hunting |
| 16 September 2026 | [CHOSEN BRICK](./16-09-2026%20-%20chosen-brick/) | Microsoft Defender XDR | Run-key value pointing to the source-observed actor-created `C:\Windows \SysWOW64` lookalike directory, with a literal space after `Windows`; a match does not establish malware execution, C2, collection, or attribution | Hunting |
| 15 September 2026 | [GitLab CVE-2026-85706](./15-09-2026%20-%20gitlab-cve-2026-85706/) | Splunk | Official high-signal anonymous multipart request shape in raw `api_json.log`: empty file part, `content-type`, `file.path`, and a configuration or secrets target; a match proves an attempt, not a successful read | Production candidate |
| 14 September 2026 | [Passkey-themed cloud compromise](./14-09-2026%20-%20passkey-cloud-compromise/) | Microsoft Defender XDR | New MFA device-record deltas in `CloudAppEvents`, plus source-observed high-volume SharePoint/OneDrive access using `python-httpx`; both require ownership and benign-automation validation | Hunting |
| 13 September 2026 | [BlueMoon exploit kit](./13-09-2026%20-%20bluemoon/) | Microsoft Defender XDR | Browser grandparent `chrome.exe` or another supported Chromium browser launches `cmd.exe`, which starts `curl.exe` with an output path under Temp; a match does not prove exploitation or payload execution | Production candidate |
| 13 September 2026 | [Cisco FMC exploitation](./13-09-2026%20-%20cisco-fmc-exploitation/) | Microsoft Defender XDR | Source-observed execution of `/usr/local/sf/bin/package_info.pl /var/tmp/license.tmp --lsm`; platform update workflows can overlap and every result requires appliance-owner validation | Hunting |
| 12 September 2026 | [PaperCut agentic campaign](./12-09-2026%20-%20papercut-agentic-campaign/) | Microsoft Sentinel / Defender XDR | Event 4728 additions to Domain Admins identified by RID 512, plus a campaign-specific hunt for source-observed SYSTEM/SECURITY hive staging with reg.exe and certutil.exe | Production candidate + Hunting |
| 11 September 2026 | [GTG-20006 / actor-controlled device registration](./11-09-2026%20-%20gtg-20006/) | Microsoft Sentinel | Validate how source-observed actor-controlled device registration is represented in Microsoft Entra `AuditLogs`; a match does not establish malicious ownership, persistence or compromise | Validation |
| 9 September 2026 | [ClearFake / Amatera](./09-09-2026%20-%20clearfake/) | Microsoft Defender XDR | Source-observed `rundll32.exe` execution of disguised DLLs directly from WebDAV UNC paths through export ordinal `#1`; a match does not establish ClickFix delivery, payload execution or C2 | Hunting |
| 7 September 2026 | [Teams helpdesk intrusion](./07-09-2026%20-%20teams-helpdesk-intrusion/) | Microsoft Defender XDR | Source-observed WScript bootstrap launches portable Node.js from LocalAppData while the child command line omits a JavaScript file; a match does not establish Teams contact, implant decryption, persistence or C2 | Hunting |
| 6 September 2026 | [Rogue ScreenConnect](./06-09-2026%20-%20rogue-screenconnect/) | Microsoft Defender XDR | Source-observed `ScreenConnect.WindowsClient.exe` parent spawning `wscript.exe` with numbered `1.vbs` through `4.vbs` stages; a match requires authorized-RMM validation and does not prove client modification or propagation | Hunting |
| 5 September 2026 | [ASCII smuggling phishing campaign](./05-09-2026%20-%20ascii-smuggling/) | Microsoft Defender XDR | Source-observed finance-token header/P2 domain combined with an operator-shaped envelope/P1 domain; the hunt does not inspect Unicode body content or prove compromise | Hunting |
| 2 September 2026 | [NodeRabbit / Mirage Kitten](./02-09-2026%20-%20noderabbit/) | Microsoft Defender XDR | Source-observed `MicrosoftEdgeUpdate` Run value referencing both `nodew.exe` and `msedge_update.js`; a match does not establish logon execution, implant activity or C2 | Hunting |
| 1 September 2026 | [ValleyRAT](./01-09-2026%20-%20valleyrat/) | Microsoft Defender XDR | Exact `PeLoader` filename, QNWallpaper version-path prefix and source-observed MD5 for exposure hunting; a match does not establish decryption, memory loading or execution | Hunting |
| 31 August 2026 | [DARKLANTERN](./31-08-2026%20-%20darklantern/) | Microsoft Sentinel | Validate perimeter CEF visibility for UDP traffic directed to the source-documented router listener on port 9992; a match does not establish protocol payload, implant presence, or compromise | Validation |
| 30 August 2026 | [TerminalFix](./30-08-2026%20-%20terminalfix/) | Microsoft Defender XDR | Source-observed `LockScreenContentServer.exe` loading a co-located `dui70.dll` outside the standard Windows SystemApps location | Hunting |
| 29 August 2026 | [Aurora ransomware](./29-08-2026%20-%20aurora/) | Microsoft Defender XDR | Source-recovered Windows `sap.exe` encryptor execution with compiled Aurora flag patterns | Hunting |
| 27 August 2026 | [SPECTRE / UAT-10147](./27-08-2026%20-%20spectre/) | Microsoft Defender XDR | Source-observed `hardware-monitor.service` systemd persistence artifact on Linux servers | Hunting |
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
