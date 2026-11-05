# Validation record

## Status

`planned`

## Hypothesis

If a monitored Windows endpoint executes an Adobe-labelled helper named `SogouComMgr.exe` from a `SogouInput\Components` directory and it loads a co-located module named `libcef.dll`, Microsoft Defender for Endpoint should record the complete relationship in one `DeviceImageLoadEvents` row and the hunt should return it. A useful result requires image-load coverage, populated company metadata, reliable folder equality and negative controls that each break one semantic condition. [C005][C008][C009][C010][C013]

## Environment and authorization

- Authorized environment: isolated, organization-owned Windows 11 Enterprise VM connected to a non-production Microsoft Defender for Endpoint tenant.
- Platform and version: record the exact Windows build, Defender sensor version, test-loader build, DLL build, test identity and cloud-service health.
- Test artifacts: benign internally built loader and no-op DLL only. Apply synthetic test version metadata identifying Adobe solely to exercise the documented field, and mark both files as laboratory artifacts.
- Telemetry and retention: preserve raw `DeviceImageLoadEvents`, Advanced Hunting export, both test binaries and hashes, build manifest, query hash, UTC timeline and sensor health evidence.
- Safety boundary: no live Sogou installer, campaign sample, campaign hash, malicious DLL, external staging host, DNS manipulation, persistence or credential is permitted.

## Positive control

Under a synthetic path such as `C:\DTL-Lab\SogouInput\Components\`, place the benign loader as `SogouComMgr.exe` and a no-op module as `libcef.dll`. The loader must carry controlled version metadata whose company field contains `Adobe` and must load the DLL from the same directory. Execute once from the isolated VM and retain the full process, file and image-load evidence.

The procedure is planned and has not been executed. Synthetic metadata must not be represented as an Adobe signature or as vendor-issued software.

## Negative controls

1. Repeat with company metadata that does not contain `Adobe` while preserving the same filenames and path.
2. Repeat with a no-op module named `dtl_test.dll` instead of `libcef.dll` while preserving the loader identity and path.
3. Repeat from `C:\DTL-Lab\NeutralComponents\`, outside a `SogouInput\Components` path, while preserving the filenames and metadata.
4. Run an approved legitimate application that loads its ordinary `libcef.dll` and confirm the absent Sogou loader/path relationship excludes it.

Each semantic negative must be captured by endpoint telemetry where applicable but must not satisfy the complete query.

## Procedure

1. Record VM snapshot, software versions, test identity, sensor health and pre-test `DeviceImageLoadEvents` coverage with a known harmless DLL load.
2. Build or verify the benign loader and DLL, retain source/build provenance and hashes, and inspect the intended version metadata before execution.
3. Execute the three semantic negatives and the legitimate CEF control first; export raw events and note any missing fields.
4. Execute the synthetic positive once from the designated path without external network access.
5. Export the raw `DeviceImageLoadEvents` row and run `hunting.kql` unchanged over the test interval.
6. Verify `FileName`, both folder paths, `InitiatingProcessFileName`, `InitiatingProcessVersionInfoCompanyName`, `Timestamp`, `DeviceName`, `ReportId` and `InitiatingProcessUniqueId` against the known timeline.
7. In a separately authorized historical review, run the hunt over an approved period and resolve every match to an owner, installer and file provenance before any alert-design decision.

## Expected artifacts

- One positive-control `DeviceImageLoadEvents` row containing the exact loader, module, co-location and synthetic company-metadata relationship.
- Raw negative-control events, where the sensor records them, that each fail the intended predicate.
- Hashes, build manifest, version-resource inspection, process execution timeline and query result export.
- No DNS hijack, exploit, persistence, implant, external connection or campaign outcome, because the lab intentionally tests only endpoint observability and predicate specificity.

## Success, rejection and failure criteria

- Success: the unmodified query returns the synthetic positive with complete investigative context, every semantic negative is excluded for the intended reason and historical overlap is bounded and attributable.
- Rejection: image loads are absent, company metadata is null or inconsistent, folder equality is not reliable, a negative control matches, or legitimate historical overlap cannot be durably separated. Redesign or withdraw the hunt rather than adding unsupported conditions.
- Failure: sensor outage, stale policy, telemetry delay beyond retention, incorrect build metadata, path-creation error, incomplete artifact preservation or any departure from the authorization boundary. A failed run is inconclusive and must not change maturity or confidence.

## Cleanup

Stop the test process, delete the synthetic loader, DLL and directory tree, revert or destroy the VM snapshot according to policy, and retain only approved source, build manifest, hashes, telemetry exports and execution notes. Verify that no external or campaign-controlled system was contacted.

## Results

Not performed. No dynamic, reproduced or detection-validated evidence is claimed.

## Promotion decision

Remain at `hunting` with Medium confidence until the positive, all semantic negatives, field-population checks and historical prevalence review are retained. A match must never be promoted as proof of malicious content, valid signing, DNS hijacking, exploitation, DarkVigil execution, compromise or attribution. [C009][C010]
