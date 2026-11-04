# Validation record

## Status

`planned`

## Hypothesis

If a monitored Windows endpoint sends a network request whose captured URL contains both the documented Inno delivery marker `d=inno` and either `r=offer_execution` or `r=offer_execution_fail`, Microsoft Defender for Endpoint should preserve the paired markers in `DeviceNetworkEvents.RemoteUrl` and the hunt should return that row. A useful result requires consistent URL capture, populated investigative context and negative controls that contain only one marker but do not match. [C003][C006][C007][C009]

## Environment and authorization

- Authorized environment: isolated, organization-owned Windows 11 Enterprise test VM connected to a non-production Microsoft Defender for Endpoint tenant.
- Network target: organization-owned internal HTTP listener with no route to campaign infrastructure; use an internal DNS name such as `dtl-inno-test.local` and record the resolved address.
- Platform and version: record the exact Windows build, Defender sensor version, browser or test-client version, test account, proxy path and cloud-service health at execution time.
- Telemetry and retention: preserve the raw `DeviceNetworkEvents` rows, Advanced Hunting export, listener access log, query file hash and UTC test timeline.
- Safety boundary: no live campaign domain, installer, sample, downstream product, credential or persistence action is permitted. Requests carry only synthetic markers and a unique lab tag.

## Positive control

From the isolated VM, issue one harmless plain-HTTP request to the internal listener using a synthetic path such as:

```text
http://dtl-inno-test.local/callback?d=inno&r=offer_execution&dtl_test=20261104
```

Retain the exact client command, process tree, DNS resolution, listener log and matching Defender event. The procedure is planned and has not been executed.

## Negative controls

1. Send a request containing `d=inno` but an unrelated result, for example `r=status_check`.
2. Send a request containing `r=offer_execution` but an unrelated delivery value, for example `d=setup`.
3. Run a legitimate, organization-approved Inno Setup installer in the lab and confirm that ordinary installer or update traffic does not emit the paired campaign markers.
4. If proxy or endpoint tooling rewrites URLs, repeat the positive request through the same approved network path and retain both raw listener and Defender representations.

The first three negative controls must not satisfy both query predicates.

## Procedure

1. Record the VM snapshot, software versions, test identity, UTC time, proxy path and pre-test `DeviceNetworkEvents` coverage.
2. Execute the negative controls first and retain the listener and endpoint telemetry for each request or installer run.
3. Execute the paired-marker positive control once; do not contact external or campaign-controlled infrastructure.
4. Export the raw `DeviceNetworkEvents` rows and run `hunting.kql` unchanged over the test interval.
5. Verify exact `RemoteUrl` preservation and population of `Timestamp`, `DeviceId`, `DeviceName`, `ReportId`, `ActionType`, remote endpoint and initiating-process fields.
6. Compare query results with the known listener timeline and document any normalization, truncation, duplicate event or process-provenance gap.
7. In a separately authorized historical review, run the hunt over an approved period and resolve every match to an owner before any alert-design decision.

## Expected artifacts

- One listener request and corresponding `DeviceNetworkEvents` row containing the complete positive-control query string.
- A query result with the positive request plus sufficient device, remote endpoint and initiating-process context for investigation.
- Raw negative-control events, if captured, that contain only one campaign marker and are not returned by the query.
- No installer, child payload, scheduled task, software installation or monetization artifact, because the lab intentionally tests only URL observability and predicate specificity.

## Success, rejection and failure criteria

- Success: the paired-marker request is captured verbatim or with semantically equivalent token preservation, is returned by the unmodified query, all required identity fields are usable, and every single-marker or normal-installer control is excluded.
- Rejection: `RemoteUrl` omits or rewrites the required query content, either single-marker control matches, required event identity is unusable, or historical authorized activity produces overlap that cannot be bounded by provenance. Redesign or withdraw the hunt rather than adding unsupported correlation.
- Failure: sensor outage, proxy or listener misconfiguration, telemetry delay beyond retention, incorrect authorization, accidental external routing or incomplete artifact preservation. A failed run is inconclusive and must not change maturity or confidence.

## Cleanup

Delete synthetic DNS and listener configuration, remove temporary commands and logs from the VM, revert or destroy the lab snapshot according to policy, and retain only the approved telemetry export, listener log, hashes and execution notes. Verify that no external domain or campaign artifact was contacted.

## Results

Not performed. No dynamic, reproduced or detection-validated evidence is claimed.

## Promotion decision

Remain at `hunting` with Medium confidence until paired-marker capture is retained, all negative controls are excluded, projected fields are sufficiently complete and legitimate prevalence is measured. A callback match must never be promoted as proof that an offer installed, failed, persisted or monetized the device. [C008][C009][C013]
