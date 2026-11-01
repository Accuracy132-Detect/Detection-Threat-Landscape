# Validation record

## Status

`planned`

## Hypothesis

If a portable Bun or Java runtime executes a JavaScript or Java source operand from a numeric `KB`-prefixed directory under `%AppData%\Roaming`, Microsoft Defender for Endpoint should create a `DeviceProcessEvents` row matching the published runtime, command-line and `FolderPath` conditions. The result should be distinguishable from legitimate activity through package provenance, software ownership and the surrounding process timeline.

## Environment and authorization

- Authorized environment: isolated Windows test device enrolled in Microsoft Defender for Endpoint.
- Platform and version: record Windows, sensor, Defender portal and portable-runtime versions before testing.
- Telemetry source and retention: `DeviceProcessEvents`; retain the raw event and query output.
- Safety boundary: use a harmless local `.js` or `.java` file, no live malicious infrastructure, no credential access and no AD CS interaction.

## Positive control

1. Create `%AppData%\Roaming\KB12345` on the authorized test device.
2. Place an approved portable Bun or Java runtime and a harmless source file in the test directory.
3. Execute the runtime with the harmless `.js` or `.java` operand.
4. Preserve `Timestamp`, `DeviceId`, `DeviceName`, `ProcessUniqueId`, `ReportId`, hashes, complete command line and process version metadata.

## Negative controls

- Execute the same approved runtime and source file from a path outside `%AppData%\Roaming\KB<digits>\`.
- Execute the approved runtime from the `KB` path without a `.js` or `.java` operand.
- Execute an unrelated benign executable from the `KB` path with a `.js` or `.java` string in its command line.

## Procedure

1. Confirm that every queried and projected field is present in recent `DeviceProcessEvents` data.
2. Record the pre-test baseline and any existing matches.
3. Execute the authorized positive and negative controls.
4. Wait for ingestion, preserve the raw events and run `hunting.kql` unchanged.
5. Verify the positive result and the exclusion of all negative controls.
6. Run the unchanged hunt over 30 days, resolve every legitimate owner and record field-null rates.

## Results

Not performed. This package is an `Untested implementation sketch`; no `static-observed`, `dynamic-observed` or `detection-validated` evidence state is claimed.

## Success and rejection criteria

- Success: the controlled positive returns a complete, explainable row; all negative controls remain absent; required fields are populated; and historical overlap is bounded by durable provenance.
- Rejection: required fields are missing or semantically inconsistent, any negative control matches, or legitimate overlap cannot be separated without suppressing the core behavior.

## Promotion decision

Remain at `hunting` maturity until retained control evidence, measured prevalence, durable exclusions and an accountable detection owner satisfy the promotion gate in `report.json`.
