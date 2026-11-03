# Validation record

## Status

`planned`

## Hypothesis

If `ftp.exe` processes the documented `!` local-command facility on a monitored Windows endpoint, Microsoft Defender for Endpoint should record the resulting `cmd.exe` process with `InitiatingProcessFileName == "ftp.exe"`. A result is useful only if the direct lineage is reproducible, all required fields are populated and ordinary FTP activity without `!` does not match. [C006][C009]

## Environment and authorization

- Authorized environment: isolated, organization-owned Windows test VM connected to a non-production Microsoft Defender for Endpoint tenant.
- Platform and version: current supported Windows 11 Enterprise build with the native `ftp.exe`; record the exact build, Defender sensor version and cloud-service health at execution time.
- Telemetry source and retention: Microsoft Defender XDR `DeviceProcessEvents`; preserve raw positive and negative events, advanced-hunting export and query version.
- Safety boundary: no campaign payloads, live infrastructure, credentials or external targets. The test command writes only a uniquely named harmless marker under `%TEMP%`.

## Positive control

Create a local FTP command file containing a benign `!` command that invokes `cmd.exe /c` to write `DTL_FTP_SHELL_TEST.txt` under `%TEMP%`. Run the native FTP client against that local command file in the isolated VM, record the exact command and capture the complete process tree. The procedure is planned and has not been executed.

## Negative controls

1. Run the same FTP client with a command file that contains only normal FTP directives and no `!` token.
2. Launch the identical harmless `cmd.exe /c` marker command from `powershell.exe`, not `ftp.exe`.
3. Use an interactive FTP session for transfer-only commands, with no operating-system command escape.

None of the negative controls should satisfy both process-name conditions.

## Procedure

1. Record the VM snapshot, Windows build, Defender sensor version, test account, UTC time and pre-test DeviceProcessEvents coverage.
2. Execute the three negative controls and retain their raw process trees.
3. Execute the positive control once and verify only the harmless marker file is created.
4. Export the raw DeviceProcessEvents rows and run `hunting.kql` unchanged over the test interval.
5. Verify `FileName`, `InitiatingProcessFileName`, process unique identifiers, command lines, device identifiers and `ReportId` population.
6. Compare query results with the known test timeline; document false positives, false negatives and any lineage discrepancy.
7. In a separately approved production-data review, measure historical matches and resolve each to an accountable owner before promotion.

## Expected artifacts

- One `cmd.exe` process event with direct `ftp.exe` initiating-process context for the positive control.
- The complete parent and child command lines, stable process identifiers and compound event identity fields.
- A harmless `%TEMP%\DTL_FTP_SHELL_TEST.txt` marker whose creation time aligns with the process event.
- No query matches for the three negative controls.

## Success, rejection and failure criteria

- Success: the positive control is returned once with complete and internally consistent lineage; negative controls do not match; retained raw evidence supports the query semantics.
- Rejection: the FTP shell escape produces different process ancestry, required fields are absent or negative controls satisfy both conditions. Redesign or remove the hunt rather than broadening it speculatively.
- Failure: sensor outage, delayed telemetry beyond the collection window, test-command error, incorrect authorization or incomplete artifact retention. A failed run is inconclusive and must not change maturity.

## Cleanup

Delete the local command file and marker, remove the test VM from the isolated tenant if it was temporary, revert or destroy the snapshot according to lab policy, and retain only the approved telemetry export, hashes and execution notes.

## Results

Not performed. No dynamic, reproduced or detection-validated evidence is claimed.

## Promotion decision

Remain at `hunting` with Medium confidence until the positive and negative controls are retained, lineage is reproducible, field completeness is measured and legitimate FTP automation overlap is bounded.
