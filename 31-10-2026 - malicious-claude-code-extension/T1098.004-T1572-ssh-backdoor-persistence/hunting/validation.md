# Validation record

## Status

`planned`

## Hypothesis

The query returns independent file, process and network evidence for controlled equivalents of the published backdoor behavior while preserving enough context to distinguish approved SSH forwarding and benign filename collisions.

## Environment and authorization

- Authorized lab endpoints: one Windows, one macOS and one Linux test device onboarded to Microsoft Defender for Endpoint.
- No connection to the published malicious infrastructure.
- Use generated benign files and an operator-owned SSH server.
- Preserve raw Advanced Hunting exports and timestamps.

## Positive controls

1. Create benign files with representative published names and a `.stk_` plus ten-hex filename.
2. Execute an authorized SSH reverse-forwarding command with the same option grammar against the operator-owned server.
3. Generate a network event to a reserved laboratory IP substituted into a temporary query copy.

## Negative controls

- Ordinary SSH interactive connection without reverse forwarding.
- Approved remote-development tunnel with documented destination and standard host-key verification.
- Benign files named `sysmon.cmd` outside extension or persistence context.

## Procedure

1. Verify table and field population on each operating system.
2. Run each positive control separately and retain the raw row.
3. Run negative controls and record collisions.
4. Measure 30-day prevalence for filenames and SSH grammar.
5. Confirm high- and medium-strength branches are correctly labeled.

## Results

Not performed. The package remains an untested hunting implementation.

## Promotion decision

Do not promote until at least one high-specificity branch or two independent medium-strength branches are reproducible and benign overlap is bounded.
