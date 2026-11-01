# Validation record

## Status

`planned`

Allowed values: `planned`, `in-progress`, `partially-validated`, `validated`, `rejected`.

## Hypothesis

State the observable hypothesis and the exact evidence required to support it.

## Environment and authorization

- Authorized environment:
- Platform and version:
- Telemetry source and retention:
- Safety boundary:

## Positive control

Describe a benign or isolated action expected to match.

## Negative controls

Describe representative legitimate activity expected not to match.

## Procedure

1. Preserve the baseline.
2. Execute the authorized control.
3. Capture raw telemetry.
4. Run the query unchanged.
5. Record false negatives, false positives and missing context.

## Results

Not performed. Do not change evidence maturity until artifacts are retained and reviewed.

## Promotion decision

Remain at the current maturity until the success criteria in `report.json` are satisfied.
