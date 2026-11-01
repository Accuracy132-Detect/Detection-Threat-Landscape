# Validation record

## Status

`planned`

## Migration note

This package was migrated from the legacy eight-page dossier into schema 2.0. The query conditions were preserved. Claim-level provenance must be reviewed against `references.txt` before any evidence type is promoted beyond `analyst-inference`.

## Hypothesis

The host executed the complete Evooo1Bot-associated downloader-to-shell pattern and requires immediate cron, URL, process-tree and network review.

## Environment and authorization

- Execute only in an authorized tenant, endpoint fleet, appliance lab, or log workspace.
- Preserve the raw matching event and connector/parser version.
- Do not contact source-published malicious infrastructure during testing.

## Positive controls

1. Generate a controlled equivalent of the principal observable without using live malicious infrastructure.
2. Confirm every required projected field is populated and retains its documented semantics.
3. Retain the raw event, query version, timestamp, test owner and expected result.

## Negative controls

- Approved administrative or software activity that overlaps the query conditions.
- A near-match that omits the most specific condition.
- An event outside the intended asset, identity or telemetry scope.

## Results

Not performed during repository migration. The package remains `Untested implementation sketch`.

## Promotion decision

Do not promote until controlled positives, representative negatives, benign prevalence, field semantics and operational ownership satisfy the promotion gate in `report.json`.
