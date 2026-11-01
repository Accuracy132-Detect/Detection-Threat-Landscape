# Validation record

## Status

`planned`

## Hypothesis

Microsoft Entra AuditLogs contains stable initiating service-principal, assigned principal and directory-role identifiers that can support self-assignment or related-principal detection after tenant-specific schema validation.

## Environment and authorization

- Use an authorized Entra test tenant connected to Microsoft Sentinel.
- Use low-risk temporary role assignments approved by the tenant owner.
- Preserve complete raw `InitiatedBy`, `TargetResources` and `modifiedProperties` values.
- Remove test assignments immediately after evidence collection.

## Positive controls

- Service principal assigns an approved test role to itself, if the platform permits the authorized scenario.
- Service principal assigns an approved test role to a related test principal.
- Direct and eligible/PIM role assignment paths.

## Negative controls

- Human administrator assigns a role to a different principal.
- PIM activation by an authorized user.
- Approved automation assigns a role to an unrelated managed identity.

## Procedure

1. Run the validation query across existing retention and export representative events.
2. Resolve every initiating and target identifier against Entra inventory.
3. Execute authorized positive and negative controls.
4. Compare direct, eligible and PIM representations.
5. Record stable equality fields, role identifiers and unavoidable ambiguity.

## Results

Not performed. Candidate self-assignment output is diagnostic only and must not be used as an alert.

## Promotion decision

Remain at validation maturity until raw samples demonstrate stable identifier and role semantics across supported workflows.
