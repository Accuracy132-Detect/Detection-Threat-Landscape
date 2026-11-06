# Validation record

## Status

`planned`

## Hypothesis

If Microsoft Defender for Office 365 assigns a threat verdict to an inbound message, an organization- or user-level policy records `Allow`, and the service records `Delivered`, the same recipient/message event should expose all four predicates in `EmailEvents` and the unmodified hunt should return it. A useful result also requires recoverable policy ownership, current delivery state and bounded legitimate overlap. [C004][C005][C006][C007][C008][C009]

## Environment and authorization

- Authorized environment: organization-owned, isolated Microsoft 365 test tenant with no production recipients, forwarding or external trust relationship.
- Platform and license: Microsoft Defender XDR with Microsoft Defender for Office 365 Plan 2; record tenant identifier, service health, policy versions and test identities.
- Telemetry and retention: preserve raw `EmailEvents`, policy audit/change records, message entity export, Threat Explorer evidence, query hash and UTC timeline.
- Safety boundary: use only Microsoft-supported harmless simulations or an internally approved benign message. Do not send live phishing, credential-harvesting content, malware, weaponized attachments or messages to real users.
- Fallback: if no supported simulation safely populates `ThreatTypes`, perform only the passive historical review and keep the package at hunting maturity.

## Positive control

In the isolated tenant, create a temporary allow entry narrowly scoped to a dedicated test sender and recipient. Use a Microsoft-supported harmless simulation only after confirming in a separate blocked delivery that it produces a non-empty `ThreatTypes` value. Send one controlled copy through the temporary allow path. Preserve evidence that the same event records `EmailDirection == "Inbound"`, non-empty `ThreatTypes`, `OrgLevelAction == "Allow"` or `UserLevelAction == "Allow"`, and `DeliveryAction == "Delivered"`.

The procedure is planned and has not been executed. If the simulation bypasses normal filtering or produces special-case telemetry, it cannot serve as validation evidence.

## Negative controls

1. **Allowed benign mail:** keep the temporary allow entry but send an ordinary benign message expected to have empty `ThreatTypes`; it must be excluded by the verdict predicate.
2. **Detected, not allowed:** send the supported harmless simulation with the allow entry removed and verify the service blocks, junks or quarantines it; it must be excluded by the Allow predicate.
3. **Detected and allowed, not delivered:** only if the platform supports a safe policy combination, preserve a harmless simulated row with an allow action but a non-`Delivered` outcome; it must be excluded by `DeliveryAction`.
4. **Passive historical control:** inspect ordinary delivered mail and ordinary detected mail to confirm neither group satisfies the complete four-field relationship by default.

Do not modify production policy to manufacture a negative control. If a safe third control cannot be produced, record that limitation rather than substituting an unsupported event.

## Procedure

1. Record tenant, license, service health, retention, test identities, policy state and the exact query hash before any change.
2. Run a 30-day passive baseline and export every match with `NetworkMessageId`, recipient, policy, verdict, initial delivery and latest delivery fields.
3. Resolve each historical match to a policy owner and classify it as necessary exception, approved simulation, false-positive verdict, stale control or unexplained delivery.
4. In the isolated tenant, confirm the supported harmless simulation generates `ThreatTypes` while blocked; retain that raw event.
5. Create the narrowly scoped, time-bounded allow entry and run the allowed benign negative followed by the single simulated positive.
6. Run `hunting.kql` unchanged over the test interval and verify every projected field against the policy and message evidence.
7. Execute the remaining safe negatives, compare initial with latest delivery state and document any delay, null field or special simulation behavior.
8. Remove the allow entry, purge the test messages, verify rollback, export the final policy state and retain only approved evidence.

## Expected artifacts

- One safe positive `EmailEvents` row containing inbound direction, a non-empty threat verdict, explicit organization- or user-level `Allow`, and `Delivered` initial action.
- Raw negative rows or documented absence showing which single predicate excluded each control.
- Policy creation/removal audit records, message entity evidence, latest delivery state, query output and UTC test timeline.
- A 30-day prevalence ledger with policy owners and analyst dispositions.
- No credential collection, malware execution, real recipient interaction or compromise outcome.

## Success, rejection and failure criteria

- Success: the unmodified query returns the harmless positive with complete policy and message context, each available negative is excluded for the intended reason, and historical overlap is bounded and accountable.
- Rejection: a required field is absent or semantically inconsistent; simulation mail is represented through a special path; necessary exceptions dominate without durable ownership; or latest state and policy provenance cannot be recovered. Keep hunting or withdraw it rather than adding unsupported conditions.
- Failure: licensing or service outage, unsafe simulation material, policy rollback failure, telemetry delay beyond retention, accidental production routing, missing audit evidence or loss of raw events. A failed run is inconclusive and must not change maturity or confidence.

## Cleanup

Remove the temporary allow entry, purge the test messages, revoke any test-only sender configuration, verify no forwarding or external access exists, restore the baseline policy set and retain only approved policy records, raw telemetry, query output and execution notes.

## Results

Not performed. No dynamic, reproduced or detection-validated evidence is claimed.

## Promotion decision

Remain at `hunting` with Medium confidence until the safe positive, available semantic negatives, 30-day prevalence, field-completeness checks, policy ownership and current-state triage are retained. A result must never be promoted as proof of sender spoofing, failed authentication, recipient action, compromise or a specific ATT&CK technique. [C007][C008][C009][C010]
