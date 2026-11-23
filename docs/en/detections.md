# Detection catalog

[Русская версия](../ru/detections.md) · [Work screens](user-guide.md)

This catalog covers ten signals in source release `a164f00`. Work with
already collected records. In [Problems](problems.md), open the finding
and review **Evidence**. In the [Event journal](event-journal.md), confirm
the event's time, domain, source, log and record identity. Keep source gaps
and the scope of your access in mind. Priorities below come from the
rule code or event catalog. Automatic publication depends on eligible
evidence and the applicable policy for the source.

## 1. Password guessing against one account

- **Signal.** Repeated password failures for one account from the same
  source. Evidence can include Windows 4625, 4771 and 4776.
- **Priority.** Medium for the released password rule.
- **Operator response.** Confirm the source and ask whether a recent password
  change or a stale application credential explains the failures. Check for
  successful sign-ins. Escalate unexpected activity for containment or
  credential rotation through the account owner.

## 2. Password guessing across many accounts

- **Signal.** Password failures from one source touch multiple accounts.
  Review the distinct accounts and the common source. The event records
  support the pattern of failures without revealing password values.
- **Priority.** Medium for the released password rule.
- **Operator response.** Identify the source host, check for a shared
  application fault, list the affected accounts and check for successful
  sign-ins. Coordinate containment if the source is unauthorized.

## 3. Successful sign-in after guessing

- **Signal.** A qualifying 4624 success follows matched password failures
  from the same source for the affected account. The released rules raise
  the underlying password finding when the evidence supports the sequence.
- **Priority.** Critical.
- **Operator response.** Start the account incident process promptly.
  Preserve the matched records, coordinate a password reset and session
  revocation, and review [Domain changes](domain-changes.md) for actions
  after the sign-in.

See [password evidence and severity](../../server-dotnet/src/Sli.Server/Semantic/Password/PasswordSignal.cs)
and [published priority](../../server-dotnet/src/Sli.Server/Semantic/Risk/PasswordRiskPublication.cs) for signals 1–3.

## 4. An account requested tickets for many services

- **Signal.** Successful 4769 records show one account requesting service
  tickets for multiple services with RC4 encryption. The detector checks
  distinct services and the source.
- **Priority.** High.
- **Operator response.** Compare the requester and services with approved
  inventory or maintenance. Preserve the relevant records and escalate
  unexpected access to the directory and service owners. Coordinate a
  review of service account credentials and encryption settings.

## 5. Ticket issued without Kerberos pre-authentication

- **Signal.** A successful 4768 record for the account has no Kerberos
  pre-authentication. Check the ticket outcome and the account.
- **Priority.** High for the ticket event rule.
- **Operator response.** Ask the account owner to verify whether the setting
  is approved. If it is unexpected, coordinate restoration of the approved
  account setting, credential rotation and review of recent sign-ins.

## 6. Account added to a privileged group

- **Signal.** Event 4728, 4732 or 4756 records an addition to a privileged
  group recognized by the rule. Compare the group and member identities.
- **Priority.** High.
- **Operator response.** Check the authorized change record, actor and
  member. If the addition is unapproved, have the directory owner remove
  the access and investigate the actor's recent activity.

See [identity rule recognition and priority](../../server-dotnet/src/Sli.Server/Semantic/Detections/IdentityAttacks.cs) for signals 4–6.

## 7. Security log cleared

- **Signal.** Event 1102, or a System event 104 from Windows Eventlog whose
  target is the Security log.
- **Priority.** High in the shipped rule. If there is no published finding,
  look up the source records in the Event journal.
- **Operator response.** Check for approved maintenance. Preserve central
  copies and review preceding changes or sign-ins. Escalate unexplained
  clearing and record any resulting gaps in evidence.

## 8. Windows auditing weakened

- **Signal.** Event 4719 identifies removal of success or failure auditing
  from an audit subcategory. Review the affected subcategory and actor
  when present.
- **Priority.** High.
- **Operator response.** Verify the change with the Windows policy owner.
  Have authorized staff restore the approved policy if needed. Check for
  missed data during the affected interval.

## 9. SLI agent service stopped or disabled

- **Signal.** Collected service events can show that the SLI agent service
  stopped (7036) or that its startup was disabled (7040 or 7045). Use
  [System status](administration.md#system-status) and the agent page
  to check delivery around that time.
- **Priority.** High for a matching service finding.
- **Operator response.** Check the host and any maintenance record. Preserve
  the service and collection records. For an unexplained stop, involve
  the host owner, restore authorized collection and investigate the gap.

See [log, audit and agent rule definitions](../../server-dotnet/src/Sli.Server/Semantic/Detections/AttackPrecursors.cs) for signals 7–9.

## 10. New task or service on a domain controller

- **Signal.** Security event 4698 records task registration. System event
  7045 from Service Control Manager records service installation. Find the
  retained records in the [Event journal](event-journal.md).
- **Priority.** The event catalog labels both records informational, in the
  important collection tier. Treat them as journal evidence. This release
  does not establish a combined automatically published problem for ordinary
  task or service creation.
- **Operator response.** Compare the name, host, available identity and
  definition with the approved change or software inventory. Preserve the
  source event and escalate an unapproved or unclear entry to the host
  owner before changing it.

See the [event catalog](../../config/event_catalog.json) and
[event normalization](../../server-dotnet/src/Sli.Server/Semantic/SemanticNormalization.cs).
