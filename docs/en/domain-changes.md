# Domain changes

[Русская версия](../ru/domain-changes.md) · [Work screens](user-guide.md)

Open **Domain changes** at `/app/report/security.events.chains` to review
changes recorded in domain events.

1. Choose the period and domain, then a view such as **Accounts**, **Groups**,
   **Passwords** or **Audit**. Search by object, initiator or attribute.
   Use the operation filter to narrow the results further.
2. Open the change and compare the object, field or group with the operation,
   initiator, domain controller and time. If repeats are collapsed, expand
   the group to inspect its rows.
3. Use **Participants** and **Source event** in the detail panel. Where
   available, follow a participant to filter on it or open the full source
   event. Export CSV only when the report offers the action and your process
   allows exporting those records.

For differences between collected directory snapshots, see
[AD state](ad-state.md). For raw events by code or source, use the
[Event journal](event-journal.md).
