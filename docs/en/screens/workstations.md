# Workstations

This workspace supports investigation of registered workstation events. Its
canonical route is `/app/report/workstations.overview`; `/app/workstations`
remains a compatible entry point that preserves the query context.

## Operator workflow

1. Choose a domain, find a workstation and optionally filter its collection
   assignment state. The list supports 25, 50, 100 and 200 rows per page.
2. Open a workstation. Events and collection details use the main workspace.
   Returning to the list restores its filters and page.
3. Choose the event period and category. Event time bounds are separate from
   the update time of the workstation inventory record.
4. Inspect a stored record or open the related journal. Navigation preserves
   the workstation source and period. Journal, problem and exact-evidence access
   are checked independently of access to the workstation list.

## Interpretation

| Information | Meaning |
|---|---|
| Workstation, domain and OS | Registered agent data and authoritative source binding; missing values are not inferred from a similar name |
| Last contact | A retained agent contact timestamp, not proof that the host is currently online |
| Inventory updated | The inventory record update time, not a separate measurement time for every property |
| Policy revision | Assigned and agent-confirmed revisions; a difference means the assigned version is not yet confirmed |
| Collection state | Assignment and binding state, separate from whether events exist in the selected period |
| Journal record | A retained event or a retained group of observations |
| Group count | Observation count, not a count of machines, files or recoverable original XML records |
| Severity | Severity of a related published finding accessible to the current user |

A Defender component-disable event describes an observed action; it does not
establish the current state of every protection component. A logon observation
does not prove that a user session is still active.

## Current data source

The report reads current registrations and the canonical event journal populated
by native workstation ingestion. Legacy workstation observations, station
summaries and check findings are not treated as current state.

The current admission profile supports these Windows events:

| Category | Event IDs |
|---|---|
| Logons and failed logons | 4624, 4625 |
| Log clearing | 1102 |
| Local groups | 4732, 4733 |
| Task creation | 4698 |
| Services | 7036, 7040, 7045 |
| Defender changes | 5001, 5010, 5012 |

An agent assignment may enable a subset. Process creation 4688, USB observations
and fresh Defender snapshots need a separately supported collection path. Their
absence from this report does not establish absence of host activity.

## Interface and implementation rules

- Lead with useful table columns rather than standalone total-count tiles.
- Show collection assignment as a compact dot beside the workstation name,
  with a tooltip and accessible description.
- Use full-width workstation and record details.
- Keep state, observations and confirmed findings distinct.
- Pair severity colour with text and a server-confirmed finding.
- Explain unavailable data locally: unbound source, denied journal access or a
  data type outside the active collection profile.
- Keep navigation state out of API filters. Preserve source, period, page size
  and return context explicitly.
- Keep workstation, journal, problem and exact-evidence permissions separate;
  links and counts must not widen access.

Opening this report is read-only. Module assignments and collection policies
continue to use the existing administration controls.
