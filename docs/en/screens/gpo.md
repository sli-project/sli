# Group policies

[Русская версия](../../ru/screens/gpo.md) · [Work screens](../user-guide.md)

Open **Group policies** at `/app/report/ad.gpo.v2`. Select a domain, search
by policy and use **Version mismatch** or **Unlinked** to narrow the list.

1. Open a policy. Use **Settings** to search by parameter and filter by
   category. Open a setting to inspect its configured value and available
   details. **Links** shows observed scopes and link flags. **Permissions**
   shows the observed access entries.
2. On **Versions**, compare AD and SYSVOL version numbers for the computer
   and user halves. To compare retained settings, select distinct **Before**
   and **After** snapshots and select **Compare snapshots**. The table shows
   added, removed and changed settings with their available values. **No
   differences in visible settings** applies to that selected pair. If
   there are fewer than two eligible snapshots, a pair cannot be compared.
3. Use **Changes** to review the collected change history, including observed
   before and after values where shown. The card and the comparison are
   observations for the selected policy and domain. Consult the domain's
   change records for independent evidence of an actor.
