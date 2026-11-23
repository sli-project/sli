# AD state

[Русская версия](../../ru/screens/ad-state.md) · [Work screens](../user-guide.md)

Open **AD state** at `/app/report/ad.infrastructure`. Select an accessible
domain and check when it was observed.

1. On **Parameters**, filter by result, area or search text. Open a check
   to review **Observation**, **Object** and **Rule**. Compare the observed
   and expected values where both are present. Use the observation time
   and source when assessing a deviation.
2. Open **AD changes** to review parameter or privileged changes when those
   views are available. A difference between observations records what was
   seen across snapshots. Inspect [Domain changes](domain-changes.md) for
   separately collected evidence about who performed an action.
3. **SPN collisions** shows duplicate service principal names when detected.
   Open a row to see affected objects. Use **Linked findings** to review
   relevant findings when the report provides them.

Check missing collection, incomplete observations and unevaluated checks
before interpreting a domain's posture.
