"""Read-only fleet admission; administrative agent documents never leave core."""

from server.sli.agents.ca import uuid_text
from server.sli.plugins.workstations.access import station_predicate
from server.sli.plugins.workstations.scope import RESOURCES

PAGE_SIZE = 100
FIELDS = ("agent_key", "status", "last_seen", "policy_revision", "applied_policy_revision")


def read_agents(cur, access, query):
    if (set(query) - {"agent_key", "cursor"}
            or any(not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], str)
                   for value in query.values())):
        raise ValueError("workstation_request_invalid")
    selected = uuid_text(query["agent_key"][0]) if "agent_key" in query else None
    cursor = uuid_text(query["cursor"][0]) if "cursor" in query else None
    predicate, params = station_predicate(access)
    if selected:
        predicate += " and a.agent_key=%s"
        params.append(selected)
    if cursor:
        predicate += " and a.agent_key>%s"
        params.append(cursor)
    cur.execute("set local statement_timeout = '5000ms'")
    cur.execute(RESOURCES + " select a.agent_key,s.status,s.last_seen,s.policy_revision,s.applied_policy_revision"
                + " from registered a join sli_agents s on s.id::text=a.transport_agent_id where " + predicate
                + " order by a.agent_key limit %s", (*params, PAGE_SIZE + 1))
    rows = cur.fetchall()
    if selected and not rows:
        # Absent and foreign agents have the same response, without counts.
        raise PermissionError("workstation_access_denied")
    items = [{key: row[key] for key in FIELDS} for row in rows[:PAGE_SIZE]]
    return {"items": items, "has_more": len(rows) > PAGE_SIZE,
            "next_cursor": items[-1]["agent_key"] if len(rows) > PAGE_SIZE else None}
