"""Reference-only templates; never interpolate source data or exception text."""
from uuid import UUID

from server.sli.core.messages import message


def message_content(job, base_url):
    job_id, object_id = str(UUID(str(job["id"]))), str(UUID(str(job["object_id"])))
    if job["object_kind"] == "test_problem":
        title = "SLI: simulated test problem"
        body = "Category: simulated test problem\nSeverity: informational\n"
        target = "/report/notifications.deliveries"
        identity = object_id
    elif job["object_kind"] == "semantic_finding":
        finding_id = job["finding_id"]
        if type(finding_id) is not int or not 0 < finding_id < 2**63:
            raise ValueError("invalid_notification_object")
        title = "SLI: security problem"
        kind = job.get("notification_kind")
        category = f".{kind}" if kind in {"remote_access", "account_decoy", "file_decoy", "account_watch"} else ""
        body = message(f"notifications.problem{category}.what", locale=job.get("language", "ru"))["text"] + "\n"
        body += message(f"notifications.problem{category}.action", locale=job.get("language", "ru"))["text"] + "\n"
        severity = job.get("object_severity")
        if severity is not None:
            if severity not in {"info", "low", "medium", "high", "critical"}:
                raise ValueError("invalid_notification_object")
            body += f"Severity: {severity}\n"
        if job.get("delivery_reason") == "pipeline_delay":
            minutes = job.get("delay_minutes")
            if type(minutes) is not int or not 15 <= minutes <= 2**31 - 1:
                raise ValueError("invalid_notification_object")
            delayed = message("notifications.delivery.delayed", {"minutes": minutes}, locale=job.get("language", "en"))["text"]
            title += f" ({delayed})"
            body += delayed + "\n"
        target = f"/report/security.problems?id={finding_id}"
        identity = str(finding_id)
    elif job["object_kind"] == "report_schedule":
        from server.sli.core.report_schedules import digest
        title, body = digest(job, base_url)
        return "SLI: " + title, body
    else:
        raise ValueError("invalid_notification_object")
    return title, (body + f"Time: {job['created_at']}\nProblem: {identity}\nJob: {job_id}\n"
                   f"{base_url.rstrip('/')}{target}\n")
