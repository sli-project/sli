"""A published RANSOM high uses both shared, reference-only transport templates."""
from uuid import uuid4

from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
from server.sli.semantic import qw_input as qw
from tests.unit.test_file_ransom import NOW, Cursor, batch, results, rule, run
from tests.unit.test_notification_smtp import delivery as smtp_delivery, channel as smtp_channel
from tests.unit.test_notification_telegram import delivery as telegram_delivery, channel as telegram_channel
from tests.unit.test_qw_publication import evaluate as publish, no_database as no_database


def test_ransom_high_reaches_both_fake_transports_without_native_file_or_approval_data(smtp_delivery, telegram_delivery):
    selected = rule(evaluation_mode="enabled")
    row = batch(results(110)[0])
    cur = Cursor(selected, row)
    run(cur, selected, [row])
    signal = qw.load_qw_signal(cur, signal_id=next(iter(cur.signals)))
    outcome = publish(cur, signal)
    assert outcome.finding_created and outcome.risk_class.value == "high"
    job = {"id": str(uuid4()), "object_id": str(outcome.scenario_id), "object_kind": "semantic_finding",
           "finding_id": outcome.finding_id, "recipient_user_id": 2, "object_severity": "high",
           "created_at": NOW.isoformat(), "path": "synthetic-private-file", "approved_by": "synthetic-private-owner"}
    assert smtp.send(job | {"channel": "smtp"}, smtp_channel()) == "accepted"
    assert telegram.send(job | {"channel": "telegram"}, telegram_channel()) == telegram.Outcome("accepted")
    messages = [smtp_delivery[-1][0].get_content(), telegram_delivery[-1][0]["text"]]
    for text in messages:
        assert "Severity: high" in text and f"/report/security.problems?id={outcome.finding_id}" in text
        assert "synthetic-private" not in text
    assert run(cur, selected, [row])["jobs"] == 0
    assert len(smtp_delivery[-1]) == len(telegram_delivery[-1]) == 1
