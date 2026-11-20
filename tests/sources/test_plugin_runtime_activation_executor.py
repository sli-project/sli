from server.sli.sources.plugin_runtime_activation_executor import execute_plugin_runtime_transition


class Cursor:
    def __init__(self):
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _sql, params):
        self.params = params

    def fetchone(self):
        return {
            "operation_id": 7,
            "committed_revision": 3,
            "desired_activation": "enabled_manual",
            "component_runtime": "running",
            "queue_state": "drained",
        }


class Connection:
    def __init__(self):
        self.current = Cursor()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.current


def test_exact_enable_call() -> None:
    digest = "a" * 64
    connection = Connection()
    value = execute_plugin_runtime_transition(
        plan={
            "plugin_id": "sli.remote-access",
            "requested_action": "enable",
            "expected_revision": 2,
            "plan_sha256": digest,
            "preserve_immutable_evidence": True,
            "production_read_path_cutover": False,
            "destructive_purge": False,
        },
        confirmation="PLUGIN-ENABLE-SLI-REMOTE-ACCESS-R2-AAAAAAAAAAAA",
        operation_uid="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        actor_kind="windows",
        actor_key=r"EXAMPLE\operator",
        actor_capabilities={"plugins.manage"},
        connection_factory=lambda: connection,
    )
    assert value["status"] == "succeeded"
    assert value["committed_revision"] == 3
    assert connection.current.params[1:3] == ("enable", 2)
