"""Runtime adapters for the retired Python services, kept outside the Debian kit."""

import os
import sys

from server.sli.ops import shutdown as shutdown


def run_service(service, remaining, workers, notifications, run_api, import_module):
    # The Linux core never enables Windows acquisition through HTTP startup.
    os.environ['ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER'] = '0'
    os.environ['ADLOG_ENABLE_INPROCESS_POST_COLLECTION'] = '0'
    os.environ['ADLOG_ACQUISITION_DISABLED'] = '1'
    os.environ['ADLOG_ENABLE_POSTGRES_COLLECTION'] = '0'
    os.environ['ADLOG_POSTGRES_RUNTIME_COLLECTION'] = '0'
    os.environ['ADLOG_NPS_EVENTLOG_ENABLED'] = '0'
    if service == 'api':
        os.environ.setdefault('ADLOG_AUTH_REQUIRED', '1')
        return run_api(remaining)
    if service in notifications:
        return import_module(notifications[service]).main()
    module_name = 'server.sli.core.job_executor' if service == 'executor' else workers[service]
    sys.argv = [module_name, *remaining]
    if service in workers:
        with shutdown.graceful_shutdown():
            return import_module(module_name).main()
    return import_module(module_name).main()


def load_config():
    from server.sli.core.app_config import load_config as legacy_config

    return legacy_config()


def read_plugin_heartbeat(service):
    from server.sli.sources.plugin_runtime_heartbeat import read_plugin_heartbeat as legacy_heartbeat

    return legacy_heartbeat(service)


def pilot_enabled():
    from server.sli.core.job_executor import pilot_enabled as legacy_pilot

    return legacy_pilot()


def configure_workstation_history():
    from server.sli.storage.workstation_history import configured_history, ensure_schema

    history = configured_history()
    if history is None:
        raise RuntimeError('workstation_history_unavailable')
    ensure_schema(history.port)


def configure_permanent_history():
    from server.sli.storage import ad_snapshot_change_history, permanent_fact_history

    permanent_fact_history.primary_read_enabled()
    port = permanent_fact_history.configured_read_port()
    if port is None:
        raise RuntimeError('permanent_history_unavailable')
    permanent_fact_history.ensure_schema(port)
    ad_snapshot_change_history.ensure_schema(port)
