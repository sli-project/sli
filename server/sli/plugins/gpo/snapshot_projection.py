"""GPO pure snapshot projector, independent of AD admission."""


def project_gpo_v2_exact(exact_input):
    from server.sli.plugins.gpo.reports.gpo_v2_reporting import project_gpo_v2_exact as project

    return project(exact_input)
