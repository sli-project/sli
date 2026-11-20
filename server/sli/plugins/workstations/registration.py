"""Reviewed finite workstation jobs; registration performs no storage I/O."""
from server.sli.plugins.workstations import retention


def register(contribution):
    from server.sli.plugins.workstations import agent_read, inventory, jobs, projection_jobs

    retention.register_jobs(contribution, core=True)
    contribution.jobs[projection_jobs.HANDLER_ID] = (projection_jobs.stage, projection_jobs.apply)
    contribution.hooks["job_source"] = jobs.job_source
    contribution.hooks["agent_read"] = agent_read.read_agents
    contribution.hooks["inventory_source"] = inventory.inventory_source

