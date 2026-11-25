import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { StateView } from "../design-system";
import { t } from "../i18n";
import { useEffectiveAccess } from "./App";

export function useFirstAdSource(search: URLSearchParams, enabled: boolean) {
  const access = useEffectiveAccess();
  const canCheck = enabled && access?.platform_owner === true && !access.preview
    && !search.has("domain") && !search.has("domain_id");
  const status = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus, enabled: canCheck, retry: false });
  if (!canCheck || !status.isSuccess || status.isFetching) return false;

  const setup = status.data;
  const agents = setup.agent_collection;
  // A failed configuration read also yields empty arrays. Require evidence that the reads succeeded.
  return setup.steps.some(step => step.id === "domains" && step.state === "todo")
    && setup.domains.length === 0 && setup.domain_controller_source != null && setup.domain_controllers.length === 0
    && setup.report_domain?.value === "" && !setup.report_domain.configured_value
    && agents?.state === "unknown" && !agents.diagnostics && agents.items.length === 0 && !agents.replaced_agents?.length;
}

export function FirstAdSource() {
  return <StateView state="empty" titleMessage={t("systemStatus.step.agent")} actions={
    <a className="sli-ds-button" href="/app/agents?register=1">{t("agents.addComputer")}</a>
  }/>;
}
