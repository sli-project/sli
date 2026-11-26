import type { SetupSourceAction, SetupStatus, SetupStep } from "../../api/client";
import { getLocale, t } from "../../i18n";

/** Step IDs identify product copy; directory values remain untouched. */
export function setupStepPresentation(step: SetupStep, status: SetupStatus): SetupStep {
  if (step.id === "first-collection" && status.agent_collection) {
    const health = status.agent_collection;
    const state = health.diagnostics ? "unavailable" : health.state;
    const hasFailure = state === "error" && health.items.some((agent) => agent.modules.some((module) =>
      module.channels.some((channel) => channel.state === "error" && channel.failure_reason)));
    return { ...step, title: t("setup.agentCollection.title"),
      state: state === "current" ? "done" : state === "unknown" || state === "unavailable" ? "unavailable" : "todo",
      summary: hasFailure ? "" : t(`setup.agentCollection.${state === "error" ? "partial" : state}`),
      link: "/admin/status" };
  }
  if (step.id === "domain-controllers" && status.agent_collection) {
    const count = status.agent_collection.connected_domain_controllers;
    const state = count === undefined ? "unavailable" : count > 0 ? "done" : "todo";
    return { ...step, state, title: t("setup.steps.controllers.title"),
      summary: count === undefined ? t("setup.steps.controllers.unavailable") : t("setup.controllers.currentCount", { count }) };
  }
  if (step.id === "sources" || step.id === "first-collection") {
    const state = status.sources.some((pack) => pack.instances === undefined) ? "unavailable" : step.state;
    const ready = status.sources.flatMap((pack) => pack.instances ?? []).filter((item) => item.configured === true && item.enabled === true);
    if (step.id === "sources") return { ...step, state, title: t("setup.steps.sources.title"), summary: state === "unavailable"
      ? t("setup.steps.sources.unavailable") : t("setup.sources.summary", { count: ready.length }), manual: t("setup.steps.sources.manual") };
    return { ...step, state, title: t("setup.steps.collection.title"), summary: state === "unavailable"
      ? t("setup.steps.collection.unavailable") : t("setup.sources.collectionSummary", { count: ready.filter((item) => item.last_data_utc || item.data_received === true).length }) };
  }
  if (getLocale() !== "en") return step;
  const unavailable = step.state === "unavailable";
  switch (step.id) {
    case "report-domain": return { ...step, title: t("setup.steps.report_domain.title"),
      summary: unavailable ? t("setup.steps.report_domain.unavailable") : status.report_domain?.source === "not_configured"
        ? t("setup.steps.report_domain.todo") : t("setup.steps.report_domain.summary", { domain: status.report_domain?.value ?? "" }) };
    case "domains": return { ...step, title: t("setup.steps.domains.title"),
      summary: unavailable ? t("setup.steps.domains.unavailable") : status.domains.length
        ? t("setup.steps.domains.summary", { count: status.domains.length }) : t("setup.steps.domains.todo"), manual: t("setup.steps.domains.manual") };
    case "domain-controllers": {
      const count = status.domain_controllers.filter((item) => item.enabled).length;
      return { ...step, title: t("setup.steps.controllers.title"), summary: unavailable ? t("setup.steps.controllers.unavailable")
        : count ? t("setup.steps.controllers.summary", { count }) : t("setup.steps.controllers.todo"), manual: t("setup.steps.controllers.manual") };
    }
    default: return step;
  }
}

export function setupSourceAnchor(packId: string, instanceId: string | null): string {
  return `setup-source-${encodeURIComponent(packId)}${instanceId === null ? "" : `-${encodeURIComponent(instanceId)}`}`;
}

export function setupSourceAction(action: SetupSourceAction, packId?: string, agentBacked = false): string {
  if (agentBacked) return t("setup.agentSource.next");
  if (packId === "sli.windows.ad-dc" && ["configure", "check_configuration", "enable"].includes(action)) {
    return t(action === "enable" ? "setup.source.next.ad_enable" : "setup.source.next.ad_configure");
  }
  const keys = {
    configure: "setup.source.next.configure", check_configuration: "setup.source.next.check_configuration",
    enable: "setup.source.next.enable", collect: "setup.source.next.collect", check_data: "setup.source.next.check_data",
  } as const;
  return t(keys[action]);
}


/** Label the destination, without changing or inferring a navigation permission. */
export function setupDestinationLabel(href: string): string {
  switch (href) {
    case "/admin/status": return t("shell.adminNav.status");
    case "/platform-settings": return t("platformSettings.page.title");
    case "/operations": return t("shell.nav.operations");
    case "/plugins": return t("plugins.title");
    case "/agents": return t("agents.title");
    case "#setup-domain-controllers": return t("setup.steps.controllers.title");
    default: return t("setup.step.openPage");
  }
}
