import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../../api/client";
import { Button, DataTable, PageHeader, StateView, type TableColumn } from "../../design-system";
import { useEffectiveAccess } from "../App";
import { hasAllowedReport } from "../report-access";
import { operationsReadinessView, type ReadinessCheckView } from "./readiness-view";
import { t } from "../../i18n";

export function ProjectReadinessPage() {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  const allowed = hasAllowedReport(access, ["operations.readiness"]);
  const query = useQuery({ queryKey: ["v4", "operations", "readiness"], queryFn: api.platformReadiness, enabled: Boolean(access && allowed && !accessRequest?.error), staleTime: 30_000, retry: false });
  const checks = query.data ? operationsReadinessView(query.data) : null;
  const columns: TableColumn<ReadinessCheckView>[] = [
    { key: "name", label: t("operations.readiness.check") },
    { key: "state", label: t("operations.readiness.state") },
    { key: "meaning", label: t("operations.readiness.meaning") },
    { key: "nextStep", label: t("operations.readiness.nextStep"), render: (row) => row.retry
      ? <Button disabled={query.isFetching} onClick={() => void query.refetch()}>{row.nextStep}</Button>
      : row.href ? <a href={row.href}>{row.nextStep}</a> : row.nextStep },
  ];

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.readiness.title")}/>
    {!access || accessRequest?.error ? <AccessRequestStateView/>
      : !allowed ? <StateView state="denied" detail={<>{t("operations.readiness.denied")} <Link to="/access-user">{t("operations.readiness.openMyAccess")}</Link></>}/>
        : query.isLoading ? <StateView state="loading"/>
          : query.isError ? <StateView state="unavailable" detail={query.error.message} onRetry={() => void query.refetch()}/>
            : checks?.length ? <DataTable columns={columns} rows={checks} rowKey={(row) => row.key} caption={t("operations.readiness.tableTitle")}/>
              : checks ? <p>{t("operations.readiness.noIssues")}</p> : null}
  </section>;
}

