import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import type { ReportResultDto } from "../api/report-v2-types";
import { StateView } from "../design-system";
import { t } from "../i18n";
import { useTimeZone } from "./App";
import {
  RelationCursorRestartNotice,
  SecurityRelationsPanel,
  VpnAccountingIsolationNotice,
  VpnAccountingSessionsPanel,
  securityEventsExactSelectorError,
  securityRelationParams,
  semanticRelationsQueryKey,
  shouldRestartSemanticRelations,
  vpnAccountingIsolatedByWindowsFilters,
  vpnAccountingSessionParams,
  type SecurityEventsFilterState,
} from "./security-events-report";

/** The report parameters and the server-resolved window as the relations API expects them. */
export function chainFilters(params: URLSearchParams, window: ReportResultDto["window"] | undefined, timeZone: string): SecurityEventsFilterState | null {
  const domainId = Number(params.get("domain"));
  const timeFrom = window?.from_utc;
  const timeTo = window?.to_utc_exclusive ?? window?.to_utc;
  if (!Number.isSafeInteger(domainId) || domainId <= 0 || !timeFrom || !timeTo) return null;
  const text = (key: string) => params.get(key) ?? "";
  return {
    domainId, timeFrom, timeTo, timeZone: params.get("tz") || timeZone,
    category: text("category"), eventId: text("event_id"), outcome: text("outcome"), actor: text("actor"),
    target: text("target"), group: text("group"), source: text("source"), q: text("q"),
    entityId: params.get("entity_id") ?? undefined, eventDbId: params.get("event_db_id") ?? undefined, limit: 200,
  };
}

/** «Связанные последовательности»: saved relations between exact events and VPN Accounting sessions. */
export function SecurityChainsView({ params, result }: { params: URLSearchParams; result?: ReportResultDto }) {
  const { timeZone } = useTimeZone();
  const filters = useMemo(() => chainFilters(params, result?.window, timeZone), [params, result?.window, timeZone]);
  const [generation, setGeneration] = useState(0);
  const [restarted, setRestarted] = useState(false);
  const selectorError = filters ? securityEventsExactSelectorError(filters) : null;
  const ready = Boolean(filters) && !selectorError;
  const isolated = filters ? vpnAccountingIsolatedByWindowsFilters(filters) : false;
  const relations = useInfiniteQuery({
    queryKey: filters ? semanticRelationsQueryKey(filters, generation) : ["security-relations", "not-ready"],
    queryFn: ({ pageParam }) => {
      const parameters = securityRelationParams(filters!);
      if (pageParam) parameters.set("cursor", String(pageParam));
      return api.semanticRelations(parameters);
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => (page.has_more ? page.next_cursor || undefined : undefined),
    enabled: ready,
    retry: false,
  });
  useEffect(() => {
    if (relations.isFetchNextPageError && shouldRestartSemanticRelations(relations.error)) {
      setRestarted(true);
      setGeneration((value) => value + 1);
    }
  }, [relations.error, relations.isFetchNextPageError]);
  const sessions = useInfiniteQuery({
    queryKey: ["security-relations", "vpn-accounting", filters],
    queryFn: ({ pageParam }) => api.vpnSessionsByParams(vpnAccountingSessionParams(filters!, Number(pageParam) || 0)),
    initialPageParam: 0,
    getNextPageParam: (page) => (page.page.has_more ? page.page.offset + page.page.limit : undefined),
    enabled: ready && !isolated,
    retry: false,
  });
  if (!filters) return <StateView state="empty" detail={t("security.chains.empty")}/>;
  if (selectorError) return <StateView state="unavailable" detail={t("security.chains.unavailable", { error: selectorError })}/>;
  return <div className="sli-ds-report__views">
    {restarted ? <RelationCursorRestartNotice/> : null}
    <SecurityRelationsPanel items={relations.data?.pages.flatMap((page) => page.items) ?? []} state={relations.data?.pages[0]?.state} coverage={relations.data?.pages[0]?.coverage}
      loading={relations.isLoading} failed={relations.isError} hasMore={Boolean(relations.hasNextPage)} fetchingMore={relations.isFetchingNextPage}
      fetchMore={() => void relations.fetchNextPage()} filters={filters}/>
    {isolated ? <VpnAccountingIsolationNotice/> : <VpnAccountingSessionsPanel report={sessions.data?.pages[0]} items={sessions.data?.pages.flatMap((page) => page.items) ?? []}
      loading={sessions.isLoading} failed={sessions.isError} hasMore={Boolean(sessions.hasNextPage)} fetchingMore={sessions.isFetchingNextPage}
      fetchMore={() => void sessions.fetchNextPage()} filters={filters}/>}
  </div>;
}
