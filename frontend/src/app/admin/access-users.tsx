import { Select } from "../../design-system/Select";
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type AuthUserInventory, type V4AccessAuditItem } from "../../api/client";
import { Button, Checkbox, DataTable, DetailDrawer, FactList, PageHeader, StateView, Tabs, TabList, TabPanel, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { EMPTY_VALUE } from "../../shared/format";
import { useTimeZone } from "../App";
import { bootstrapEffectiveRole } from "../access-control";
import { auditActionLabel, auditReasonLabel } from "../report-labels";
import { useReportTitles } from "../report-titles";
import { filterAccounts } from "./account-filter";

type User = AuthUserInventory["items"][number];
type AuditEntry = V4AccessAuditItem & { occurrences?: V4AccessAuditItem[] | null };
type Editor = { mode: "create" } | { mode: "details" | "role" | "password"; user: User };

function userRole(role: string) {
  if (role === "admin") return t("access.admin.roles.admin.label");
  if (role === "viewer") return t("access.people.role.viewer");
  if (role === "operator") return t("access.people.role.operator");
  return role || EMPTY_VALUE;
}

/** The user endpoint requires both the admin role and access.manage. */
export function AccessUsersContent() {
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const canManage = bootstrapEffectiveRole(bootstrap.data) === "admin";
  const inventory = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers, enabled: canManage, refetchOnWindowFocus: false });
  const [tab, setTab] = useState("users");
  const [collapse, setCollapse] = useState(true);
  const audit = useQuery({ queryKey: ["v4", "access-audit", collapse], queryFn: () => api.v4AccessJournal(collapse), enabled: canManage && tab === "audit" });
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const reportTitle = useReportTitles();
  const [editor, setEditor] = useState<Editor | null>(null);
  const [auditItem, setAuditItem] = useState<AuditEntry | null>(null);
  const [original, setOriginal] = useState<V4AccessAuditItem | null>(null);
  const refresh = () => {
    void client.invalidateQueries({ queryKey: ["admin-users"] });
    void client.invalidateQueries({ queryKey: ["v4", "access-audit"] });
  };
  const toggle = useMutation({
    mutationFn: (user: User) => api.updateUser(user.id, { is_active: !user.is_active }),
    onSuccess: refresh,
    onError: (_error, user) => setEditor({ mode: "details", user }),
  });
  const title = t("access.people.title");
  if (bootstrap.isLoading) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="loading" skeleton="table"/></section>;
  if (!canManage) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="denied" detail={t("access.admin.error.denied")}/></section>;

  const openEditor = (next: Editor) => { toggle.reset(); setEditor(next); };
  const toggleUser = (user: User) => {
    if (window.confirm(t("access.admin.confirm.toggleUser", { action: user.is_active ? t("access.admin.action.disable") : t("access.admin.action.enable"), username: user.username }))) toggle.mutate(user);
  };
  const users = filterAccounts(inventory.data?.items ?? [], "people");
  const username = (id?: number | null) => inventory.data?.items.find(user => user.id === id)?.username ?? EMPTY_VALUE;
  const auditActor = (item: V4AccessAuditItem) => {
    if (item.actor_type === "system" || (item.actor_type === "local" && item.actor_id == null)) return "SLI";
    return item.actor_type === "user" || item.actor_type === "session" ? username(item.actor_id) : EMPTY_VALUE;
  };
  const auditAction = (item: V4AccessAuditItem) => auditActionLabel(item.action, item.target_key);
  const auditTarget = (item: V4AccessAuditItem) => {
    if (item.target_type === "notification_channel" && (item.target_key === "telegram" || item.target_key === "smtp"))
      return t(`reports.v2.notifications.channels.columns.kind.labels.${item.target_key}`);
    return item.subject_type === "user" && !item.target_key ? username(item.subject_id)
      : item.target_key ? reportTitle(item.target_key, EMPTY_VALUE) : EMPTY_VALUE;
  };
  const date = (value?: string | null) => <span title={formatDateTime(value, timeZone)}>{formatDateTime(value, timeZone, { withYear: false })}</span>;
  const userColumns: TableColumn<User>[] = [
    { key: "username", label: t("access.people.name") },
    { key: "role", label: t("access.admin.users.col.role"), render: user => userRole(user.role) },
    { key: "is_active", label: t("access.people.status"), render: user => t(user.is_active ? "access.admin.status.active" : "access.admin.status.disabled") },
    { key: "last_login_at", label: t("access.admin.users.col.lastLogin"), render: user => date(user.last_login_at) },
    { key: "actions", label: t("access.admin.users.col.actions"), render: user => <span onClick={event => event.stopPropagation()}>
      <button type="button" className="sli-ds-link-button" disabled={toggle.isPending} onClick={() => openEditor({ mode: "role", user })}>{t("access.people.changeRole")}</button>{" · "}
      <button type="button" className="sli-ds-link-button" disabled={!user.is_active || toggle.isPending} onClick={() => openEditor({ mode: "password", user })}>{t("access.admin.action.resetPassword")}</button>{" · "}
      <button type="button" className="sli-ds-link-button" disabled={toggle.isPending} onClick={() => toggleUser(user)}>{t(user.is_active ? "access.admin.action.disable" : "access.admin.action.enable")}</button>
    </span> },
  ];
  const auditColumns: TableColumn<AuditEntry>[] = [
    { key: "created_at", label: t(collapse ? "journal.last" : "access.center.col.time"), render: item => date(item.created_at) },
    { key: "actor_id", label: t("access.people.audit.actor"), render: auditActor },
    { key: "action", label: t("access.audit.action"), render: auditAction },
    { key: "target_key", label: t("access.people.audit.object"), render: auditTarget },
  ];
  if (collapse && audit.data?.items.some((item) => item.occurrences?.length)) auditColumns.push(
    { key: "count", label: t("journal.count"), render: (item) => item.occurrences?.length ?? 1 },
    { key: "first", label: t("journal.first"), render: (item) => date(item.occurrences?.at(-1)?.created_at ?? item.created_at) },
  );
  const selected = original ?? auditItem;
  const add = <button type="button" className="sli-ds-button" data-variant="primary" onClick={() => openEditor({ mode: "create" })}>{t("access.people.add")}</button>;
  return <section className="sli-ds-report">
    <PageHeader title={title} actions={<>
      <a className="sli-ds-button" href="/app/access-requests">{t("shell.nav.access-requests")}</a>
      {add}
    </>}/>
    <Tabs items={[{ key: "users", label: t("access.people.accounts") }, { key: "audit", label: t("access.people.audit.title") }]} active={tab} onChange={setTab}>
      <TabList label={title}/>
      <TabPanel>{tab === "users" ? <>
        {inventory.isLoading ? <StateView state="loading" skeleton="table"/>
          : inventory.isError || !inventory.data ? <StateView state="unavailable" detail={t("access.people.error.users")} onRetry={() => void inventory.refetch()}/>
            : users.length ? <DataTable localPagination columns={userColumns} rows={users} rowKey={user => String(user.id)} caption={title} onRowClick={user => openEditor({ mode: "details", user })}/>
              : <div>{t("access.people.empty")}</div>}
      </> : <>
        <Checkbox checked={collapse} onChange={(event) => setCollapse(event.target.checked)}>{t("journal.collapse")}</Checkbox>
        {audit.isLoading ? <StateView state="loading" skeleton="table"/>
          : audit.isError || !audit.data ? <StateView state="unavailable" detail={t("access.people.error.audit")} onRetry={() => void audit.refetch()}/>
            : audit.data.items.length ? <DataTable localPagination columns={auditColumns} rows={audit.data.items} rowKey={item => String(item.id)} caption={t("access.people.audit.title")}
              onRowClick={(item) => { setOriginal(null); setAuditItem(item); }}/>
              : <div>{t("access.people.audit.empty")}</div>}
      </>}</TabPanel>
    </Tabs>
    {editor ? <UserDrawer key={editor.mode === "create" ? "create" : `${editor.mode}:${editor.user.id}`} editor={editor} onClose={() => setEditor(null)} onSaved={refresh}
      statusError={toggle.isError && editor.mode !== "create" && toggle.variables?.id === editor.user.id}/>: null}
    {auditItem && selected ? <DetailDrawer open title={auditAction(auditItem)} onClose={() => { setAuditItem(null); setOriginal(null); }}>
      <FactList facts={[
        { label: t("access.center.col.time"), value: formatDateTime(selected.created_at, timeZone) },
        { label: t("access.people.audit.actor"), value: auditActor(selected) },
        { label: t("access.people.audit.object"), value: auditTarget(selected) },
        { label: t("access.center.audit.basis"), value: selected.reason?.trim() ? auditReasonLabel(selected.reason) : EMPTY_VALUE },
        { label: t("access.center.col.outcome"), value: selected.outcome === "ok" ? t("access.center.outcome.ok") : selected.outcome || EMPTY_VALUE },
      ]}/>
      {auditItem.occurrences?.length ? <DataTable localPagination rows={auditItem.occurrences} rowKey={(item) => String(item.id)}
        caption={t("journal.records")} columns={[
          { key: "created_at", label: t("access.center.col.time"), render: (item) => <Button variant="ghost" aria-pressed={selected.id === item.id} onClick={() => setOriginal(item)}>
            {formatDateTime(item.created_at, timeZone)}
          </Button> },
        ]}/> : null}
      <FactList facts={[
        { label: t("access.people.audit.actorId"), value: selected.actor_id },
        { label: t("access.audit.targetKey"), value: selected.target_key },
        { label: t("access.people.audit.subjectId"), value: selected.subject_id },
      ]}/>
    </DetailDrawer> : null}
  </section>;
}

function UserDrawer({ editor, onClose, onSaved, statusError }: { editor: Editor; onClose: () => void; onSaved: () => void; statusError: boolean }) {
  const { timeZone } = useTimeZone();
  const user = editor.mode === "create" ? undefined : editor.user;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState(user?.role ?? "viewer");
  const [savedRole, setSavedRole] = useState(user?.role ?? "viewer");
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const [createdPassword, setCreatedPassword] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"copied" | "error" | null>(null);
  const create = useMutation({ mutationFn: api.createUser, onSuccess: (_result, body) => { setCreatedPassword(body.password); setPassword(""); onSaved(); } });
  const changeRole = useMutation({ mutationFn: (next: string) => api.updateUser(user!.id, { role: next }), onSuccess: (_result, next) => { setSavedRole(next); setSavedAt(new Date()); onSaved(); } });
  const reset = useMutation({ mutationFn: (next: string) => api.resetUserPassword(user!.id, next), onSuccess: () => { setPassword(""); setSavedAt(new Date()); onSaved(); } });
  const title = editor.mode === "create" ? t("access.people.add") : editor.mode === "role" ? t("access.people.changeRole") : editor.mode === "password" ? t("access.admin.action.resetPassword") : user!.username;
  const pending = create.isPending || changeRole.isPending || reset.isPending;
  const passwordRejected = create.error instanceof ApiResponseError && create.error.code === "password_must_be_at_least_12_characters";
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (pending) return;
    if (editor.mode === "create") create.mutate({ username: username.trim(), password, role });
    if (editor.mode === "role") changeRole.mutate(role);
    if (editor.mode === "password" && window.confirm(t("access.admin.confirm.resetPassword", { username: user!.username }))) reset.mutate(password);
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(createdPassword!); setCopyState("copied"); }
    catch { setCopyState("error"); }
  };
  const roleOptions = [{ value: "viewer", label: userRole("viewer") }, { value: "admin", label: userRole("admin") }];
  return <DetailDrawer open title={title} subtitle={editor.mode !== "details" ? user?.username : undefined} onClose={onClose}
    footer={editor.mode !== "details" && !createdPassword ? <button type="submit" form="access-user-editor" className="sli-ds-button" data-variant="primary"
      disabled={pending || (editor.mode === "role" ? role === savedRole : editor.mode === "create" ? !username.trim() || !password : !password)}>{t("access.people.save")}</button> : undefined}>
    {editor.mode === "details" ? <FactList facts={[
      { label: t("access.admin.users.col.role"), value: userRole(user!.role) },
      { label: t("access.people.status"), value: <>{t(user!.is_active ? "access.admin.status.active" : "access.admin.status.disabled")}{statusError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.updateUser")}</p> : null}</> },
      { label: t("access.admin.users.col.lastLogin"), value: formatDateTime(user!.last_login_at, timeZone) },
    ]}/> : createdPassword ? <div className="sli-ds-report__views">
      <div className="sli-ds-field"><label htmlFor="created-user-password">{t("access.admin.field.password")}</label><input id="created-user-password" readOnly value={createdPassword}/></div>
      <button type="button" className="sli-ds-button" onClick={() => void copy()}>{t("access.people.copy")}</button>
      {copyState ? <span role="status">{t(copyState === "copied" ? "access.people.copied" : "access.people.copyError")}</span> : null}
    </div> : <form id="access-user-editor" aria-label={title} className="sli-ds-report__views" onSubmit={submit}>
      {editor.mode === "create" ? <div className="sli-ds-field"><label htmlFor="access-user-name">{t("access.people.name")}</label>
        <input id="access-user-name" autoComplete="username" required minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9_.\-]{2,63}" value={username} disabled={pending} onChange={event => setUsername(event.target.value)}/>
        {create.isError && !passwordRejected ? <p className="sli-ds-field__error" role="alert">{t("access.people.error.create")}</p> : null}
      </div> : null}
      {editor.mode === "role" ? <FactList facts={(savedRole === "operator" ? ["viewer", "operator", "admin"] as const : ["viewer", "admin"] as const)
        .map((id) => ({ label: userRole(id), value: t(`access.admin.roles.${id}.description`) }))}/> : null}
      {editor.mode === "create" || editor.mode === "role" ? <div className="sli-ds-field"><label htmlFor="access-user-role">{t("access.admin.field.role")}</label>
        <Select label={t("access.admin.field.role")} id="access-user-role" value={role} disabled={pending} onChange={(selectedValue) => setRole(selectedValue)}
          options={[...(savedRole === "operator" ? [{ value: "operator", label: userRole("operator"), disabled: true }] : []), ...(roleOptions ?? [])]}/>
        {changeRole.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.updateUser")}</p> : null}
      </div> : null}
      {editor.mode === "create" || editor.mode === "password" ? <div className="sli-ds-field"><label htmlFor="access-user-password">{t(editor.mode === "password" ? "access.admin.reset.newPassword" : "access.admin.field.password")}</label>
        <input id="access-user-password" type="password" autoComplete="new-password" required minLength={12} value={password} disabled={pending} onChange={event => setPassword(event.target.value)}/>
        {passwordRejected ? <p className="sli-ds-field__error" role="alert">{t("access.people.error.password")}</p> : null}
        {reset.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.resetPassword")}</p> : null}
      </div> : null}
      {savedAt ? <span role="status">{t("access.people.saved", { time: formatDateTime(savedAt, timeZone) })}</span> : null}
    </form>}
    {user ? <FactList facts={[{ label: t("access.people.id"), value: user.id }]}/> : null}
  </DetailDrawer>;
}
