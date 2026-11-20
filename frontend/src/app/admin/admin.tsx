import { EMPTY_VALUE } from "../../shared/format";
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ApiKeyInventoryItem, type AuthUserInventory } from "../../api/client";
import { DataTable, PageHeader, StateView, type TableColumn } from "../../design-system";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../App";
import { bootstrapEffectiveRole } from "../access-control";
import { Badge, FieldError, Note } from "./gate";
import { t, type MessageKey } from "../../i18n";
import { AccountFilterField, filterAccounts, type AccountFilter } from "./account-filter";

type UserRow = AuthUserInventory["items"][number];

// These three role IDs and descriptions are the built-in /api/auth/users contract.
// Unknown role metadata is source data, not a translation guess.
const ROLE_MESSAGES: Record<string, { label: MessageKey; description: MessageKey }> = {
  viewer: { label: "access.admin.roles.viewer.label", description: "access.admin.roles.viewer.description" },
  operator: { label: "access.admin.roles.operator.label", description: "access.admin.roles.operator.description" },
  admin: { label: "access.admin.roles.admin.label", description: "access.admin.roles.admin.description" },
};

/** Пользователи, роли и ключи API; только роль «Администратор», сервер проверяет повторно. */
export function AdminPage() {
  const { timeZone } = useTimeZone();
  const queryClient = useQueryClient();
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const canManage = bootstrapEffectiveRole(bootstrap.data) === "admin";
  const inventory = useQuery({ queryKey: ["admin-users"], queryFn: api.adminUsers, enabled: canManage, staleTime: 30_000, refetchOnWindowFocus: false });
  const apiKeys = useQuery({ queryKey: ["admin-api-keys"], queryFn: api.apiKeys, enabled: canManage, staleTime: 30_000, refetchOnWindowFocus: false });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [resetUser, setResetUser] = useState<{ id: number; username: string } | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [keyLabel, setKeyLabel] = useState("");
  const [keyRole, setKeyRole] = useState("viewer");
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null);
  const [accountFilter, setAccountFilter] = useState<AccountFilter>("people");
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    void queryClient.invalidateQueries({ queryKey: ["admin-api-keys"] });
  };
  const createUser = useMutation({ mutationFn: api.createUser, onSuccess: () => { setUsername(""); setPassword(""); setRole("viewer"); refresh(); } });
  const updateUser = useMutation({ mutationFn: ({ id, body }: { id: number; body: { role?: string; is_active?: boolean } }) => api.updateUser(id, body), onSuccess: refresh });
  const passwordReset = useMutation({ mutationFn: ({ id, password: next }: { id: number; password: string }) => api.resetUserPassword(id, next), onSuccess: () => { setResetPassword(""); setResetUser(null); refresh(); } });
  const createApiKey = useMutation({ mutationFn: api.createApiKey, onSuccess: (result) => { setKeyLabel(""); setKeyRole("viewer"); setOneTimeToken(result.token); refresh(); } });
  const revokeApiKey = useMutation({ mutationFn: api.revokeApiKey, onSuccess: refresh });

  const title = t("access.admin.title");
  if (bootstrap.isLoading) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="loading"/></section>;
  if (!canManage) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="denied" detail={t("access.admin.error.denied")}/></section>;
  if (inventory.isLoading) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="loading"/></section>;
  if (inventory.isError || !inventory.data) return <section className="sli-ds-report"><PageHeader title={title}/><StateView state="unavailable" detail={t("access.admin.error.unavailable")} onRetry={() => void inventory.refetch()}/></section>;

  const roles = inventory.data.roles.map((role) => Object.hasOwn(ROLE_MESSAGES, role.id)
    ? { ...role, label: t(ROLE_MESSAGES[role.id].label), description: t(ROLE_MESSAGES[role.id].description) }
    : role);
  const visibleUsers = filterAccounts(inventory.data.items, accountFilter);
  const roleOptions = roles.map((item) => <option key={item.id} value={item.id}>{item.label}</option>);
  const submitUser = (event: FormEvent) => {
    event.preventDefault();
    if (window.confirm(t("access.admin.confirm.createUser", { username: username.trim(), role }))) createUser.mutate({ username: username.trim(), password, role });
  };
  const submitReset = (event: FormEvent) => {
    event.preventDefault();
    if (resetUser && window.confirm(t("access.admin.confirm.resetPassword", { username: resetUser.username }))) passwordReset.mutate({ id: resetUser.id, password: resetPassword });
  };
  const submitKey = (event: FormEvent) => {
    event.preventDefault();
    if (window.confirm(t("access.admin.confirm.createKey", { label: keyLabel.trim(), role: keyRole }))) createApiKey.mutate({ label: keyLabel.trim(), role: keyRole });
  };
  const keyActive = (key: ApiKeyInventoryItem) => key.is_active && !key.revoked_at;

  const userColumns: TableColumn<UserRow>[] = [
    { key: "username", label: t("access.admin.users.col.username") },
    { key: "role", label: t("access.admin.users.col.role"), render: (user) => <select aria-label={t("access.admin.users.aria.role", { username: user.username })} value={user.role} onChange={(event) => {
      const nextRole = event.target.value;
      if (window.confirm(t("access.admin.confirm.changeRole", { username: user.username, role: nextRole }))) updateUser.mutate({ id: user.id, body: { role: nextRole } });
    }}>{roleOptions}</select> },
    { key: "is_active", label: t("access.admin.users.col.status"), render: (user) => <button type="button" className="sli-ds-button" disabled={updateUser.isPending} onClick={() => {
      const active = !user.is_active;
      if (window.confirm(t("access.admin.confirm.toggleUser", { action: active ? t("access.admin.action.enable") : t("access.admin.action.disable"), username: user.username }))) updateUser.mutate({ id: user.id, body: { is_active: active } });
    }}>{user.is_active ? t("access.admin.status.active") : t("access.admin.status.disabled")}</button> },
    { key: "last_login_at", label: t("access.admin.users.col.lastLogin"), render: (user) => (formatDateTime(user.last_login_at, timeZone)) },
    { key: "reset", label: t("access.admin.users.col.actions"), render: (user) => <button type="button" className="sli-ds-button" disabled={!user.is_active || passwordReset.isPending} onClick={() => { setResetPassword(""); setResetUser({ id: user.id, username: user.username }); }}>{t("access.admin.action.resetPassword")}</button> },
  ];
  const keyColumns: TableColumn<ApiKeyInventoryItem>[] = [
    { key: "label", label: t("access.admin.keys.col.label") },
    { key: "key_prefix", label: t("access.admin.keys.col.prefix"), render: (key) => <code>{key.key_prefix}…</code> },
    { key: "role", label: t("access.admin.keys.col.role"), render: (key) => roles.find((item) => item.id === key.role)?.label ?? key.role },
    { key: "created_at", label: t("access.admin.keys.col.created"), render: (key) => (formatDateTime(key.created_at, timeZone)) },
    { key: "last_used_at", label: t("access.admin.keys.col.lastUsed"), render: (key) => (key.last_used_at ? formatDateTime(key.last_used_at, timeZone) : t("access.admin.keys.notUsed")) },
    { key: "status", label: t("access.admin.users.col.status"), render: (key) => <Badge tone={keyActive(key) ? "success" : "danger"}>{keyActive(key) ? t("access.admin.status.active") : t("access.admin.status.revoked")}</Badge> },
    { key: "revoke", label: t("access.admin.keys.col.action"), render: (key) => (keyActive(key)
      ? <button type="button" className="sli-ds-button" disabled={revokeApiKey.isPending} onClick={() => {
        if (window.confirm(t("access.admin.confirm.revokeKey", { label: key.label, prefix: key.key_prefix ?? "" }))) revokeApiKey.mutate(key.id);
      }}>{t("access.admin.action.revoke")}</button> : EMPTY_VALUE) },
  ];

  return <section className="sli-ds-report">
    <PageHeader title={title} subtitle={t("access.admin.subtitle")}/>

    <h2 className="sli-ds-section-title">{t("access.admin.section.roles")}</h2>
    <ul className="sli-ds-link-list">{roles.map((item) => <li key={item.id}><Badge tone="accent">{item.label}</Badge> {item.description}</li>)}</ul>

    <form className="sli-ds-filters" aria-label={t("access.admin.section.newUser")} onSubmit={submitUser}>
      <h2 className="sli-ds-section-title">{t("access.admin.section.newUser")}</h2>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="new-username">{t("access.admin.field.username")}</label><input id="new-username" required minLength={1} value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username"/></div>
        <div className="sli-ds-field"><label htmlFor="new-password">{t("access.admin.field.password")}</label><input id="new-password" required minLength={12} type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password"/></div>
        <div className="sli-ds-field"><label htmlFor="new-role">{t("access.admin.field.role")}</label><select id="new-role" value={role} onChange={(event) => setRole(event.target.value)}>{roleOptions}</select></div>
      </div>
      {createUser.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.createUser")}</p> : null}
      <div className="sli-ds-filters__actions"><button type="submit" className="sli-ds-button" data-variant="primary" disabled={createUser.isPending}>{createUser.isPending ? t("access.admin.button.creating") : t("access.admin.button.create")}</button></div>
    </form>

    <h2 className="sli-ds-section-title">{t("access.admin.section.users")}</h2>
    <div className="sli-ds-filters"><div className="sli-ds-filters__fields">
      <AccountFilterField value={accountFilter} onChange={(value) => { setAccountFilter(value); setResetUser(null); setResetPassword(""); }}/>
    </div></div>
    {visibleUsers.length ? <DataTable columns={userColumns} rows={visibleUsers} rowKey={(user) => String(user.id)} caption={t("access.admin.section.users")}/> : <StateView state="empty" detail={t(accountFilter === "service" ? "access.accountFilter.emptyService" : "access.admin.users.empty")}/>}
    {updateUser.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.updateUser")}</p> : null}

    {resetUser ? <form className="sli-ds-filters" aria-label={t("access.admin.section.resetPassword", { username: resetUser.username })} onSubmit={submitReset}>
      <h2 className="sli-ds-section-title">{t("access.admin.section.resetPassword", { username: resetUser.username })}</h2>
      <Note title={t("access.admin.reset.warning.title")}>{t("access.admin.reset.warning.text")}</Note>
      <div className="sli-ds-field"><label htmlFor="reset-password">{t("access.admin.reset.newPassword")}</label><input id="reset-password" required minLength={12} type="password" value={resetPassword} onChange={(event) => setResetPassword(event.target.value)} autoComplete="new-password"/></div>
      {passwordReset.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.resetPassword")}</p> : null}
      <div className="sli-ds-filters__actions">
        <button type="button" className="sli-ds-button" onClick={() => { setResetPassword(""); setResetUser(null); }}>{t("access.admin.button.cancel")}</button>
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={passwordReset.isPending}>{passwordReset.isPending ? t("access.admin.button.resetting") : t("access.admin.button.confirmReset")}</button>
      </div>
    </form> : null}

    <h2 className="sli-ds-section-title">{t("access.admin.section.keys")}</h2>
    <p className="sli-ds-header__subtitle">{t("access.admin.keys.subtitle")}</p>
    <form className="sli-ds-filters" aria-label={t("access.admin.button.createKey")} onSubmit={submitKey}>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="key-label">{t("access.admin.keys.field.label")}</label><input id="key-label" required maxLength={120} value={keyLabel} onChange={(event) => setKeyLabel(event.target.value)} placeholder={t("access.admin.keys.field.label.placeholder")} autoComplete="off"/></div>
        <div className="sli-ds-field"><label htmlFor="key-role">{t("access.admin.keys.field.role")}</label><select id="key-role" value={keyRole} onChange={(event) => setKeyRole(event.target.value)}>{roleOptions}</select></div>
      </div>
      {createApiKey.isError ? <p className="sli-ds-field__error" role="alert">{t("access.admin.error.createKey")}</p> : null}
      <div className="sli-ds-filters__actions"><button type="submit" className="sli-ds-button" data-variant="primary" disabled={createApiKey.isPending}>{createApiKey.isPending ? t("access.admin.button.creating") : t("access.admin.button.createKey")}</button></div>
    </form>
    {oneTimeToken ? <Note title={t("access.admin.keys.copy.title")}>
      {t("access.admin.keys.copy.text")}
      <pre className="sli-ds-pre">{oneTimeToken}</pre>
      <button type="button" className="sli-ds-button" onClick={() => setOneTimeToken(null)}>{t("access.admin.keys.copy.dismiss")}</button>
    </Note> : null}
    {apiKeys.isLoading ? <StateView state="loading"/>
      : apiKeys.isError ? <StateView state="unavailable" detail={t("access.admin.error.keysUnavailable")} onRetry={() => void apiKeys.refetch()}/>
        : apiKeys.data?.items.length ? <DataTable columns={keyColumns} rows={apiKeys.data.items} rowKey={(key) => String(key.id)} caption={t("access.admin.section.keys")}/> : <StateView state="empty" detail={t("access.admin.keys.empty")}/>}
    <FieldError error={revokeApiKey.isError ? new Error(t("access.admin.error.revokeKey")) : null}/>
  </section>;
}
