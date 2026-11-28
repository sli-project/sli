/** Value-free N01–N08 registry and N10 presentation API. */
export type NotificationKind = "smtp" | "telegram";
export type TelegramSetupErrorCode = "telegram_setup_invalid_proxy" | "telegram_setup_invalid_token" | "telegram_setup_network" | "telegram_setup_tls"
  | "telegram_setup_timeout" | "telegram_setup_unavailable" | "telegram_setup_provider_unavailable"
  | "telegram_setup_rate_limited" | "telegram_setup_conflict" | "telegram_setup_protocol" | "telegram_setup_failed";
export type TelegramSetup = {
  proxy_url?: string; secret_set?: boolean; chat_bound?: boolean; chat_name?: string | null; bot_name?: string;
  chats?: { choice: string; name: string }[];
  job_id?: string; state?: string; test_state?: string | null; test_job_id?: string | null;
};
export type NotificationChannel = {
  kind: NotificationKind; enabled: boolean; tls_mode: "starttls" | "tls";
  secret_ref: string; state: string; revision: number; updated_at: string;
  last_accepted_at: string | null; last_attempt_at: string | null; last_result_code: string | null; secret_status: string | null;
};
export type NotificationSubscription = {
  id: string; owner_user_id: number; recipient_user_id: number; channel: NotificationKind;
  enabled: boolean; revision: number; updated_at: string;
};
export type NotificationDelivery = {
  id: string; subscription_id: string; object_id: string; object_kind: string;
  object_severity: string | null; channel: NotificationKind; state: string; attempts: number | null;
  result_code: string | null; created_at: string; updated_at: string; available_at: string | null;
  finding_id: number | null;
  problem_title?: string | null;
  occurrence_count?: number;
  first_at?: string;
  delivery_reason?: "live" | "pipeline_delay" | "historical_replay" | "history_import" | null;
  delay_minutes?: number | null;
};
export type NotificationStatus = "accepted" | "errors" | "waiting" | "other";
export type NotificationWorkspace = {
  channels: NotificationChannel[]; subscriptions: NotificationSubscription[];
  counts: Record<"total" | "new_count" | NotificationStatus, number | null>;
  items: NotificationDelivery[]; has_more: boolean; next_cursor: string | null;
  previous_login_at: string | null; can_configure: boolean;
};


export type SmtpSetup = {
  host: string; port: number; username: string; sender: string; secret_set: boolean; self_user_id: number; needs_save: boolean;
  recipients: { user_id: number; mailbox: string }[]; revision: number; tls_mode: "tls" | "starttls"; enabled: boolean;
};
export type SmtpSetupSave = Omit<SmtpSetup, "secret_set" | "self_user_id" | "needs_save"> & { password: string };
export type SmtpSetupResult = Pick<SmtpSetup, "secret_set" | "needs_save" | "revision">;
export type NotificationScheduleInput = {
  report_key: "security.problems" | "file-audit.mass-operations";
  filters: Record<string, string>; timezone: string; local_time: string;
  weekday: number | null; period_days: number; language: "ru" | "en";
  enabled: boolean; subscription_ids: string[];
};
export type NotificationSchedule = NotificationScheduleInput & {
  id: string; owner_user_id: number; revision: number; created_at: string;
};
