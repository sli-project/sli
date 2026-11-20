/** The supported vocabulary of bundled plugin settings schemas. */
export type SettingsSchema = {
  type: string | string[];
  properties?: Record<string, SettingsSchema>;
  required?: string[];
  additionalProperties?: boolean;
  items?: SettingsSchema;
  oneOf?: SettingsSchema[];
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  default?: unknown;
  "x-label"?: string;
  "x-help"?: string;
  "x-group"?: string;
  "x-secret"?: boolean;
  "x-core-settings"?: string[];
};

export type PluginSettings = {
  plugin_id: string;
  schema: SettingsSchema;
  values: Record<string, unknown>;
  sources: Record<string, string>;
  rules?: Array<{ rule_id: string; name: string; settings: string[]; core_settings: string[] }>;
};
