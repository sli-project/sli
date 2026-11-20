export type ThemePreference = "system" | "light" | "dark";
export const THEME_STORAGE_KEY = "sli.theme";
export const THEME_PREFERENCES: readonly ThemePreference[] = ["system", "light", "dark"];

export function storedTheme(): ThemePreference {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (value === "light" || value === "dark") return value;
  } catch { /* storage may be blocked */ }
  return "system";
}

/** "system" removes the attribute so the prefers-color-scheme rules in tokens.css apply. */
export function applyTheme(theme: ThemePreference): void {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
}

export function setTheme(theme: ThemePreference): void {
  try {
    if (theme === "system") window.localStorage.removeItem(THEME_STORAGE_KEY);
    else window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch { /* the choice then lasts only for this page view */ }
  applyTheme(theme);
}
