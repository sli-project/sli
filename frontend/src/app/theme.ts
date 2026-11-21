export type ThemePreference = "system" | "light" | "dark";
export const THEME_STORAGE_KEY = "sli.theme";
export const THEME_PREFERENCES: readonly ThemePreference[] = ["system", "light", "dark"];

export function storedTheme(): ThemePreference {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (value === "light" || value === "dark" || value === "system") return value;
  } catch { /* storage may be blocked */ }
  return "dark";
}

export function applyTheme(theme: ThemePreference): void {
  document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: ThemePreference): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch { /* the choice then lasts only for this page view */ }
  applyTheme(theme);
}
