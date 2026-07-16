export type ThemePreference = 'dark' | 'light' | 'system'

export const THEME_PREFERENCE_KEY = 'triageops-theme-preference'
export const THEME_PREFERENCE_EVENT = 'triageops-theme-preference-changed'

export const getStoredThemePreference = (): ThemePreference => {
  const stored = window.localStorage.getItem(THEME_PREFERENCE_KEY)
  return stored === 'dark' || stored === 'light' || stored === 'system' ? stored : 'dark'
}

export const resolveThemePreference = (preference: ThemePreference): 'dark' | 'light' => {
  if (preference !== 'system') return preference
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export const saveThemePreference = (preference: ThemePreference) => {
  window.localStorage.setItem(THEME_PREFERENCE_KEY, preference)
  window.dispatchEvent(new CustomEvent(THEME_PREFERENCE_EVENT, { detail: preference }))
}
