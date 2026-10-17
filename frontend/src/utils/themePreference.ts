export type ThemePreference = 'dark' | 'light' | 'system'

export const THEME_PREFERENCE_KEY = 'socluma-theme-preference'
export const THEME_PREFERENCE_EVENT = 'socluma-theme-preference-changed'

export const getStoredThemePreference = (): ThemePreference => {
  const stored = window.localStorage.getItem(THEME_PREFERENCE_KEY)
    || window.localStorage.getItem('vigilantai-theme-preference')
  if (stored === 'dark' || stored === 'light' || stored === 'system') {
    window.localStorage.setItem(THEME_PREFERENCE_KEY, stored)
    window.localStorage.removeItem('vigilantai-theme-preference')
  }
  return stored === 'dark' || stored === 'light' || stored === 'system' ? stored : 'dark'
}

export const resolveThemePreference = (preference: ThemePreference): 'dark' | 'light' => {
  if (preference !== 'system') return preference
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export const saveThemePreference = (preference: ThemePreference) => {
  window.localStorage.setItem(THEME_PREFERENCE_KEY, preference)
  window.localStorage.removeItem('vigilantai-theme-preference')
  window.dispatchEvent(new CustomEvent(THEME_PREFERENCE_EVENT, { detail: preference }))
}
