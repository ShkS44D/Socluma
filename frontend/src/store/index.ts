import { create } from 'zustand'
import { User } from '../services/api'
import {
  getStoredAuthToken,
  getStoredRefreshToken,
  setStoredAuthToken,
  clearStoredAuthToken,
  hasUsableStoredToken,
  AUTH_LOGOUT_EVENT
} from '../services/api/authStorage'
import { useEffect } from 'react'

interface AuthState {
  token: string | null
  refreshToken: string | null
  user: User | null
  isAuthenticated: boolean
  login: (token: string, refreshToken?: string | null) => void
  logout: () => void
  setUser: (user: User) => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: getStoredAuthToken(),
  refreshToken: getStoredRefreshToken(),
  user: null,
  isAuthenticated: hasUsableStoredToken(),
  login: (token: string, refreshToken?: string | null) => {
    const sanitizedToken = setStoredAuthToken(token, refreshToken)
    set({ token: sanitizedToken, refreshToken: refreshToken || getStoredRefreshToken(), isAuthenticated: true })
  },
  logout: () => {
    clearStoredAuthToken()
    set({ token: null, refreshToken: null, user: null, isAuthenticated: false })
  },
  setUser: (user: User) => set({ user }),
}))

export const useAuthStoreSync = () => {
  const logout = useAuthStore((state) => state.logout)
  
  useEffect(() => {
    const handleAuthLogout = () => logout()
    window.addEventListener(AUTH_LOGOUT_EVENT, handleAuthLogout)
    return () => window.removeEventListener(AUTH_LOGOUT_EVENT, handleAuthLogout)
  }, [logout])
}
