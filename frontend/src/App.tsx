import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import DashboardLayout from './components/layout/DashboardLayout'
import LoadingState from './components/ui/LoadingState'
import { useAuthStore, useAuthStoreSync } from './store'
import { hasRole, UserRole } from './utils/permissions'
import { createSocTheme } from './theme'
import {
  THEME_PREFERENCE_EVENT,
  getStoredThemePreference,
  resolveThemePreference,
  ThemePreference,
} from './utils/themePreference'

const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const AlertQueue = lazy(() => import('./pages/AlertQueue'))
const AlertDetail = lazy(() => import('./pages/AlertDetail'))
const Incidents = lazy(() => import('./pages/Incidents'))
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'))
const MitreMatrix = lazy(() => import('./pages/MitreMatrix'))
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'))
const IOCDetail = lazy(() => import('./pages/IOCDetail'))
const DetectionRules = lazy(() => import('./pages/DetectionRules'))
const DetectionRuleDetail = lazy(() => import('./pages/DetectionRuleDetail'))
const Events = lazy(() => import('./pages/Events'))
const EventDetail = lazy(() => import('./pages/EventDetail'))
const Feedback = lazy(() => import('./pages/Feedback'))
const Settings = lazy(() => import('./pages/Settings'))
const Users = lazy(() => import('./pages/Users'))
const LogSources = lazy(() => import('./pages/LogSources'))
const Playbooks = lazy(() => import('./pages/Playbooks'))
const PlaybookDetail = lazy(() => import('./pages/PlaybookDetail'))
const Connectors = lazy(() => import('./pages/Connectors'))
const ConnectorDetail = lazy(() => import('./pages/ConnectorDetail'))
const ActionHistory = lazy(() => import('./pages/ActionHistory'))
const ActionExecutionDetail = lazy(() => import('./pages/ActionExecutionDetail'))
const Organizations = lazy(() => import('./pages/Organizations'))
const OrganizationSettings = lazy(() => import('./pages/OrganizationSettings'))
const OrganizationMembers = lazy(() => import('./pages/OrganizationMembers'))
const OrganizationInvitations = lazy(() => import('./pages/OrganizationInvitations'))
const OrganizationRoles = lazy(() => import('./pages/OrganizationRoles'))
const OrganizationUsage = lazy(() => import('./pages/OrganizationUsage'))
const OrganizationSubscription = lazy(() => import('./pages/OrganizationSubscription'))
const OrganizationApiKeys = lazy(() => import('./pages/OrganizationApiKeys'))
const AICopilotDashboard = lazy(() => import('./pages/AICopilotDashboard'))
const IncidentCopilot = lazy(() => import('./pages/IncidentCopilot'))
const AIReports = lazy(() => import('./pages/AIReports'))
const AITimelineViewer = lazy(() => import('./pages/AITimelineViewer'))
const AIAlertExplanation = lazy(() => import('./pages/AIAlertExplanation'))
const AIIocAnalysis = lazy(() => import('./pages/AIIocAnalysis'))
const AIDetectionSuggestions = lazy(() => import('./pages/AIDetectionSuggestions'))
const AIPlaybookSuggestions = lazy(() => import('./pages/AIPlaybookSuggestions'))

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

const RoleRoute: React.FC<{ children: React.ReactNode; requiredRole: UserRole }> = ({
  children,
  requiredRole,
}) => {
  const user = useAuthStore((state) => state.user)
  if (!user) return null
  return hasRole(user.role, requiredRole) ? <>{children}</> : <Navigate to="/dashboard" replace />
}

function App() {
  useAuthStoreSync()
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => getStoredThemePreference())
  const [systemThemeVersion, setSystemThemeVersion] = useState(0)
  const resolvedMode = resolveThemePreference(themePreference)
  const theme = useMemo(() => createSocTheme(resolvedMode), [resolvedMode, systemThemeVersion])

  useEffect(() => {
    const handlePreferenceChange = (event: Event) => {
      const customEvent = event as CustomEvent<ThemePreference>
      setThemePreference(customEvent.detail || getStoredThemePreference())
    }
    const handleStorageChange = (event: StorageEvent) => {
      if (event.key === 'triageops-theme-preference') {
        setThemePreference(getStoredThemePreference())
      }
    }
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)')
    const handleSystemThemeChange = () => setSystemThemeVersion((value) => value + 1)

    window.addEventListener(THEME_PREFERENCE_EVENT, handlePreferenceChange)
    window.addEventListener('storage', handleStorageChange)
    mediaQuery.addEventListener('change', handleSystemThemeChange)

    return () => {
      window.removeEventListener(THEME_PREFERENCE_EVENT, handlePreferenceChange)
      window.removeEventListener('storage', handleStorageChange)
      mediaQuery.removeEventListener('change', handleSystemThemeChange)
    }
  }, [])

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Suspense fallback={<LoadingState />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/" element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="alerts" element={<AlertQueue />} />
              <Route path="alerts/:alertId" element={<AlertDetail />} />
              <Route path="incidents" element={<Incidents />} />
              <Route path="incidents/:incidentId" element={<IncidentDetail />} />
              <Route path="mitre-matrix" element={<MitreMatrix />} />
              <Route path="threat-intel" element={<ThreatIntel />} />
              <Route path="threat-intel/:iocId" element={<IOCDetail />} />
              <Route path="detection-rules" element={<DetectionRules />} />
              <Route path="detection-rules/:ruleId" element={<DetectionRuleDetail />} />
              <Route path="events" element={<Events />} />
              <Route path="events/:eventId" element={<EventDetail />} />
              <Route path="feedback" element={<Feedback />} />
              <Route path="settings" element={<Settings />} />
              <Route path="users" element={
                <RoleRoute requiredRole="admin">
                  <Users />
                </RoleRoute>
              } />
              <Route path="log-sources" element={<LogSources />} />
              <Route path="playbooks" element={<Playbooks />} />
              <Route path="playbooks/:playbookId" element={<PlaybookDetail />} />
              <Route path="soar/connectors" element={<Connectors />} />
              <Route path="soar/connectors/:connectorId" element={<ConnectorDetail />} />
              <Route path="soar/actions" element={<ActionHistory />} />
              <Route path="soar/actions/:executionId" element={<ActionExecutionDetail />} />
              <Route path="organizations" element={<Organizations />} />
              <Route path="organizations/settings" element={<OrganizationSettings />} />
              <Route path="organizations/members" element={<OrganizationMembers />} />
              <Route path="organizations/invitations" element={<OrganizationInvitations />} />
              <Route path="organizations/roles" element={<OrganizationRoles />} />
              <Route path="organizations/usage" element={<OrganizationUsage />} />
              <Route path="organizations/subscription" element={<OrganizationSubscription />} />
              <Route path="organizations/api-keys" element={<OrganizationApiKeys />} />
              <Route path="ai" element={<AICopilotDashboard />} />
              <Route path="ai/incident-copilot" element={<IncidentCopilot />} />
              <Route path="ai/reports" element={<AIReports />} />
              <Route path="ai/timeline" element={<AITimelineViewer />} />
              <Route path="ai/alert-explanation" element={<AIAlertExplanation />} />
              <Route path="ai/ioc-analysis" element={<AIIocAnalysis />} />
              <Route path="ai/detection-suggestions" element={<AIDetectionSuggestions />} />
              <Route path="ai/playbook-suggestions" element={<AIPlaybookSuggestions />} />
            </Route>
          </Routes>
        </Suspense>
      </Router>
    </ThemeProvider>
  )
}

export default App
