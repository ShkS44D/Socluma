import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import DashboardLayout from './components/layout/DashboardLayout'
import LoadingState from './components/ui/LoadingState'
import { useAuthStore, useAuthStoreSync, usePermissionStore } from './store'
import { createSocTheme } from './theme'
import {
  THEME_PREFERENCE_EVENT,
  getStoredThemePreference,
  resolveThemePreference,
  ThemePreference,
} from './utils/themePreference'

const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'))
const ResetPassword = lazy(() => import('./pages/ResetPassword'))
const VerifyEmail = lazy(() => import('./pages/VerifyEmail'))
const AccountSecurity = lazy(() => import('./pages/AccountSecurity'))
const Unauthorized = lazy(() => import('./pages/Unauthorized'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const AlertQueue = lazy(() => import('./pages/AlertQueue'))
const AlertDetail = lazy(() => import('./pages/AlertDetail'))
const Incidents = lazy(() => import('./pages/Incidents'))
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'))
const MitreMatrix = lazy(() => import('./pages/MitreMatrix'))
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'))
const IOCDetail = lazy(() => import('./pages/IOCDetail'))
const IOCCommercialWorkspace = lazy(() => import('./pages/IOCCommercialWorkspace'))
const DetectionRules = lazy(() => import('./pages/DetectionRules'))
const DetectionRuleDetail = lazy(() => import('./pages/DetectionRuleDetail'))
const DetectionEngineering = lazy(() => import('./pages/DetectionEngineering'))
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
const AuditLogs = lazy(() => import('./pages/AuditLogs'))
const SearchWorkspace = lazy(() => import('./pages/SearchWorkspace'))
const EntityDetail = lazy(() => import('./pages/EntityDetail'))
const Investigations = lazy(() => import('./pages/Investigations'))
const InvestigationDetail = lazy(() => import('./pages/InvestigationDetail'))
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

const PermissionRoute: React.FC<{ children: React.ReactNode; permission: string }> = ({
  children,
  permission,
}) => {
  const loaded = usePermissionStore((state) => state.loaded)
  const can = usePermissionStore((state) => state.can)
  if (!loaded) return <LoadingState />
  return can(permission) ? <>{children}</> : <Unauthorized />
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
      if (event.key === 'vigilantai-theme-preference') {
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
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
            <Route path="/" element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<PermissionRoute permission="organization.view"><Dashboard /></PermissionRoute>} />
              <Route path="alerts" element={<PermissionRoute permission="alerts.view"><AlertQueue /></PermissionRoute>} />
              <Route path="alerts/:alertId" element={<PermissionRoute permission="alerts.view"><AlertDetail /></PermissionRoute>} />
              <Route path="incidents" element={<PermissionRoute permission="incidents.view"><Incidents /></PermissionRoute>} />
              <Route path="incidents/:incidentId" element={<PermissionRoute permission="incidents.view"><IncidentDetail /></PermissionRoute>} />
              <Route path="mitre-matrix" element={<PermissionRoute permission="detections.view"><MitreMatrix /></PermissionRoute>} />
              <Route path="threat-intel" element={<PermissionRoute permission="threat_intelligence.view"><ThreatIntel /></PermissionRoute>} />
              <Route path="threat-intel/:iocId" element={<PermissionRoute permission="threat_intelligence.view"><IOCDetail /></PermissionRoute>} />
              <Route path="threat-intel/review" element={<PermissionRoute permission="ioc.review.assign"><IOCCommercialWorkspace mode="review" /></PermissionRoute>} />
              <Route path="threat-intel/watchlists" element={<PermissionRoute permission="ioc.watchlists.view"><IOCCommercialWorkspace mode="watchlists" /></PermissionRoute>} />
              <Route path="threat-intel/hunts" element={<PermissionRoute permission="ioc.hunts.manage"><IOCCommercialWorkspace mode="hunts" /></PermissionRoute>} />
              <Route path="threat-intel/sources" element={<PermissionRoute permission="threat_intelligence.sources.manage"><IOCCommercialWorkspace mode="sources" /></PermissionRoute>} />
              <Route path="threat-intel/taxii" element={<PermissionRoute permission="threat_intelligence.sync"><IOCCommercialWorkspace mode="taxii" /></PermissionRoute>} />
              <Route path="threat-intel/misp" element={<PermissionRoute permission="threat_intelligence.sync"><IOCCommercialWorkspace mode="misp" /></PermissionRoute>} />
              <Route path="threat-intel/bulk" element={<PermissionRoute permission="ioc.bulk_manage"><IOCCommercialWorkspace mode="bulk" /></PermissionRoute>} />
              <Route path="threat-intel/graph" element={<PermissionRoute permission="ioc.graph.view"><IOCCommercialWorkspace mode="graph" /></PermissionRoute>} />
              <Route path="threat-intel/detections" element={<PermissionRoute permission="ioc.detection.generate"><IOCCommercialWorkspace mode="detections" /></PermissionRoute>} />
              <Route path="threat-intel/recommendations" element={<PermissionRoute permission="ioc.response.recommend"><IOCCommercialWorkspace mode="recommendations" /></PermissionRoute>} />
              <Route path="threat-intel/reports" element={<PermissionRoute permission="ioc.reports.export"><IOCCommercialWorkspace mode="reports" /></PermissionRoute>} />
              <Route path="detection-rules" element={<PermissionRoute permission="detections.view"><DetectionRules /></PermissionRoute>} />
              <Route path="detection-rules/:ruleId" element={<PermissionRoute permission="detections.view"><DetectionRuleDetail /></PermissionRoute>} />
              <Route path="detection-engineering" element={<PermissionRoute permission="detections.view"><DetectionEngineering /></PermissionRoute>} />
              <Route path="events" element={<PermissionRoute permission="alerts.view"><Events /></PermissionRoute>} />
              <Route path="events/:eventId" element={<PermissionRoute permission="alerts.view"><EventDetail /></PermissionRoute>} />
              <Route path="feedback" element={<Feedback />} />
              <Route path="settings" element={<PermissionRoute permission="settings.view"><Settings /></PermissionRoute>} />
              <Route path="account-security" element={<AccountSecurity />} />
              <Route path="users" element={<PermissionRoute permission="users.view"><Users /></PermissionRoute>} />
              <Route path="log-sources" element={<PermissionRoute permission="collectors.view"><LogSources /></PermissionRoute>} />
              <Route path="playbooks" element={<PermissionRoute permission="playbooks.view"><Playbooks /></PermissionRoute>} />
              <Route path="playbooks/:playbookId" element={<PermissionRoute permission="playbooks.view"><PlaybookDetail /></PermissionRoute>} />
              <Route path="soar/connectors" element={<PermissionRoute permission="soar.view"><Connectors /></PermissionRoute>} />
              <Route path="soar/connectors/:connectorId" element={<PermissionRoute permission="soar.view"><ConnectorDetail /></PermissionRoute>} />
              <Route path="soar/actions" element={<PermissionRoute permission="soar.view"><ActionHistory /></PermissionRoute>} />
              <Route path="soar/actions/:executionId" element={<PermissionRoute permission="soar.view"><ActionExecutionDetail /></PermissionRoute>} />
              <Route path="organizations" element={<PermissionRoute permission="organization.view"><Organizations /></PermissionRoute>} />
              <Route path="organizations/settings" element={<PermissionRoute permission="organization.update"><OrganizationSettings /></PermissionRoute>} />
              <Route path="organizations/members" element={<PermissionRoute permission="users.view"><OrganizationMembers /></PermissionRoute>} />
              <Route path="organizations/invitations" element={<PermissionRoute permission="users.view"><OrganizationInvitations /></PermissionRoute>} />
              <Route path="organizations/roles" element={<PermissionRoute permission="roles.view"><OrganizationRoles /></PermissionRoute>} />
              <Route path="organizations/usage" element={<PermissionRoute permission="usage.view"><OrganizationUsage /></PermissionRoute>} />
              <Route path="organizations/subscription" element={<PermissionRoute permission="subscriptions.view"><OrganizationSubscription /></PermissionRoute>} />
              <Route path="organizations/api-keys" element={<PermissionRoute permission="api_keys.view"><OrganizationApiKeys /></PermissionRoute>} />
              <Route path="audit-logs" element={<PermissionRoute permission="audit.view"><AuditLogs /></PermissionRoute>} />
              <Route path="search" element={<PermissionRoute permission="search.events"><SearchWorkspace /></PermissionRoute>} />
              <Route path="entities/:entityId" element={<PermissionRoute permission="entities.view"><EntityDetail /></PermissionRoute>} />
              <Route path="investigations" element={<PermissionRoute permission="investigations.view"><Investigations /></PermissionRoute>} />
              <Route path="investigations/:investigationId" element={<PermissionRoute permission="investigations.view"><InvestigationDetail /></PermissionRoute>} />
              <Route path="ai" element={<PermissionRoute permission="triage_ai.use"><AICopilotDashboard /></PermissionRoute>} />
              <Route path="ai/incident-copilot" element={<PermissionRoute permission="triage_ai.use"><IncidentCopilot /></PermissionRoute>} />
              <Route path="ai/reports" element={<PermissionRoute permission="triage_ai.use"><AIReports /></PermissionRoute>} />
              <Route path="ai/timeline" element={<PermissionRoute permission="triage_ai.use"><AITimelineViewer /></PermissionRoute>} />
              <Route path="ai/alert-explanation" element={<PermissionRoute permission="triage_ai.use"><AIAlertExplanation /></PermissionRoute>} />
              <Route path="ai/ioc-analysis" element={<PermissionRoute permission="triage_ai.use"><AIIocAnalysis /></PermissionRoute>} />
              <Route path="ai/detection-suggestions" element={<PermissionRoute permission="triage_ai.use"><AIDetectionSuggestions /></PermissionRoute>} />
              <Route path="ai/playbook-suggestions" element={<PermissionRoute permission="triage_ai.use"><AIPlaybookSuggestions /></PermissionRoute>} />
            </Route>
          </Routes>
        </Suspense>
      </Router>
    </ThemeProvider>
  )
}

export default App
