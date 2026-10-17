import React, { useEffect, useMemo, useState } from 'react'
import { Alert, Box, Button, CssBaseline, IconButton } from '@mui/material'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Dashboard as DashboardIcon,
  Warning as AlertsIcon,
  Report as IncidentsIcon,
  Security as ThreatIntelIcon,
  TrackChanges as DetectionRulesIcon,
  AccountTree as PlaybooksIcon,
  Hub as ConnectorsIcon,
  Event as EventsIcon,
  Feedback as FeedbackIcon,
  Settings as SettingsIcon,
  People as UsersIcon,
  Storage as StorageIcon,
  Business as OrganizationsIcon,
  Mail as InvitationsIcon,
  VpnKey as ApiKeysIcon,
  Psychology as AIIcon,
  GridView as MatrixIcon,
  History as AuditIcon,
  Close as CloseIcon,
  Search as SearchIcon,
  FactCheck as InvestigationIcon,
  PlaylistAddCheck as ReviewIcon,
  Visibility as WatchlistIcon,
  TravelExplore as HuntIcon,
  CloudSync as SourceIcon,
  Assessment as ReportIcon,
} from '@mui/icons-material'
import AppSidebar, { NavigationItem } from './AppSidebar'
import MainContent from './MainContent'
import TopNavigation from './TopNavigation'
import type { BreadcrumbItem } from '../ui'
import { useAuthStore, useAuthStoreSync, usePermissionStore } from '../../store'
import {
  getCurrentOrganization,
  getMe,
  healthCheck,
  HealthCheck,
  listOrganizations,
  logout as logoutRequest,
  Organization,
  switchOrganization,
} from '../../services/api'
import { websocketService } from '../../services/api/websocket'

const drawerWidth = 280

const DashboardLayout: React.FC = () => {
  useAuthStoreSync()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [anchorElUser, setAnchorElUser] = useState<null | HTMLElement>(null)
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [currentOrganization, setCurrentOrganization] = useState<Organization | null>(null)
  const [emailWarningDismissed, setEmailWarningDismissed] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const { isAuthenticated, logout, refreshToken, setUser, user } = useAuthStore()
  const permissions = usePermissionStore((state) => state.permissions)
  const loadPermissions = usePermissionStore((state) => state.load)
  const clearPermissions = usePermissionStore((state) => state.clear)
  const can = (permission: string) => permissions.includes(permission)

  useEffect(() => {
    setEmailWarningDismissed(
      Boolean(user?.id && sessionStorage.getItem(`socluma-email-warning-dismissed:${user.id}`)),
    )
  }, [user?.id])

  const dismissEmailWarning = () => {
    if (user?.id) {
      sessionStorage.setItem(`socluma-email-warning-dismissed:${user.id}`, 'true')
    }
    setEmailWarningDismissed(true)
  }

  const filteredNavItems = useMemo<NavigationItem[]>(() => {
    const baseItems: NavigationItem[] = [
      { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard', group: 'Overview' },
      ...(can('alerts.view') ? [{ text: 'Alerts', icon: <AlertsIcon />, path: '/alerts', group: 'Investigations' }] : []),
      ...(can('incidents.view') ? [{ text: 'Incidents', icon: <IncidentsIcon />, path: '/incidents', group: 'Investigations' }] : []),
      ...(can('search.events') ? [{ text: 'Search', icon: <SearchIcon />, path: '/search', group: 'Investigations' }] : []),
      ...(can('investigations.view') ? [{ text: 'Investigation Workspace', icon: <InvestigationIcon />, path: '/investigations', group: 'Investigations' }] : []),
      ...(can('detections.view') ? [{ text: 'MITRE Matrix', icon: <MatrixIcon />, path: '/mitre-matrix', group: 'Investigations' }] : []),
      ...(can('triage_ai.use') ? [{ text: 'Socluma Copilot', icon: <AIIcon />, path: '/ai', group: 'Investigations' }] : []),
    ]

    if (can('alerts.view') || can('incidents.view')) {
      baseItems.push(
        ...(can('alerts.view') ? [{ text: 'Events', icon: <EventsIcon />, path: '/events', group: 'Telemetry' }] : []),
        ...(can('collectors.view') ? [{ text: 'Log Sources', icon: <StorageIcon />, path: '/log-sources', group: 'Telemetry' }] : []),
        ...(can('threat_intelligence.view') ? [{ text: 'Threat Intelligence', icon: <ThreatIntelIcon />, path: '/threat-intel', group: 'Detection' }] : []),
        ...(can('ioc.review.assign') ? [{ text: 'IOC Review', icon: <ReviewIcon />, path: '/threat-intel/review', group: 'Detection' }] : []),
        ...(can('ioc.watchlists.view') ? [{ text: 'IOC Watchlists', icon: <WatchlistIcon />, path: '/threat-intel/watchlists', group: 'Detection' }] : []),
        ...(can('ioc.hunts.manage') ? [{ text: 'IOC Hunts', icon: <HuntIcon />, path: '/threat-intel/hunts', group: 'Detection' }] : []),
        ...(can('threat_intelligence.sources.manage') ? [{ text: 'Threat Sources', icon: <SourceIcon />, path: '/threat-intel/sources', group: 'Detection' }] : []),
        ...(can('threat_intelligence.sync') ? [{ text: 'TAXII Sync', icon: <SourceIcon />, path: '/threat-intel/taxii', group: 'Detection' }] : []),
        ...(can('threat_intelligence.sync') ? [{ text: 'MISP Sync', icon: <ConnectorsIcon />, path: '/threat-intel/misp', group: 'Detection' }] : []),
        ...(can('ioc.bulk_manage') ? [{ text: 'Bulk IOC Operations', icon: <StorageIcon />, path: '/threat-intel/bulk', group: 'Detection' }] : []),
        ...(can('ioc.graph.view') ? [{ text: 'IOC Graph', icon: <MatrixIcon />, path: '/threat-intel/graph', group: 'Detection' }] : []),
        ...(can('ioc.detection.generate') ? [{ text: 'IOC Detection Drafts', icon: <DetectionRulesIcon />, path: '/threat-intel/detections', group: 'Detection' }] : []),
        ...(can('ioc.response.recommend') ? [{ text: 'Response Recommendations', icon: <PlaybooksIcon />, path: '/threat-intel/recommendations', group: 'Detection' }] : []),
        ...(can('ioc.reports.export') ? [{ text: 'IOC Reports', icon: <ReportIcon />, path: '/threat-intel/reports', group: 'Detection' }] : []),
        ...(can('detections.view') ? [{ text: 'Detection Rules', icon: <DetectionRulesIcon />, path: '/detection-rules', group: 'Detection' }] : []),
        ...(can('playbooks.view') ? [{ text: 'Playbooks', icon: <PlaybooksIcon />, path: '/playbooks', group: 'Automation' }] : []),
        ...(can('soar.view') ? [{ text: 'SOAR Connectors', icon: <ConnectorsIcon />, path: '/soar/connectors', group: 'Automation' }] : []),
        { text: 'Feedback', icon: <FeedbackIcon />, path: '/feedback', group: 'Operations' },
      )
    }
    baseItems.push(
      { text: 'Account Security', icon: <SettingsIcon />, path: '/account-security', group: 'Account' },
    )

    if (can('users.view') || can('organization.update') || can('audit.view')) {
      baseItems.push(
        ...(can('organization.view') ? [{ text: 'Organizations', icon: <OrganizationsIcon />, path: '/organizations', group: 'Administration' }] : []),
        ...(can('users.view') ? [{ text: 'User Management', icon: <UsersIcon />, path: '/users', group: 'Administration' }] : []),
        ...(can('users.view') ? [{ text: 'Members', icon: <UsersIcon />, path: '/organizations/members', group: 'Administration' }] : []),
        ...(can('users.invite') ? [{ text: 'Invitations', icon: <InvitationsIcon />, path: '/organizations/invitations', group: 'Administration' }] : []),
        ...(can('roles.view') ? [{ text: 'Roles', icon: <UsersIcon />, path: '/organizations/roles', group: 'Administration' }] : []),
        ...(can('usage.view') ? [{ text: 'Usage', icon: <StorageIcon />, path: '/organizations/usage', group: 'Administration' }] : []),
        ...(can('subscriptions.view') ? [{ text: 'Subscription', icon: <StorageIcon />, path: '/organizations/subscription', group: 'Administration' }] : []),
        ...(can('api_keys.view') ? [{ text: 'API Keys', icon: <ApiKeysIcon />, path: '/organizations/api-keys', group: 'Administration' }] : []),
        ...(can('audit.view') ? [{ text: 'Audit Logs', icon: <AuditIcon />, path: '/audit-logs', group: 'Administration' }] : []),
        ...(can('settings.view') ? [{ text: 'Settings', icon: <SettingsIcon />, path: '/settings', group: 'Administration' }] : []),
      )
    }

    return baseItems
  }, [permissions])

  const breadcrumbItems = useMemo<BreadcrumbItem[]>(() => {
    const segments = location.pathname.split('/').filter(Boolean)
    if (segments.length === 0) {
      return [{ label: 'Dashboard', href: '/dashboard' }]
    }

    const labelMap: Record<string, string> = {
      dashboard: 'Dashboard',
      alerts: 'Alerts',
      incidents: 'Incidents',
      'mitre-matrix': 'MITRE Matrix',
      'threat-intel': 'Threat Intelligence',
      review: 'IOC Review',
      watchlists: 'IOC Watchlists',
      hunts: 'IOC Hunts',
      sources: 'Threat Sources',
      taxii: 'TAXII',
      misp: 'MISP',
      bulk: 'Bulk Operations',
      graph: 'Relationship Graph',
      detections: 'IOC Detections',
      recommendations: 'Recommendations',
      'detection-rules': 'Detection Rules',
      playbooks: 'Playbooks',
      soar: 'SOAR',
      connectors: 'Connectors',
      actions: 'Action History',
      events: 'Events',
      search: 'Search',
      entities: 'Entities',
      investigations: 'Investigations',
      'log-sources': 'Log Sources',
      feedback: 'Feedback',
      settings: 'Settings',
      users: 'User Management',
      organizations: 'Organizations',
      ai: 'Socluma Copilot',
      'incident-copilot': 'Socluma Copilot',
      timeline: 'Timeline',
      reports: 'Reports',
      'alert-explanation': 'Alert Explanation',
      'ioc-analysis': 'IOC Analysis',
      'detection-suggestions': 'Detection Suggestions',
      'playbook-suggestions': 'Playbook Suggestions',
      members: 'Members',
      invitations: 'Invitations',
      roles: 'Roles',
      usage: 'Usage',
      subscription: 'Subscription',
      'api-keys': 'API Keys',
    }

    const crumbs: BreadcrumbItem[] = []
    let currentPath = ''
    segments.forEach((segment, index) => {
      currentPath += `/${segment}`
      const isLast = index === segments.length - 1
      crumbs.push({
        label: labelMap[segment] || segment,
        href: isLast ? undefined : currentPath,
      })
    })

    return crumbs
  }, [location.pathname])

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login')
      websocketService.disconnect()
      return
    }

    let cancelled = false
    const fetchHealth = async () => {
      try {
        const data = await healthCheck()
        if (!cancelled) {
          setHealth(data)
        }
      } catch (err) {
        console.error('Failed to fetch health status:', err)
      }
    }

    getMe()
      .then((nextUser) => {
        if (!cancelled) {
          setUser(nextUser)
          void loadPermissions()
        }
      })
      .catch(() => {
        if (!cancelled) {
          logout()
          clearPermissions()
        }
      })
    Promise.all([listOrganizations(), getCurrentOrganization()])
      .then(([orgs, org]) => {
        if (!cancelled) {
          setOrganizations(orgs)
          setCurrentOrganization(org)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setOrganizations([])
          setCurrentOrganization(null)
        }
      })
    fetchHealth()
    const interval = setInterval(fetchHealth, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
      websocketService.disconnect()
    }
  }, [clearPermissions, isAuthenticated, loadPermissions, logout, navigate, setUser])

  useEffect(() => {
    if (user && user.tenant_id) {
      websocketService.connect(user.tenant_id)
    }
  }, [user])

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen)
  }

  const handleOpenUserMenu = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorElUser(event.currentTarget)
  }

  const handleCloseUserMenu = () => {
    setAnchorElUser(null)
  }

  const handleLogout = async () => {
    try {
      await logoutRequest(refreshToken)
    } catch (err) {
      console.error('Failed to revoke session during logout:', err)
    }
    logout()
    clearPermissions()
    navigate('/login')
  }

  const handleSwitchOrganization = async (organizationId: string) => {
    if (!organizationId || organizationId === user?.tenant_id) return
    const tokenPair = await switchOrganization(organizationId)
    clearPermissions()
    useAuthStore.getState().login(tokenPair.access_token, tokenPair.refresh_token)
    const [nextUser, orgs, org] = await Promise.all([getMe(), listOrganizations(), getCurrentOrganization()])
    setUser(nextUser)
    setOrganizations(orgs)
    setCurrentOrganization(org)
    await loadPermissions()
    navigate('/dashboard')
  }

  return (
    <>
      <CssBaseline />
      <TopNavigation
        drawerWidth={drawerWidth}
        onToggleSidebar={handleDrawerToggle}
        health={health}
        user={user}
        organizations={organizations}
        currentOrganization={currentOrganization}
        breadcrumbItems={breadcrumbItems}
        anchorElUser={anchorElUser}
        onOpenUserMenu={handleOpenUserMenu}
        onCloseUserMenu={handleCloseUserMenu}
        onLogout={handleLogout}
        onSwitchOrganization={handleSwitchOrganization}
      />
      <AppSidebar
        drawerWidth={drawerWidth}
        items={filteredNavItems}
        mobileOpen={mobileOpen}
        onClose={handleDrawerToggle}
      />
      <MainContent drawerWidth={drawerWidth}>
        {user && user.email_verified === false && !emailWarningDismissed && (
          <Alert
            severity="warning"
            action={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Button color="inherit" size="small" onClick={() => navigate('/account-security')}>
                  Review
                </Button>
                <IconButton
                  color="inherit"
                  size="small"
                  aria-label="Dismiss email verification reminder"
                  onClick={dismissEmailWarning}
                >
                  <CloseIcon fontSize="small" />
                </IconButton>
              </Box>
            }
          >
            Your email address has not been verified.
          </Alert>
        )}
        <Outlet />
      </MainContent>
    </>
  )
}

export default DashboardLayout
