import React, { useEffect, useMemo, useState } from 'react'
import { CssBaseline } from '@mui/material'
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
} from '@mui/icons-material'
import AppSidebar, { NavigationItem } from './AppSidebar'
import MainContent from './MainContent'
import TopNavigation from './TopNavigation'
import type { BreadcrumbItem } from '../ui'
import { useAuthStore, useAuthStoreSync } from '../../store'
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
import { hasRole } from '../../utils/permissions'

const drawerWidth = 280

const DashboardLayout: React.FC = () => {
  useAuthStoreSync()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [anchorElUser, setAnchorElUser] = useState<null | HTMLElement>(null)
  const [health, setHealth] = useState<HealthCheck | null>(null)
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [currentOrganization, setCurrentOrganization] = useState<Organization | null>(null)
  const location = useLocation()
  const navigate = useNavigate()
  const { isAuthenticated, logout, refreshToken, setUser, user } = useAuthStore()

  const filteredNavItems = useMemo<NavigationItem[]>(() => {
    const baseItems: NavigationItem[] = [
      { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard', group: 'Overview' },
      { text: 'Alerts', icon: <AlertsIcon />, path: '/alerts', group: 'Investigations' },
      { text: 'Incidents', icon: <IncidentsIcon />, path: '/incidents', group: 'Investigations' },
      { text: 'MITRE Matrix', icon: <MatrixIcon />, path: '/mitre-matrix', group: 'Investigations' },
      { text: 'AI Copilot', icon: <AIIcon />, path: '/ai', group: 'Investigations' },
    ]

    if (hasRole(user?.role ?? null, 'analyst')) {
      baseItems.push(
        { text: 'Events', icon: <EventsIcon />, path: '/events', group: 'Telemetry' },
        { text: 'Log Sources', icon: <StorageIcon />, path: '/log-sources', group: 'Telemetry' },
        { text: 'Threat Intelligence', icon: <ThreatIntelIcon />, path: '/threat-intel', group: 'Detection' },
        { text: 'Detection Rules', icon: <DetectionRulesIcon />, path: '/detection-rules', group: 'Detection' },
        { text: 'Playbooks', icon: <PlaybooksIcon />, path: '/playbooks', group: 'Automation' },
        { text: 'SOAR Connectors', icon: <ConnectorsIcon />, path: '/soar/connectors', group: 'Automation' },
        { text: 'Feedback', icon: <FeedbackIcon />, path: '/feedback', group: 'Operations' },
      )
    }

    if (hasRole(user?.role ?? null, 'admin')) {
      baseItems.push(
        { text: 'Organizations', icon: <OrganizationsIcon />, path: '/organizations', group: 'Administration' },
        { text: 'User Management', icon: <UsersIcon />, path: '/users', group: 'Administration' },
        { text: 'Members', icon: <UsersIcon />, path: '/organizations/members', group: 'Administration' },
        { text: 'Invitations', icon: <InvitationsIcon />, path: '/organizations/invitations', group: 'Administration' },
        { text: 'Roles', icon: <UsersIcon />, path: '/organizations/roles', group: 'Administration' },
        { text: 'Usage', icon: <StorageIcon />, path: '/organizations/usage', group: 'Administration' },
        { text: 'Subscription', icon: <StorageIcon />, path: '/organizations/subscription', group: 'Administration' },
        { text: 'API Keys', icon: <ApiKeysIcon />, path: '/organizations/api-keys', group: 'Administration' },
        { text: 'Settings', icon: <SettingsIcon />, path: '/settings', group: 'Administration' },
      )
    }

    return baseItems
  }, [user])

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
      'detection-rules': 'Detection Rules',
      playbooks: 'Playbooks',
      soar: 'SOAR',
      connectors: 'Connectors',
      actions: 'Action History',
      events: 'Events',
      'log-sources': 'Log Sources',
      feedback: 'Feedback',
      settings: 'Settings',
      users: 'User Management',
      organizations: 'Organizations',
      ai: 'AI Copilot',
      'incident-copilot': 'Incident Copilot',
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
        }
      })
      .catch(() => {
        if (!cancelled) {
          logout()
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
  }, [isAuthenticated, logout, navigate, setUser])

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
    navigate('/login')
  }

  const handleSwitchOrganization = async (organizationId: string) => {
    if (!organizationId || organizationId === user?.tenant_id) return
    const tokenPair = await switchOrganization(organizationId)
    useAuthStore.getState().login(tokenPair.access_token, tokenPair.refresh_token)
    const [nextUser, orgs, org] = await Promise.all([getMe(), listOrganizations(), getCurrentOrganization()])
    setUser(nextUser)
    setOrganizations(orgs)
    setCurrentOrganization(org)
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
        <Outlet />
      </MainContent>
    </>
  )
}

export default DashboardLayout
