import React from 'react'
import {
  AppBar,
  Avatar,
  Box,
  Chip,
  FormControl,
  IconButton,
  Menu,
  MenuItem,
  Select,
  Stack,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import { alpha } from '@mui/material/styles'
import {
  Logout as LogoutIcon,
  Menu as MenuIcon,
  NavigateNext,
} from '@mui/icons-material'
import { Breadcrumbs } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'
import type { HealthCheck, Organization, User } from '../../services/api'
import type { BreadcrumbItem } from '../ui'

interface TopNavigationProps {
  drawerWidth: number
  onToggleSidebar: () => void
  health: HealthCheck | null
  user: User | null
  organizations: Organization[]
  currentOrganization: Organization | null
  breadcrumbItems: BreadcrumbItem[]
  anchorElUser: HTMLElement | null
  onOpenUserMenu: (event: React.MouseEvent<HTMLElement>) => void
  onCloseUserMenu: () => void
  onLogout: () => void
  onSwitchOrganization: (organizationId: string) => void
}

const TopNavigation: React.FC<TopNavigationProps> = ({
  drawerWidth,
  onToggleSidebar,
  health,
  user,
  organizations,
  currentOrganization,
  breadcrumbItems,
  anchorElUser,
  onOpenUserMenu,
  onCloseUserMenu,
  onLogout,
  onSwitchOrganization,
}) => {
  const selectedOrganizationId = currentOrganization?.id || user?.tenant_id || ''
  const visibleOrganizations = selectedOrganizationId && !organizations.some((organization) => organization.id === selectedOrganizationId)
    ? [
        {
          id: selectedOrganizationId,
          name: currentOrganization?.name || 'Default Tenant',
        } as Organization,
        ...organizations,
      ]
    : organizations

  const initials = user?.full_name
    ?.split(' ')
    .map((part: string) => part[0])
    .join('')
    .slice(0, 2)
    .toUpperCase() || user?.email?.slice(0, 2).toUpperCase() || 'SO'

  return (
    <AppBar
      position="fixed"
      sx={{
        width: { lg: `calc(100% - ${drawerWidth}px)` },
        ml: { lg: `${drawerWidth}px` },
      }}
    >
      <Toolbar sx={{ minHeight: 72 }}>
        <IconButton
          color="inherit"
          edge="start"
          onClick={onToggleSidebar}
          sx={{ mr: 2, display: { lg: 'none' } }}
        >
          <MenuIcon />
        </IconButton>
        <Box sx={{ flexGrow: 1 }}>
          <Breadcrumbs
            separator={<NavigateNext fontSize="small" />}
            aria-label="breadcrumb"
            sx={{ color: 'text.secondary' }}
          >
            {breadcrumbItems.map((item, index) =>
              item.href && index < breadcrumbItems.length - 1 ? (
                <Typography
                  key={`${item.label}-${item.href}`}
                  component={RouterLink}
                  to={item.href}
                  sx={{ color: 'text.secondary', textDecoration: 'none' }}
                >
                  {item.label}
                </Typography>
              ) : (
                <Typography key={`${item.label}-${index}`} color="text.primary" variant="body2">
                  {item.label}
                </Typography>
              )
            )}
          </Breadcrumbs>
          <Typography variant="h6" sx={{ mt: 0.5 }}>
            Analyst Workspace
          </Typography>
        </Box>
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <FormControl size="small" sx={{ minWidth: 220 }}>
            <Select
              value={selectedOrganizationId}
              onChange={(event) => onSwitchOrganization(event.target.value)}
              displayEmpty
            >
              {visibleOrganizations.map((organization) => (
                <MenuItem key={organization.id} value={organization.id}>
                  {organization.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Chip
            label={health?.status === 'ok' ? 'Backend Healthy' : 'Backend Disconnected'}
            color={health?.status === 'ok' ? 'success' : 'error'}
            variant="outlined"
            sx={{
              borderColor:
                health?.status === 'ok' ? alpha('#22c55e', 0.45) : alpha('#ef4444', 0.45),
            }}
          />
          <Tooltip title="Account menu">
            <IconButton onClick={onOpenUserMenu} sx={{ p: 0 }}>
              <Avatar sx={{ bgcolor: 'primary.main', color: '#001018' }}>{initials}</Avatar>
            </IconButton>
          </Tooltip>
        </Stack>
        <Menu
          anchorEl={anchorElUser}
          open={Boolean(anchorElUser)}
          onClose={onCloseUserMenu}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
          transformOrigin={{ vertical: 'top', horizontal: 'right' }}
          sx={{ mt: 1 }}
        >
          <MenuItem disabled>
            <Box>
              <Typography variant="body2">{user?.full_name || user?.email || 'User'}</Typography>
              <Typography variant="caption" color="text.secondary">
                {user?.role || 'analyst'}
              </Typography>
            </Box>
          </MenuItem>
          <MenuItem onClick={onLogout}>
            <LogoutIcon fontSize="small" sx={{ mr: 1 }} />
            Logout
          </MenuItem>
        </Menu>
      </Toolbar>
    </AppBar>
  )
}

export default TopNavigation
