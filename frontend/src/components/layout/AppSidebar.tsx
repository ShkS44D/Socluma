import React from 'react'
import {
  Box,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
} from '@mui/material'
import { alpha } from '@mui/material/styles'
import { useLocation, useNavigate } from 'react-router-dom'

export interface NavigationItem {
  text: string
  icon: React.ReactNode
  path: string
  group?: string
}

interface AppSidebarProps {
  drawerWidth: number
  items: NavigationItem[]
  mobileOpen: boolean
  onClose: () => void
}

const SidebarContent: React.FC<{ items: NavigationItem[] }> = ({ items }) => {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <Box sx={{ height: '100%', px: 1.5 }}>
      <Toolbar sx={{ px: 1 }}>
        <Box>
          <Typography variant="h6">VigilantAI</Typography>
          <Typography variant="caption" color="text.secondary">
            SOC Operations Console
          </Typography>
        </Box>
      </Toolbar>
      <List sx={{ mt: 1 }}>
        {items.map((item) => {
          const selected =
            location.pathname === item.path ||
            (item.path !== '/dashboard' && location.pathname.startsWith(item.path))
          const itemIndex = items.indexOf(item)
          const showGroup = item.group && item.group !== items[itemIndex - 1]?.group

          return (
            <React.Fragment key={item.text}>
              {showGroup && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mt: itemIndex === 0 ? 0 : 2, mb: 0.75, px: 2, fontWeight: 700 }}
                >
                  {item.group}
                </Typography>
              )}
              <ListItem disablePadding sx={{ mb: 0.5 }}>
                <ListItemButton
                  selected={selected}
                  onClick={() => navigate(item.path)}
                  sx={{
                    borderRadius: 2,
                    '&.Mui-selected': {
                      backgroundColor: alpha('#38bdf8', 0.14),
                      border: `1px solid ${alpha('#38bdf8', 0.2)}`,
                    },
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 40, color: selected ? 'primary.main' : 'text.secondary' }}>
                    {item.icon}
                  </ListItemIcon>
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            </React.Fragment>
          )
        })}
      </List>
    </Box>
  )
}

const AppSidebar: React.FC<AppSidebarProps> = ({
  drawerWidth,
  items,
  mobileOpen,
  onClose,
}) => {
  return (
    <Box component="nav" sx={{ width: { lg: drawerWidth }, flexShrink: { lg: 0 } }}>
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: 'block', lg: 'none' },
          '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
        }}
      >
        <SidebarContent items={items} />
      </Drawer>
      <Drawer
        variant="permanent"
        open
        sx={{
          display: { xs: 'none', lg: 'block' },
          '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
        }}
      >
        <SidebarContent items={items} />
      </Drawer>
    </Box>
  )
}

export default AppSidebar
