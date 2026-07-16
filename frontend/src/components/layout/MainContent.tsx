import React from 'react'
import { Box, Toolbar } from '@mui/material'

interface MainContentProps {
  drawerWidth: number
  children: React.ReactNode
}

const MainContent: React.FC<MainContentProps> = ({ drawerWidth, children }) => {
  return (
    <Box
      component="main"
      sx={{
        flexGrow: 1,
        width: { lg: `calc(100% - ${drawerWidth}px)` },
        minHeight: '100vh',
        ml: { lg: `${drawerWidth}px` },
        overflowX: 'hidden',
        boxSizing: 'border-box'
      }}
    >
      <Toolbar sx={{ minHeight: '72px !important' }} />
      <Box sx={{ px: 3, py: 3, boxSizing: 'border-box' }}>
        {children}
      </Box>
    </Box>
  )
}

export default MainContent
