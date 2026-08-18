import React from 'react'
import { Box, Toolbar } from '@mui/material'

interface MainContentProps {
  drawerWidth: number
  children: React.ReactNode
}

const MainContent: React.FC<MainContentProps> = ({ drawerWidth, children }) => {
  const codeStreams = [
    '01 10 11 00 01', '7F A3 09 C1', '101101 001011', '4D 5A 90 00',
    '00 FF 3A 81', '1100 0110 10', '2E 4B A0 19', '010 111 001',
    '9C 31 E7 04', '1010 0101 11', '6A 00 D4 2F', '011 100 110',
  ]

  return (
    <Box
      component="main"
      className="authenticated-cyber-background"
      sx={{
        flexGrow: 1,
        width: { lg: `calc(100% - ${drawerWidth}px)` },
        minHeight: '100vh',
        ml: { lg: `${drawerWidth}px` },
        overflowX: 'hidden',
        boxSizing: 'border-box'
      }}
    >
      <Box className="workspace-cyber-grid" aria-hidden="true" />
      <Box className="workspace-code-rain" aria-hidden="true">
        {codeStreams.map((stream, index) => (
          <span key={index} style={{ '--stream-index': index } as React.CSSProperties}>
            {stream}<br />{stream}<br />{stream}
          </span>
        ))}
      </Box>
      <Toolbar sx={{ minHeight: '72px !important', position: 'relative', zIndex: 1 }} />
      <Box sx={{ px: 3, py: 3, boxSizing: 'border-box', position: 'relative', zIndex: 1 }}>
        {children}
      </Box>
    </Box>
  )
}

export default MainContent
