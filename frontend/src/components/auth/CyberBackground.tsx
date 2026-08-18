import React from 'react'
import { Box } from '@mui/material'

const CyberBackground: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Box className="cyber-auth-background">
    <Box className="cyber-grid" aria-hidden="true" />
    <Box className="cyber-glow cyber-glow-one" aria-hidden="true" />
    <Box className="cyber-glow cyber-glow-two" aria-hidden="true" />
    <Box sx={{ position: 'relative', zIndex: 1, width: '100%' }}>{children}</Box>
  </Box>
)

export default CyberBackground
