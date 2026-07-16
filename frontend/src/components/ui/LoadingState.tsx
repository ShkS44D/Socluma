import React from 'react'
import { Box, CircularProgress, Typography } from '@mui/material'

interface LoadingStateProps {
  title?: string
  description?: string
}

const LoadingState: React.FC<LoadingStateProps> = ({
  title = 'Loading workspace',
  description = 'Collecting SOC telemetry and analyst context.',
}) => {
  return (
    <Box
      sx={{
        minHeight: 260,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 2,
        textAlign: 'center',
      }}
    >
      <CircularProgress />
      <Box>
        <Typography variant="h6">{title}</Typography>
        <Typography variant="body2" color="text.secondary">
          {description}
        </Typography>
      </Box>
    </Box>
  )
}

export default LoadingState
