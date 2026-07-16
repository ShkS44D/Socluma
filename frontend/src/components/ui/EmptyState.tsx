import React from 'react'
import { Box, Typography } from '@mui/material'

interface EmptyStateProps {
  title: string
  description: string
}

const EmptyState: React.FC<EmptyStateProps> = ({ title, description }) => {
  return (
    <Box
      sx={{
        minHeight: 180,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        gap: 1,
      }}
    >
      <Typography variant="h6">{title}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 420 }}>
        {description}
      </Typography>
    </Box>
  )
}

export default EmptyState
