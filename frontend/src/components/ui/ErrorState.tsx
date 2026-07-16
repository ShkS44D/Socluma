import React from 'react'
import { Alert, Button, Stack, Typography } from '@mui/material'

interface ErrorStateProps {
  title?: string
  message: string
  actionLabel?: string
  onRetry?: () => void
}

const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Unable to load data',
  message,
  actionLabel = 'Retry',
  onRetry,
}) => {
  return (
    <Stack spacing={2}>
      <Alert severity="error">
        <Typography variant="subtitle2">{title}</Typography>
        <Typography variant="body2">{message}</Typography>
      </Alert>
      {onRetry && (
        <Button variant="outlined" onClick={onRetry} sx={{ alignSelf: 'flex-start' }}>
          {actionLabel}
        </Button>
      )}
    </Stack>
  )
}

export default ErrorState
