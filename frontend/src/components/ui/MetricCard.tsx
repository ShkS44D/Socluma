import React from 'react'
import { alpha } from '@mui/material/styles'
import { Box, Card, CardContent, Typography } from '@mui/material'

type MetricSeverity = 'info' | 'success' | 'warning' | 'error'

interface MetricCardProps {
  title: string
  value: string | number
  trend?: string
  icon: React.ReactNode
  severity?: MetricSeverity
}

const accents: Record<MetricSeverity, string> = {
  info: '#38bdf8',
  success: '#22c55e',
  warning: '#f59e0b',
  error: '#ef4444',
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  trend,
  icon,
  severity = 'info',
}) => {
  const accent = accents[severity]

  return (
    <Card sx={{ height: '100%', width: '100%', boxSizing: 'border-box', overflow: 'hidden' }}>
      <CardContent sx={{ display: 'flex', flexDirection: 'column', gap: 2.5, height: '100%', boxSizing: 'border-box' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 2 }}>
          <Box sx={{ minWidth: 0, flexGrow: 1 }}>
            <Typography variant="body2" color="text.secondary" sx={{ wordWrap: 'break-word' }}>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ mt: 1, wordWrap: 'break-word' }}>
              {value}
            </Typography>
          </Box>
          <Box
            sx={{
              width: 44,
              height: 44,
              flexShrink: 0,
              display: 'grid',
              placeItems: 'center',
              borderRadius: 2.5,
              color: accent,
              backgroundColor: alpha(accent, 0.16),
              border: `1px solid ${alpha(accent, 0.28)}`,
            }}
          >
            {icon}
          </Box>
        </Box>
        <Typography variant="caption" color="text.secondary" sx={{ mt: 'auto', wordWrap: 'break-word' }}>
          {trend || 'Live operational telemetry'}
        </Typography>
      </CardContent>
    </Card>
  )
}

export default MetricCard
