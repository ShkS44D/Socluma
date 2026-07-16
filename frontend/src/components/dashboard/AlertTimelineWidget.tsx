import React from 'react'
import { Box, Stack, Typography } from '@mui/material'
import { TimelinePoint } from '../../hooks/useDashboardData'

interface AlertTimelineWidgetProps {
  points: TimelinePoint[]
}

const AlertTimelineWidget: React.FC<AlertTimelineWidgetProps> = ({ points }) => {
  const maxValue = Math.max(...points.map((point) => point.value), 0)

  if (points.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No recent alert activity available.
      </Typography>
    )
  }

  return (
    <Box sx={{ height: 300, width: '100%', display: 'flex', alignItems: 'flex-end' }}>
      <Stack direction="row" spacing={1.5} sx={{ height: '100%', width: '100%', alignItems: 'flex-end' }}>
        {points.map((point) => (
          <Stack key={point.label} spacing={1} alignItems="center" sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary">
              {point.value}
            </Typography>
            <Box
              sx={{
                width: '100%',
                borderRadius: 1,
                minHeight: 18,
                height: maxValue === 0 ? 18 : `${Math.max((point.value / maxValue) * 180, 18)}px`,
                background: 'linear-gradient(180deg, #38bdf8 0%, #0f172a 100%)',
                border: '1px solid',
                borderColor: 'divider',
              }}
            />
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{ textAlign: 'center', whiteSpace: 'nowrap' }}
            >
              {point.label}
            </Typography>
          </Stack>
        ))}
      </Stack>
    </Box>
  )
}

export default AlertTimelineWidget
