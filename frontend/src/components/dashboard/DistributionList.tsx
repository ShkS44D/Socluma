import React from 'react'
import { Box, LinearProgress, Stack, Typography } from '@mui/material'
import { DistributionItem } from '../../hooks/useDashboardData'

interface DistributionListProps {
  items: DistributionItem[]
  emptyMessage: string
}

const DistributionList: React.FC<DistributionListProps> = ({ items, emptyMessage }) => {
  const maxValue = Math.max(...items.map((item) => item.value), 0)

  if (items.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        {emptyMessage}
      </Typography>
    )
  }

  return (
    <Stack spacing={2}>
      {items.map((item) => (
        <Box key={item.label}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 0.75 }}>
            <Typography variant="body2">{item.label}</Typography>
            <Typography variant="body2" color="text.secondary">
              {item.value}
            </Typography>
          </Stack>
          <LinearProgress
            variant="determinate"
            value={maxValue === 0 ? 0 : (item.value / maxValue) * 100}
            sx={{
              height: 10,
              '& .MuiLinearProgress-bar': {
                backgroundColor: item.color,
              },
            }}
          />
        </Box>
      ))}
    </Stack>
  )
}

export default DistributionList
