import React from 'react'
import { Box, Paper, Typography } from '@mui/material'
import { TimelineItem } from '../../services/api'
import { formatDateTimePKT } from '../../utils/time'

interface IncidentTimelineProps {
  items: TimelineItem[]
}

const IncidentTimeline: React.FC<IncidentTimelineProps> = ({ items }) => {
  const formatDate = (date: string) => formatDateTimePKT(date)

  if (items.length === 0) {
    return <Typography variant="body2" color="text.secondary">No timeline items available.</Typography>
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {items.map((item) => (
        <Paper key={item.id} sx={{ p: 2, position: 'relative', pl: 4 }}>
          <Box
            sx={{
              position: 'absolute',
              left: 0,
              top: '50%',
              transform: 'translateY(-50%)',
              width: 12,
              height: 12,
              borderRadius: '50%',
              bgcolor: 'primary.main',
              mx: 2
            }}
          />
          <Typography variant="subtitle2">{item.title}</Typography>
          <Typography variant="caption" color="text.secondary" display="block">
            {formatDate(item.created_at)}
          </Typography>
          {item.description && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {item.description}
            </Typography>
          )}
          {item.actor && (
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.5 }}>
              By: {item.actor.name || item.actor.email}
            </Typography>
          )}
        </Paper>
      ))}
    </Box>
  )
}

export default IncidentTimeline
