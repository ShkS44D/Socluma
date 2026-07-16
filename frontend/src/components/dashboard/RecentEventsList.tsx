import React from 'react'
import { Box, Divider, Stack, Typography } from '@mui/material'
import { SecurityEvent } from '../../services/api'
import { StatusChip } from '../ui'
import { formatDateTime } from '../../utils'

interface RecentEventsListProps {
  events: SecurityEvent[]
}

const RecentEventsList: React.FC<RecentEventsListProps> = ({ events }) => {
  if (events.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No recent security events available.
      </Typography>
    )
  }

  return (
    <Stack divider={<Divider flexItem />} spacing={0}>
      {events.map((event) => (
        <Box key={event.id} sx={{ py: 1.75 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                {event.normalized_event?.message || event.event_type}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {event.source} • {formatDateTime(event.timestamp || event.created_at)}
              </Typography>
            </Box>
            <Stack direction="row" spacing={1} alignItems="center">
              <StatusChip label={event.severity} type="severity" />
              <StatusChip
                label={(event.detection_count || 0) > 0 ? 'matched' : event.processed ? 'processed' : 'pending'}
                color={(event.detection_count || 0) > 0 ? 'warning' : event.processed ? 'success' : 'default'}
              />
            </Stack>
          </Stack>
        </Box>
      ))}
    </Stack>
  )
}

export default RecentEventsList
