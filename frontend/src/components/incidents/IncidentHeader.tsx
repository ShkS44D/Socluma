import React from 'react'
import { Box, Chip, Paper, Stack, Typography } from '@mui/material'
import { Incident } from '../../services/api'
import StatusChip from '../ui/StatusChip'
import { formatDateTimePKT } from '../../utils/time'

interface IncidentHeaderProps {
  incident: Incident
}

const IncidentHeader: React.FC<IncidentHeaderProps> = ({ incident }) => {
  const formatDate = (date: string) => formatDateTimePKT(date)

  const statusColorMap: Record<string, 'default' | 'primary' | 'secondary' | 'success' | 'error' | 'info' | 'warning'> = {
    open: 'default',
    investigating: 'primary',
    resolved: 'success',
    closed: 'secondary'
  }

  const severityColorMap: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'info'
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Stack spacing={2}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Typography variant="h4" fontWeight={700}>
            {incident.title}
          </Typography>
        </Box>
        <Stack direction="row" spacing={2} flexWrap="wrap">
          <StatusChip label={`Severity: ${incident.severity}`} color={severityColorMap[incident.severity]} />
          <StatusChip label={`Status: ${incident.status}`} color={statusColorMap[incident.status]} />
          <Chip label={`Risk Score: ${incident.risk_score.toFixed(0)}`} color="default" variant="outlined" />
          <Chip label={`Priority: ${incident.priority.toUpperCase()}`} color="default" variant="outlined" />
          {incident.attack_technique?.technique_id && (
            <Chip
              label={`MITRE: ${incident.attack_technique.technique_id}`}
              color="warning"
              variant="outlined"
            />
          )}
        </Stack>
        {incident.description && (
          <Typography variant="body2" color="text.secondary">
            {incident.description}
          </Typography>
        )}
        <Stack direction="row" spacing={4} flexWrap="wrap">
          <Typography variant="body2" color="text.secondary">
            Created: {formatDate(incident.created_at)}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Updated: {formatDate(incident.updated_at)}
          </Typography>
          {incident.assigned_analyst && (
            <Typography variant="body2" color="text.secondary">
              Assigned: {incident.assigned_analyst.full_name || incident.assigned_analyst.email}
            </Typography>
          )}
          <Typography variant="body2" color="text.secondary">
            Related Alerts: {incident.alert_count}
          </Typography>
          {incident.ai_analyzed_at && (
            <Typography variant="body2" color="text.secondary">
              AI analyzed: {formatDate(incident.ai_analyzed_at)}
            </Typography>
          )}
        </Stack>
      </Stack>
    </Paper>
  )
}

export default IncidentHeader
