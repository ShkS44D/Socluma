import React from 'react'
import { Box, LinearProgress, Stack, Typography } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { Incident } from '../../services/api'
import { formatDateTime } from '../../utils'
import { DataTable, DataTableColumn, StatusChip } from '../ui'

interface RecentIncidentsTableProps {
  incidents: Incident[]
}

const RecentIncidentsTable: React.FC<RecentIncidentsTableProps> = ({ incidents }) => {
  const navigate = useNavigate()

  const columns: DataTableColumn<Incident>[] = [
    {
      key: 'title',
      header: 'Title',
      render: (incident) => (
        <Box>
          <Typography variant="subtitle2">{incident.title}</Typography>
          <Typography variant="body2" color="text.secondary">
            {incident.description || 'No description available'}
          </Typography>
        </Box>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (incident) => <StatusChip label={incident.severity} type="severity" />,
    },
    {
      key: 'risk',
      header: 'Risk Score',
      width: 170,
      render: (incident) => (
        <Box sx={{ minWidth: 140 }}>
          <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.75 }}>
            <Typography variant="body2">{incident.risk_score.toFixed(0)}/100</Typography>
            <Typography variant="caption" color="text.secondary">
              Risk
            </Typography>
          </Stack>
          <LinearProgress
            variant="determinate"
            value={incident.risk_score}
            color={incident.risk_score >= 85 ? 'error' : incident.risk_score >= 70 ? 'warning' : 'info'}
          />
        </Box>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (incident) => <StatusChip label={incident.status} type="status" />,
    },
    {
      key: 'priority',
      header: 'Priority',
      render: (incident) => <StatusChip label={incident.priority} type="priority" />,
    },
    {
      key: 'created_at',
      header: 'Created',
      width: 180,
      render: (incident) => (
        <Typography variant="body2" color="text.secondary">
          {formatDateTime(incident.created_at)}
        </Typography>
      ),
    },
  ]

  return (
    <DataTable
      columns={columns}
      rows={incidents}
      getRowId={(incident) => incident.id}
      onRowClick={(incident) => navigate(`/incidents/${incident.id}`)}
      emptyMessage="No recent incidents have been correlated yet."
    />
  )
}

export default RecentIncidentsTable
