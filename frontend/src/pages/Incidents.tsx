import React, { useEffect, useState } from 'react'
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Pagination,
  LinearProgress,
  Stack,
} from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { getIncidents, Incident } from '../services/api'
import { formatDateTime } from '../utils/formatters'
import {
  ErrorState,
  LoadingState,
  PageHeader,
  SectionCard,
  StatusChip,
} from '../components/ui'

const severityColors: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
}

const statusColors: Record<string, 'default' | 'primary' | 'secondary' | 'success' | 'error'> = {
  open: 'default',
  investigating: 'primary',
  resolved: 'success',
  closed: 'secondary',
}

const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const pageSize = 10
  const navigate = useNavigate()

  const fetchIncidents = async () => {
    try {
      setLoading(true)
      setError('')
      const response = await getIncidents(page, pageSize)
      setIncidents(response.items)
      setTotal(response.total)
    } catch (err) {
      setError('Failed to load incidents')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
  }, [page])

  if (loading) {
    return <LoadingState title="Loading Incidents" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchIncidents} />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Incidents"
        description="Correlated security incidents with severity, risk score, and investigation status."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Incidents' },
        ]}
      />

      <SectionCard title="Incident Queue">
        <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Incident</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Risk Score</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Related Alerts</TableCell>
                <TableCell>Created</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {incidents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    No incidents found
                  </TableCell>
                </TableRow>
              ) : (
                incidents.map((incident) => (
                  <TableRow
                    hover
                    key={incident.id}
                    onClick={() => navigate(`/incidents/${incident.id}`)}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>
                        {incident.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {incident.description || 'No description'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <StatusChip
                        label={incident.severity}
                        color={severityColors[incident.severity] || 'default'}
                      />
                    </TableCell>
                    <TableCell sx={{ minWidth: 180 }}>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        {incident.risk_score.toFixed(0)}/100
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={incident.risk_score}
                        color={incident.risk_score >= 80 ? 'error' : incident.risk_score >= 60 ? 'warning' : 'info'}
                      />
                    </TableCell>
                    <TableCell>
                      <StatusChip
                        label={incident.status}
                        color={statusColors[incident.status] || 'default'}
                      />
                    </TableCell>
                    <TableCell>{incident.alert_count}</TableCell>
                    <TableCell>{formatDateTime(incident.created_at)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {total > pageSize && (
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
            <Pagination
              count={Math.ceil(total / pageSize)}
              page={page}
              onChange={(_event, value) => setPage(value)}
            />
          </Box>
        )}
      </SectionCard>
    </Stack>
  )
}

export default Incidents
