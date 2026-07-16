import React, { useState, useEffect } from 'react'
import {
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Pagination,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Stack,
} from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { getAlerts, Alert, AlertStatus, Severity } from '../services/api'
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
  low: 'info'
}

const statusColors: Record<string, 'default' | 'primary' | 'secondary' | 'success' | 'error'> = {
  open: 'default',
  investigating: 'primary',
  resolved: 'success',
  dismissed: 'secondary'
}

const AlertQueue: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(10)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('')
  const navigate = useNavigate()

  const fetchAlerts = async () => {
    try {
      setLoading(true)
      setError('')
      const response = await getAlerts(page, pageSize, severityFilter || undefined, statusFilter || undefined)
      setAlerts(response.items)
      setTotal(response.total)
    } catch (err) {
      setError('Failed to load alerts')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAlerts()
  }, [page, severityFilter, statusFilter])

  const handlePageChange = (_event: React.ChangeEvent<unknown>, value: number) => {
    setPage(value)
  }

  const formatDate = (dateStr: string) => formatDateTime(dateStr)

  if (loading) {
    return <LoadingState title="Loading Alert Queue" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchAlerts} />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Alert Queue"
        description="Detected security alerts with severity, status, and OCSF classification."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Alerts' },
        ]}
      />

      <SectionCard title="Alert Queue">
        <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select
              value={severityFilter}
              label="Severity"
              onChange={(e) => { setSeverityFilter(e.target.value as Severity | ''); setPage(1) }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>

          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={statusFilter}
              label="Status"
              onChange={(e) => { setStatusFilter(e.target.value as AlertStatus | ''); setPage(1) }}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="investigating">Investigating</MenuItem>
              <MenuItem value="resolved">Resolved</MenuItem>
              <MenuItem value="dismissed">Dismissed</MenuItem>
            </Select>
          </FormControl>
        </Box>

        <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Class</TableCell>
                <TableCell>Activity</TableCell>
                <TableCell>Created</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alerts.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    No alerts found
                  </TableCell>
                </TableRow>
              ) : (
                alerts.map((alert) => (
                  <TableRow
                    hover
                    key={alert.id}
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <StatusChip
                        label={alert.severity}
                        color={severityColors[alert.severity] || 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <StatusChip
                        label={alert.status}
                        color={statusColors[alert.status] || 'default'}
                      />
                    </TableCell>
                    <TableCell>{String(alert.raw_data?.source || 'api')}</TableCell>
                    <TableCell>{alert.ocsf_data?.class_name || 'Unknown'}</TableCell>
                    <TableCell>{alert.ocsf_data?.activity_name || 'Unknown'}</TableCell>
                    <TableCell>{formatDate(alert.created_at)}</TableCell>
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
              onChange={handlePageChange}
            />
          </Box>
        )}
      </SectionCard>
    </Stack>
  )
}

export default AlertQueue
