import React, { useEffect, useMemo, useState } from 'react'
import {
  Box,
  Button,
  Grid,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { Add as AddIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { getEvents, createEvent } from '../services/api/events'
import { SecurityEvent, Severity } from '../services/api/types'
import { formatDateTime } from '../utils/formatters'
import {
  PageHeader,
  MetricCard,
  SectionCard,
  DataTable,
  DataTableColumn,
  StatusChip,
  LoadingState,
  ErrorState,
  EmptyState,
} from '../components/ui'

const Events: React.FC = () => {
  const navigate = useNavigate()
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('')
  const [sourceFilter, setSourceFilter] = useState<string>('')

  const fetchEvents = async () => {
    try {
      setLoading(true)
      setError('')
      const data = await getEvents({ sort_by: 'created_at', sort_order: 'desc', limit: 100 })
      setEvents(data)
    } catch (err) {
      setError('Failed to load events')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEvents()
  }, [])

  const handleGenerateTestEvent = async () => {
    try {
      await createEvent({
        source: 'test-generator',
        event_type: 'process',
        raw_event: {
          Image: 'powershell.exe',
          CommandLine: 'powershell -enc SGVsbG8='
        },
        severity: 'high'
      })
      fetchEvents()
    } catch (err) {
      setError('Failed to generate test event')
      console.error(err)
    }
  }

  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      const matchesSearch = !search || 
        event.source.toLowerCase().includes(search.toLowerCase()) ||
        JSON.stringify(event.raw_event).toLowerCase().includes(search.toLowerCase())
      const matchesSeverity = !severityFilter || event.severity === severityFilter
      const matchesType = !eventTypeFilter || event.event_type === eventTypeFilter
      const matchesSource = !sourceFilter || event.source.toLowerCase().includes(sourceFilter.toLowerCase())
      return matchesSearch && matchesSeverity && matchesType && matchesSource
    })
  }, [events, search, severityFilter, eventTypeFilter, sourceFilter])

  const stats = useMemo(() => {
    const total = filteredEvents.length
    const processEvents = filteredEvents.filter((e) => e.event_type === 'process').length
    const loginEvents = filteredEvents.filter((e) => e.event_type === 'login').length
    const highSeverityEvents = filteredEvents.filter(
      (e) => e.severity === 'high' || e.severity === 'critical'
    ).length
    return { total, processEvents, loginEvents, highSeverityEvents }
  }, [filteredEvents])

  const columns: DataTableColumn<SecurityEvent>[] = [
    {
      key: 'timestamp',
      header: 'Timestamp',
      render: (event) => formatDateTime(event.timestamp),
    },
    {
      key: 'source',
      header: 'Source',
      render: (event) => (
        <Typography variant="body2">{event.source}</Typography>
      ),
    },
    {
      key: 'event_type',
      header: 'Event Type',
      render: (event) => (
        <StatusChip label={event.event_type} />
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (event) => (
        <StatusChip
          label={event.severity}
          color={
            event.severity === 'critical' || event.severity === 'high'
              ? 'error'
              : event.severity === 'medium'
              ? 'warning'
              : 'info'
          }
        />
      ),
    },
    {
      key: 'processed',
      header: 'Processing Status',
      render: (event) => (
        <StatusChip
          label={event.processed ? 'Processed' : 'Pending'}
          color={event.processed ? 'success' : 'default'}
        />
      ),
    },
    {
      key: 'detection',
      header: 'Detection Status',
      render: (event) => {
        const count = event.detection_count || 0
        return (
          <StatusChip
            label={count > 0 ? `Matched (${count})` : 'No Match'}
            color={count > 0 ? 'warning' : 'default'}
          />
        )
      },
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (event) => (
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => navigate(`/events/${event.id}`)}
          >
            View
          </Button>
        </Stack>
      ),
    },
  ]

  if (loading) {
    return <LoadingState title="Loading Events" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchEvents} />
  }

  const uniqueSources = [...new Set(events.map(e => e.source))]

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Event Explorer"
        description="Explore normalized security events and detection activity"
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Events' },
        ]}
      />

      <Box sx={{ width: '100%', overflow: 'hidden' }}>
        <Grid container spacing={6}>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Total Events"
              value={stats.total}
              severity="info"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Process Events"
              value={stats.processEvents}
              severity="info"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Login Events"
              value={stats.loginEvents}
              severity="info"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="High Severity Events"
              value={stats.highSeverityEvents}
              severity="error"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
        </Grid>
      </Box>

      <SectionCard
        title="Security Events"
        action={
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleGenerateTestEvent}
          >
            Generate Test Event
          </Button>
        }
      >
        <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <TextField
            label="Search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ minWidth: 300 }}
          />
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select
              value={severityFilter}
              label="Severity"
              onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Event Type</InputLabel>
            <Select
              value={eventTypeFilter}
              label="Event Type"
              onChange={(e) => setEventTypeFilter(e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="login">Login</MenuItem>
              <MenuItem value="logout">Logout</MenuItem>
              <MenuItem value="file">File</MenuItem>
              <MenuItem value="network">Network</MenuItem>
              <MenuItem value="process">Process</MenuItem>
              <MenuItem value="alert">Alert</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Source</InputLabel>
            <Select
              value={sourceFilter}
              label="Source"
              onChange={(e) => setSourceFilter(e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              {uniqueSources.map((source) => (
                <MenuItem key={source} value={source}>
                  {source}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        {filteredEvents.length === 0 ? (
          <EmptyState
            title="No events found"
            description="Ingest events or generate a test event to get started"
          />
        ) : (
          <DataTable
            columns={columns}
            rows={filteredEvents}
            getRowId={(row) => row.id}
            onRowClick={(row) => navigate(`/events/${row.id}`)}
          />
        )}
      </SectionCard>
    </Stack>
  )
}

export default Events
