import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Button,
  Stack,
  Typography,
  Alert as MuiAlert,
} from '@mui/material'
import { ArrowBack as ArrowBackIcon, PlayArrow as AnalyzeIcon } from '@mui/icons-material'
import {
  PageHeader,
  SectionCard,
  StatusChip,
  LoadingState,
  ErrorState,
} from '../components/ui'
import { getEvent, analyzeEvent } from '../services/api/events'
import { SecurityEvent, EventAnalysisResponse } from '../services/api/types'
import { formatDateTimePKT } from '../utils/time'

const EventDetail: React.FC = () => {
  const { eventId } = useParams<{ eventId: string }>()
  const navigate = useNavigate()
  const [event, setEvent] = useState<SecurityEvent | null>(null)
  const [analysisResult, setAnalysisResult] = useState<EventAnalysisResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [analyzing, setAnalyzing] = useState(false)

  const fetchEvent = async () => {
    if (!eventId) return
    try {
      setLoading(true)
      setError('')
      const data = await getEvent(eventId)
      setEvent(data)
    } catch (err) {
      setError('Failed to load event')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchEvent()
  }, [eventId])

  const handleAnalyze = async () => {
    if (!eventId) return
    try {
      setAnalyzing(true)
      setError('')
      const result = await analyzeEvent(eventId)
      setAnalysisResult(result)
      fetchEvent()
    } catch (err) {
      setError('Failed to analyze event')
      console.error(err)
    } finally {
      setAnalyzing(false)
    }
  }

  if (loading) {
    return <LoadingState title="Loading Event Details" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchEvent} />
  }

  if (!event) {
    return <ErrorState message="Event not found" />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title={`Event: ${event.event_type}`}
        description={`Event from ${event.source}`}
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Events', href: '/events' },
          { label: event.id },
        ]}
        actions={
          <Stack direction="row" spacing={2}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate('/events')}
            >
              Back
            </Button>
            <Button
              variant="contained"
              startIcon={<AnalyzeIcon />}
              onClick={handleAnalyze}
              disabled={analyzing}
            >
              {analyzing ? 'Analyzing...' : 'Analyze Event'}
            </Button>
          </Stack>
        }
      />

      <SectionCard title="Overview">
        <Stack spacing={3}>
          <Stack direction="row" spacing={4} flexWrap="wrap">
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Source
              </Typography>
              <Typography variant="body1">{event.source}</Typography>
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Event Type
              </Typography>
              <StatusChip label={event.event_type} />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Severity
              </Typography>
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
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Processing Status
              </Typography>
              <StatusChip
                label={event.processed ? 'Processed' : 'Pending'}
                color={event.processed ? 'success' : 'default'}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Detection Status
              </Typography>
              <StatusChip
                label={(event.detection_count || 0) > 0 ? `Matched (${event.detection_count})` : 'No Match'}
                color={(event.detection_count || 0) > 0 ? 'warning' : 'default'}
              />
            </Box>
          </Stack>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">
              Timestamp
            </Typography>
            <Typography variant="body1">
              {formatDateTimePKT(event.timestamp)}
            </Typography>
          </Box>
        </Stack>
      </SectionCard>

      <SectionCard title="Raw Event">
        <Box
          sx={{
            p: 2,
            backgroundColor: 'rgba(0,0,0,0.2)',
            borderRadius: 1,
            overflowX: 'auto',
            fontFamily: 'monospace',
            fontSize: '0.875rem',
          }}
        >
          <pre>{JSON.stringify(event.raw_event, null, 2)}</pre>
        </Box>
      </SectionCard>

      <SectionCard title="Normalized Event">
        <Box
          sx={{
            p: 2,
            backgroundColor: 'rgba(0,0,0,0.2)',
            borderRadius: 1,
            overflowX: 'auto',
            fontFamily: 'monospace',
            fontSize: '0.875rem',
          }}
        >
          <pre>{JSON.stringify(event.normalized_event, null, 2)}</pre>
        </Box>
      </SectionCard>

      {analysisResult && (
        <>
          <SectionCard title="Detection Results">
            <Stack spacing={2}>
              <MuiAlert
              severity={analysisResult.matched_rules.length > 0 ? 'warning' : 'info'}
            >
              {analysisResult.matched_rules.length > 0
                ? `Matched ${analysisResult.matched_rules.length} rule(s)`
                : 'No rules matched'}
            </MuiAlert>
            {analysisResult.matched_rules.length > 0 && (
              <Stack spacing={1}>
                {analysisResult.matched_rules.map((rule, idx) => (
                  <Box
                    key={idx}
                    sx={{
                      p: 2,
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 2,
                    }}
                  >
                    <Typography variant="subtitle1">{rule.rule}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Severity: {rule.severity}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            )}
            {analysisResult.incident_created && analysisResult.incident_id && (
              <MuiAlert
                severity="warning">
                Incident created: {analysisResult.incident_id}
              </MuiAlert>
            )}
          </Stack>
        </SectionCard>
        </>
      )}
    </Stack>
  )
}

export default EventDetail
