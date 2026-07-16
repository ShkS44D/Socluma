import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { generateInvestigationTimeline, AITimelineResponse } from '../services/api'

const AITimelineViewer: React.FC = () => {
  const [incidentId, setIncidentId] = useState('')
  const [timeline, setTimeline] = useState<AITimelineResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const generate = async () => {
    try {
      setError(null)
      setTimeline(await generateInvestigationTimeline(incidentId))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Timeline generation failed')
    }
  }

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <PageHeader title="Timeline Viewer" description="Generate chronological investigation timelines" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}><CardContent><Stack spacing={2}>
        <TextField label="Incident ID" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} />
        <Button disabled={!incidentId} variant="contained" onClick={generate}>Generate Timeline</Button>
      </Stack></CardContent></Card>
      {timeline && <Card sx={{ mt: 3 }}><CardContent>
        {timeline.entries.map((entry) => (
          <Box key={`${entry.timestamp}-${entry.title}`} sx={{ py: 1.5, borderBottom: '1px solid', borderColor: 'divider' }}>
            <Typography variant="caption" color="text.secondary">{new Date(entry.timestamp).toLocaleString()} - {entry.source}</Typography>
            <Typography variant="subtitle1">{entry.title}</Typography>
            {entry.description && <Typography variant="body2">{entry.description}</Typography>}
          </Box>
        ))}
      </CardContent></Card>}
    </Box>
  )
}

export default AITimelineViewer
