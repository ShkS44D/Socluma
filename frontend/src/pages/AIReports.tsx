import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { generateIncidentReport, AIReportResponse } from '../services/api'

const AIReports: React.FC = () => {
  const [incidentId, setIncidentId] = useState('')
  const [report, setReport] = useState<AIReportResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const generate = async () => {
    try {
      setLoading(true)
      setError(null)
      setReport(await generateIncidentReport(incidentId))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Report generation failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto' }}>
      <PageHeader title="AI Reports" description="Generate PDF-ready markdown incident reports" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}><CardContent><Stack spacing={2}>
        <TextField label="Incident ID" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} />
        <Button disabled={!incidentId || loading} variant="contained" onClick={generate}>Generate Report</Button>
      </Stack></CardContent></Card>
      {report && <Card sx={{ mt: 3 }}><CardContent><Typography sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{report.markdown}</Typography></CardContent></Card>}
    </Box>
  )
}

export default AIReports
