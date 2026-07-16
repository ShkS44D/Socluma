import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { explainAlert, AIAlertExplanation as Explanation } from '../services/api'

const AIAlertExplanation: React.FC = () => {
  const [alertId, setAlertId] = useState('')
  const [result, setResult] = useState<Explanation | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    try {
      setError(null)
      setResult(await explainAlert(alertId))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Alert explanation failed')
    }
  }

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <PageHeader title="Alert Explanation" description="Explain why an alert triggered and what analysts should do next" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}><CardContent><Stack spacing={2}>
        <TextField label="Alert ID" value={alertId} onChange={(e) => setAlertId(e.target.value)} />
        <Button disabled={!alertId} variant="contained" onClick={run}>Explain Alert</Button>
      </Stack></CardContent></Card>
      {result && <Card sx={{ mt: 3 }}><CardContent>
        <Typography variant="h6">Why It Triggered</Typography><Typography>{result.why_triggered}</Typography>
        <Typography variant="h6" sx={{ mt: 2 }}>Why Suspicious</Typography><Typography>{result.why_suspicious}</Typography>
        <Typography variant="h6" sx={{ mt: 2 }}>False Positive Assessment</Typography><Typography>{result.false_positive_assessment}</Typography>
        <Typography variant="h6" sx={{ mt: 2 }}>Recommended Actions</Typography>
        {result.recommended_actions.map((item) => <Typography key={item}>- {item}</Typography>)}
      </CardContent></Card>}
    </Box>
  )
}

export default AIAlertExplanation
