import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Chip, Stack, TextField, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { analyzeIOC, AIIocAnalysis as Analysis } from '../services/api'

const AIIocAnalysis: React.FC = () => {
  const [iocId, setIocId] = useState('')
  const [result, setResult] = useState<Analysis | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    try {
      setError(null)
      setResult(await analyzeIOC(iocId))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'IOC analysis failed')
    }
  }

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <PageHeader title="IOC Analysis" description="Analyze indicators with enrichment, risk, and hunting guidance" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}><CardContent><Stack spacing={2}>
        <TextField label="IOC ID" value={iocId} onChange={(e) => setIocId(e.target.value)} />
        <Button disabled={!iocId} variant="contained" onClick={run}>Analyze IOC</Button>
      </Stack></CardContent></Card>
      {result && <Card sx={{ mt: 3 }}><CardContent>
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}><Chip label={result.risk_level} /><Chip label={`${result.confidence}% confidence`} /></Stack>
        <Typography variant="h6">Threat Description</Typography><Typography>{result.threat_description}</Typography>
        <Typography variant="h6" sx={{ mt: 2 }}>Blocking</Typography>{result.recommended_blocking.map((item) => <Typography key={item}>- {item}</Typography>)}
        <Typography variant="h6" sx={{ mt: 2 }}>Hunting</Typography>{result.hunting_recommendations.map((item) => <Typography key={item}>- {item}</Typography>)}
      </CardContent></Card>}
    </Box>
  )
}

export default AIIocAnalysis
