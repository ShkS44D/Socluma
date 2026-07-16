import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Chip, Stack, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { suggestDetectionRules, AIDetectionSuggestions as Suggestions } from '../services/api'

const AIDetectionSuggestions: React.FC = () => {
  const [result, setResult] = useState<Suggestions | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    try {
      setError(null)
      setResult(await suggestDetectionRules())
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Detection suggestion failed')
    }
  }

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto' }}>
      <PageHeader title="Detection Suggestions" description="Generate Sigma-style detection ideas from recent incidents" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Button variant="contained" sx={{ mt: 3 }} onClick={run}>Suggest Detection Rules</Button>
      <Stack spacing={2} sx={{ mt: 3 }}>
        {result?.suggestions.map((rule) => (
          <Card key={rule.rule_name}><CardContent>
            <Stack direction="row" spacing={1} alignItems="center"><Typography variant="h6">{rule.rule_name}</Typography><Chip label={rule.severity} size="small" /></Stack>
            <Typography variant="body2" sx={{ mt: 1 }}>Fields: {rule.fields.join(', ')}</Typography>
            <Typography variant="body2" sx={{ mt: 1, fontFamily: 'monospace' }}>{JSON.stringify(rule.logic, null, 2)}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>False Positive Considerations</Typography>
            {rule.false_positive_considerations.map((item) => <Typography key={item}>- {item}</Typography>)}
          </CardContent></Card>
        ))}
      </Stack>
    </Box>
  )
}

export default AIDetectionSuggestions
