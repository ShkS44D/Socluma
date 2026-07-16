import React, { useState } from 'react'
import { Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material'
import { ErrorState, PageHeader } from '../components/ui'
import { suggestPlaybooks, AIPlaybookSuggestions as Suggestions } from '../services/api'

const AIPlaybookSuggestions: React.FC = () => {
  const [incidentId, setIncidentId] = useState('')
  const [result, setResult] = useState<Suggestions | null>(null)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    try {
      setError(null)
      setResult(await suggestPlaybooks(incidentId || undefined))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Playbook suggestion failed')
    }
  }

  return (
    <Box sx={{ maxWidth: 1100, mx: 'auto' }}>
      <PageHeader title="Playbook Suggestions" description="Generate response workflow suggestions from incident context" />
      {error && <ErrorState message={error} onRetry={() => setError(null)} />}
      <Card sx={{ mt: 3 }}><CardContent><Stack spacing={2}>
        <TextField label="Incident ID" value={incidentId} onChange={(e) => setIncidentId(e.target.value)} helperText="Optional. Leave blank to use recent incidents." />
        <Button variant="contained" onClick={run}>Suggest Playbooks</Button>
      </Stack></CardContent></Card>
      <Stack spacing={2} sx={{ mt: 3 }}>
        {result?.suggestions.map((playbook) => (
          <Card key={playbook.name}><CardContent>
            <Typography variant="h6">{playbook.name}</Typography>
            <Typography variant="body2" sx={{ mt: 1 }}>Trigger: {playbook.trigger}</Typography>
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Actions</Typography>
            {playbook.actions.map((item) => <Typography key={item}>- {item}</Typography>)}
            <Typography variant="subtitle2" sx={{ mt: 2 }}>Expected Outcome</Typography>
            <Typography>{playbook.expected_outcome}</Typography>
          </CardContent></Card>
        ))}
      </Stack>
    </Box>
  )
}

export default AIPlaybookSuggestions
