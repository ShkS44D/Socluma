import { useEffect, useState } from 'react'
import { Box, Chip, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getMitreMatrix, MitreMatrixResponse } from '../services/api'
import { ErrorState, LoadingState, PageHeader, SectionCard } from '../components/ui'

export default function MitreMatrix() {
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const [data, setData] = useState<MitreMatrixResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [createdFrom, setCreatedFrom] = useState('')
  const [createdTo, setCreatedTo] = useState('')
  const incidentId = search.get('incident_id') || undefined

  useEffect(() => {
    setLoading(true)
    getMitreMatrix({ severity: severity || undefined, status: status || undefined, incident_id: incidentId,
      created_from: createdFrom ? new Date(createdFrom).toISOString() : undefined,
      created_to: createdTo ? new Date(`${createdTo}T23:59:59`).toISOString() : undefined })
      .then(setData).catch(() => setError('Failed to load the incident-derived MITRE matrix.')).finally(() => setLoading(false))
  }, [severity, status, incidentId, createdFrom, createdTo])

  if (loading) return <LoadingState title="Loading MITRE ATT&CK matrix" />
  if (error || !data) return <ErrorState message={error || 'Matrix unavailable'} />
  const tactics = Array.from(new Set(data.techniques.map((item) => item.tactic)))
  return <Stack spacing={4}>
    <PageHeader title="MITRE ATT&CK Matrix" description="Evidence-backed techniques aggregated from correlated incidents only." />
    <Stack direction="row" spacing={2}>
      <TextField select label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)} sx={{ minWidth: 160 }}>
        <MenuItem value="">All</MenuItem>{['low','medium','high','critical'].map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
      </TextField>
      <TextField select label="Status" value={status} onChange={(e) => setStatus(e.target.value)} sx={{ minWidth: 160 }}>
        <MenuItem value="">All</MenuItem>{['open','investigating','resolved','closed'].map((v) => <MenuItem key={v} value={v}>{v}</MenuItem>)}
      </TextField>
      <TextField type="date" label="From" value={createdFrom} onChange={(e) => setCreatedFrom(e.target.value)} InputLabelProps={{ shrink: true }} />
      <TextField type="date" label="To" value={createdTo} onChange={(e) => setCreatedTo(e.target.value)} InputLabelProps={{ shrink: true }} />
      <Chip label={`${data.incident_count} correlated incident(s)`} />
    </Stack>
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: `repeat(${Math.min(tactics.length || 1, 4)}, 1fr)` }, gap: 2 }}>
      {tactics.map((tactic) => <SectionCard key={tactic} title={tactic}>
        <Stack spacing={1.5}>{data.techniques.filter((item) => item.tactic === tactic).map((item) =>
          <Paper key={item.technique_id} variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2">{item.sub_technique_id || item.technique_id}</Typography>
            <Typography variant="body2">{item.sub_technique_name || item.technique_name}</Typography>
            <Typography variant="caption">{item.incident_count} incident(s)</Typography>
            <Stack spacing={0.5} sx={{ mt: 1 }}>{item.incidents.map((incident) =>
              <Typography key={incident.id} variant="caption" color="primary" sx={{ cursor: 'pointer' }} onClick={() => navigate(`/incidents/${incident.id}`)}>
                {incident.title} ({incident.confidence.toFixed(0)}%)
              </Typography>)}</Stack>
          </Paper>)}</Stack>
      </SectionCard>)}
    </Box>
  </Stack>
}
