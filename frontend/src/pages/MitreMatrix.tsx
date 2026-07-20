import { useEffect, useState } from 'react'
import { Box, Chip, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getMitreMatrix, MitreMatrixResponse } from '../services/api'
import { ErrorState, LoadingState, PageHeader, SectionCard } from '../components/ui'

const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

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
  const mappedTactics = Array.from(new Set(data.techniques.map((item) => item.tactic)))
  const tactics = [...TACTIC_ORDER, ...mappedTactics.filter((item) => !TACTIC_ORDER.includes(item)).sort()]
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
    <Box sx={{ display: 'flex', gap: 2, overflowX: 'auto', pb: 2, alignItems: 'flex-start' }}>
      {tactics.map((tactic) => <SectionCard key={tactic} title={tactic}>
        <Stack spacing={1.5} sx={{ minWidth: 280 }}>
          {data.techniques.filter((item) => item.tactic === tactic).length === 0 && (
            <Typography variant="body2" color="text.secondary">No matching incident techniques</Typography>
          )}
          {data.techniques.filter((item) => item.tactic === tactic).map((item) =>
          <Paper key={`${item.technique_id}-${item.mapping_source}`} variant="outlined" sx={{ p: 2, borderColor: item.mapping_source === 'correlated' ? 'primary.main' : 'divider' }}>
            <Typography variant="subtitle2">{item.parent_technique_id} {item.parent_technique_name}</Typography>
            {item.sub_technique_id && <Typography variant="body2">↳ {item.sub_technique_id} {item.sub_technique_name || 'Name unavailable'}</Typography>}
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ my: 0.75 }}>
              <Chip size="small" label={`${item.incident_count} incident(s)`} />
              <Chip size="small" label={`${item.supporting_alert_count} supporting alert(s)`} />
              <Chip size="small" variant="outlined" label={item.mapping_source === 'correlated' ? 'Correlated' : 'Legacy-derived'} />
            </Stack>
            <Stack spacing={0.5} sx={{ mt: 1 }}>{item.incidents.map((incident) =>
              <Typography key={incident.id} variant="caption" color="primary" sx={{ cursor: 'pointer' }} onClick={() => navigate(`/incidents/${incident.id}`)}>
                {incident.title} ({incident.confidence.toFixed(0)}%, {incident.supporting_alert_count} alert(s))
              </Typography>)}</Stack>
          </Paper>)}</Stack>
      </SectionCard>)}
    </Box>
  </Stack>
}
