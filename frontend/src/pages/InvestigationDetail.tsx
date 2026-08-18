import { useEffect, useState } from 'react'
import { Alert, Button, Paper, Stack, TextField, Typography } from '@mui/material'
import { useParams } from 'react-router-dom'
import { addInvestigationNote, getInvestigation } from '../services/api/search'

export default function InvestigationDetail() {
  const { investigationId = '' } = useParams()
  const [item, setItem] = useState<any>()
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const load = () => getInvestigation(investigationId).then(setItem).catch(() => setError('Unable to load investigation.'))
  useEffect(() => { void load() }, [investigationId])
  const add = async () => {
    try { await addInvestigationNote(investigationId, note); setNote(''); void load() }
    catch (err: any) { setError(err?.response?.data?.detail?.message || 'Unable to add note.') }
  }
  return <Stack spacing={3}>
    {error && <Alert severity="error">{error}</Alert>}
    <Paper sx={{ p: 2 }}><Typography variant="overline">{item?.status}</Typography><Typography variant="h4">{item?.title || 'Investigation'}</Typography><Typography color="text.secondary">{item?.description}</Typography></Paper>
    <Paper sx={{ p: 2 }}><Typography variant="h6">Analyst notes</Typography><Stack spacing={1} mt={2}>{item?.notes?.map((entry: any) => <Paper variant="outlined" sx={{ p: 1.5 }} key={entry.id}><Typography>{entry.content}</Typography><Typography variant="caption">{new Date(entry.created_at).toLocaleString()}</Typography></Paper>)}</Stack><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} mt={2}><TextField fullWidth label="Add a plain-text note" value={note} onChange={(e) => setNote(e.target.value)} multiline /><Button variant="contained" disabled={!note.trim()} onClick={() => void add()}>Add note</Button></Stack></Paper>
    <Paper sx={{ p: 2 }}><Typography variant="h6">Evidence</Typography><Typography color="text.secondary">{item?.bookmarks?.length || 0} bookmarks · {item?.snapshots?.length || 0} immutable snapshots · {item?.resources?.length || 0} linked resources</Typography></Paper>
  </Stack>
}
