import { useEffect, useState } from 'react'
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Paper, Stack, TextField, Typography } from '@mui/material'
import { Link } from 'react-router-dom'
import { createInvestigation, Investigation, listInvestigations } from '../services/api/search'

export default function Investigations() {
  const [items, setItems] = useState<Investigation[]>([])
  const [open, setOpen] = useState(false)
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState('')
  const load = () => listInvestigations().then(setItems).catch(() => setError('Unable to load investigations.'))
  useEffect(() => { void load() }, [])
  const create = async () => {
    try { await createInvestigation({ title, description }); setOpen(false); setTitle(''); setDescription(''); void load() }
    catch (err: any) { setError(err?.response?.data?.detail?.message || 'Unable to create investigation.') }
  }
  return <Stack spacing={3}>
    <Stack direction="row" justifyContent="space-between"><BoxTitle /><Button variant="contained" onClick={() => setOpen(true)}>New investigation</Button></Stack>
    {error && <Alert severity="error">{error}</Alert>}
    {items.map((item) => <Paper key={item.id} sx={{ p: 2 }}><Typography variant="h6"><Link to={`/investigations/${item.id}`}>{item.title}</Link></Typography><Typography color="text.secondary">{item.description || 'No description'}</Typography><Typography variant="caption">{item.status} · updated {new Date(item.updated_at).toLocaleString()}</Typography></Paper>)}
    {!items.length && <Paper sx={{ p: 3 }}><Typography>No investigations yet.</Typography></Paper>}
    <Dialog open={open} onClose={() => setOpen(false)} fullWidth><DialogTitle>New investigation</DialogTitle><DialogContent><Stack spacing={2} mt={1}><TextField label="Title" value={title} onChange={(e) => setTitle(e.target.value)} autoComplete="off" /><TextField label="Description" multiline rows={4} value={description} onChange={(e) => setDescription(e.target.value)} /></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="contained" disabled={!title.trim()} onClick={() => void create()}>Create</Button></DialogActions></Dialog>
  </Stack>
}

function BoxTitle() { return <div><Typography variant="h4">Investigations</Typography><Typography color="text.secondary">Collaborative cases with preserved evidence and analyst notes.</Typography></div> }
