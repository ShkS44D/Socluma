import { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Chip, MenuItem, Paper, Stack, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Typography,
} from '@mui/material'
import { Link } from 'react-router-dom'
import {
  getSavedSearches, getSearchFields, getSearchHistory, getSearchTemplates,
  runSearch, saveSearch, SearchField, SearchResource, SearchResults,
} from '../services/api/search'

const errorText = (error: any) =>
  error?.response?.data?.detail?.message || error?.message || 'Search could not be completed.'

export default function SearchWorkspace() {
  const [query, setQuery] = useState('')
  const [scope, setScope] = useState<SearchResource>('events')
  const [page, setPage] = useState(1)
  const [results, setResults] = useState<SearchResults | null>(null)
  const [fields, setFields] = useState<SearchField[]>([])
  const [history, setHistory] = useState<any[]>([])
  const [saved, setSaved] = useState<any[]>([])
  const [templates, setTemplates] = useState<any[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const refreshLibrary = () => Promise.all([
    getSearchFields().then(setFields),
    getSearchHistory().then(setHistory),
    getSavedSearches().then(setSaved),
    getSearchTemplates().then(setTemplates),
  ]).catch((err) => setError(errorText(err)))

  useEffect(() => { void refreshLibrary() }, [])

  const search = async (nextPage = 1) => {
    setLoading(true); setError('')
    try {
      setResults(await runSearch({ query, resource_scope: scope, page: nextPage, page_size: 50 }))
      setPage(nextPage)
      void getSearchHistory().then(setHistory)
    } catch (err) { setError(errorText(err)) } finally { setLoading(false) }
  }

  const save = async () => {
    const name = window.prompt('Name this search')
    if (!name) return
    try { await saveSearch({ name, query, resource_scope: scope }); void getSavedSearches().then(setSaved) }
    catch (err) { setError(errorText(err)) }
  }

  const selectDefinition = (item: any) => {
    setQuery(item.display_query || '')
    setScope(item.resource_scope || 'events')
  }

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4">Search & Investigation</Typography>
        <Typography color="text.secondary">Query tenant-scoped telemetry, alerts, incidents, and extracted entities.</Typography>
      </Box>
      {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
      <Paper sx={{ p: 2 }}>
        <Stack spacing={2}>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
            <TextField select label="Resource" value={scope} onChange={(e) => setScope(e.target.value as SearchResource)} sx={{ minWidth: 170 }}>
              {['events', 'alerts', 'incidents', 'entities'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
            </TextField>
            <TextField
              fullWidth label="Structured query" value={query}
              placeholder='severity:high AND source.ip:10.0.0.5'
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void search(1) }}
              inputProps={{ list: 'search-field-catalog', autoComplete: 'off' }}
            />
            <datalist id="search-field-catalog">{fields.map((field) => <option key={field.name} value={`${field.name}:`} />)}</datalist>
            <Button variant="contained" onClick={() => void search(1)} disabled={loading}>{loading ? 'Searching…' : 'Search'}</Button>
            <Button variant="outlined" onClick={() => void save()} disabled={!query.trim()}>Save</Button>
          </Stack>
          <Typography variant="caption" color="text.secondary">
            Examples: severity:high · user.name EXISTS · destination.port IN (80,443) · timestamp&gt;=now-24h
          </Typography>
        </Stack>
      </Paper>

      <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
        <Paper sx={{ p: 2, flex: 1, overflow: 'auto' }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
            <Typography variant="h6">Results</Typography>
            {results && <Chip label={`${results.total_count} matches · ${results.execution_time_ms} ms`} size="small" />}
          </Stack>
          <Table size="small">
            <TableHead><TableRow><TableCell>Time</TableCell><TableCell>Type</TableCell><TableCell>Title</TableCell><TableCell>Severity / Status</TableCell></TableRow></TableHead>
            <TableBody>
              {(results?.items || []).map((item) => (
                <TableRow key={item.id} hover>
                  <TableCell>{item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}</TableCell>
                  <TableCell>{item.type}</TableCell>
                  <TableCell><Link to={item.path}>{item.title}</Link></TableCell>
                  <TableCell>{String(item.severity || item.status || '—')}</TableCell>
                </TableRow>
              ))}
              {results && results.items.length === 0 && <TableRow><TableCell colSpan={4}>No matches in the selected time range.</TableCell></TableRow>}
            </TableBody>
          </Table>
          {results && <Stack direction="row" spacing={1} mt={2}>
            <Button disabled={page <= 1 || loading} onClick={() => void search(page - 1)}>Previous</Button>
            <Button disabled={!results.has_next || loading} onClick={() => void search(page + 1)}>Next</Button>
          </Stack>}
        </Paper>
        <Paper sx={{ p: 2, width: { lg: 360 } }}>
          <Typography variant="h6">Search library</Typography>
          <Typography variant="subtitle2" mt={2}>Saved</Typography>
          {saved.map((item) => <Button key={item.id} fullWidth sx={{ justifyContent: 'flex-start' }} onClick={() => selectDefinition(item)}>{item.name}</Button>)}
          <Typography variant="subtitle2" mt={2}>Templates</Typography>
          {templates.map((item) => <Button key={item.id} fullWidth sx={{ justifyContent: 'flex-start' }} onClick={() => selectDefinition(item)}>{item.name}</Button>)}
          <Typography variant="subtitle2" mt={2}>Recent</Typography>
          {history.slice(0, 8).map((item) => <Button key={item.id} fullWidth sx={{ justifyContent: 'flex-start', textTransform: 'none' }} onClick={() => selectDefinition(item)}>{item.display_query || '(all records)'}</Button>)}
        </Paper>
      </Stack>
    </Stack>
  )
}
