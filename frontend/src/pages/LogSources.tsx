import React, { useEffect, useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  Paper,
  Alert,
  Chip,
} from '@mui/material'
import { Add, ContentCopy, Security, VpnKey } from '@mui/icons-material'
import { PageHeader, SectionCard, StatusChip } from '../components/ui'
import {
  getLogSources, createLogSource, getCollectors, registerCollector, LogSource, Collector,
  createEnrollmentToken, getDataSources, getDeadLetters, getIngestionMetrics,
  DataSource, DeadLetterItem, IngestionMetrics, getCollectorGroups, getCollectorPolicies,
  importTelemetry, CollectorRegistrationResponse,
} from '../services/api'
import { formatDateTimePKT } from '../utils/time'

const LogSources: React.FC = () => {
  const [logSources, setLogSources] = useState<LogSource[]>([])
  const [collectors, setCollectors] = useState<Collector[]>([])
  const [dataSources, setDataSources] = useState<DataSource[]>([])
  const [deadLetters, setDeadLetters] = useState<DeadLetterItem[]>([])
  const [metrics, setMetrics] = useState<IngestionMetrics | null>(null)
  const [enrollmentToken, setEnrollmentToken] = useState<string | null>(null)
  const [collectorGroups, setCollectorGroups] = useState<Array<{ id: string; name: string; description?: string }>>([])
  const [collectorPolicies, setCollectorPolicies] = useState<Array<{ id: string; name: string; active_version?: number }>>([])
  const [importMessage, setImportMessage] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [openLogSourceDialog, setOpenLogSourceDialog] = useState(false)
  const [openCollectorDialog, setOpenCollectorDialog] = useState(false)
  const [collectorCredentials, setCollectorCredentials] = useState<CollectorRegistrationResponse | null>(null)
  const [registrationError, setRegistrationError] = useState<string | null>(null)
  const [credentialsCopied, setCredentialsCopied] = useState(false)
  const [newLogSource, setNewLogSource] = useState({ name: '', type: 'custom' as const, description: '' })
  const [newCollector, setNewCollector] = useState({ name: '', type: '', hostname: '', log_source_id: '' })

  const fetchData = async () => {
    try {
      const [sources, colls, managedSources, failures, ingestion, groups, policies] = await Promise.all([
        getLogSources(), getCollectors(), getDataSources().catch(() => []),
        getDeadLetters().catch(() => []), getIngestionMetrics().catch(() => null),
        getCollectorGroups().catch(() => []), getCollectorPolicies().catch(() => []),
      ])
      setLogSources(sources)
      setCollectors(colls)
      setDataSources(managedSources)
      setDeadLetters(failures)
      setMetrics(ingestion)
      setCollectorGroups(groups)
      setCollectorPolicies(policies)
    } catch (err) {
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleCreateLogSource = async () => {
    try {
      const source = await createLogSource(newLogSource)
      setLogSources([...logSources, source])
      setOpenLogSourceDialog(false)
      setNewLogSource({ name: '', type: 'custom', description: '' })
    } catch (err) {
      console.error('Failed to create log source:', err)
    }
  }

  const handleRegisterCollector = async () => {
    if (!newCollector.name.trim() || !newCollector.type.trim()) {
      setRegistrationError('Collector name and type are required.')
      return
    }
    try {
      const coll = await registerCollector(newCollector)
      setCollectorCredentials(coll)
      setCredentialsCopied(false)
      setRegistrationError(null)
      await fetchData()
      setOpenCollectorDialog(false)
      setNewCollector({ name: '', type: '', hostname: '', log_source_id: '' })
    } catch (err: any) {
      setRegistrationError(
        err?.response?.data?.detail?.message ||
        err?.response?.data?.detail ||
        'Failed to register collector.'
      )
      console.error('Failed to register collector:', err)
    }
  }

  const collectorConfiguration = collectorCredentials
    ? [
        `COLLECTOR_ID=${collectorCredentials.id}`,
        `COLLECTOR_TOKEN=${collectorCredentials.token}`,
        'BACKEND_URL=http://127.0.0.1:8001',
        `SPOOL_PATH=./data/event-spool-${collectorCredentials.id}.db`,
        `CHECKPOINT_PATH=./data/checkpoints-${collectorCredentials.id}.json`,
      ].join('\n')
    : ''

  const copyCollectorConfiguration = async () => {
    if (!collectorConfiguration) return
    await navigator.clipboard.writeText(collectorConfiguration)
    setCredentialsCopied(true)
  }

  const handleCreateEnrollmentToken = async () => {
    try {
      const result = await createEnrollmentToken({ name: 'Collector enrollment', expires_minutes: 30 })
      setEnrollmentToken(result.token)
    } catch (err) {
      console.error('Failed to create enrollment token:', err)
    }
  }

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return
    const extension = file.name.toLowerCase().split('.').pop()
    const formatName = extension === 'csv' ? 'csv' : extension === 'jsonl' ? 'jsonl' : 'json'
    try {
      const result = await importTelemetry(file, formatName)
      setImportMessage(`Import ${result.state}: ${result.accepted} accepted, ${result.duplicates} duplicates, ${result.rejected} rejected.`)
      await fetchData()
    } catch {
      setImportMessage('Import failed. Check the file format and your telemetry import permission.')
    } finally {
      event.target.value = ''
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'online':
        return 'success'
      case 'error':
        return 'error'
      default:
        return 'default'
    }
  }

  if (loading) {
    return <PageHeader title="Loading..." description="Please wait..." />
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <PageHeader
        title="Log Sources & Collectors"
        description="Manage your log sources and data collectors"
      />
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setOpenLogSourceDialog(true)}
        >
          Add Log Source
        </Button>
        <Button
          variant="outlined"
          startIcon={<Security />}
          onClick={() => setOpenCollectorDialog(true)}
        >
          Register Collector
        </Button>
        <Button variant="outlined" startIcon={<VpnKey />} onClick={handleCreateEnrollmentToken}>
          Create Enrollment Token
        </Button>
        <Button variant="outlined" component="label">
          Import JSON / JSONL / CSV
          <input hidden type="file" accept=".json,.jsonl,.csv" onChange={handleImport} />
        </Button>
      </Box>
      {enrollmentToken && (
        <Alert severity="warning" onClose={() => setEnrollmentToken(null)}>
          Copy this one-time enrollment token now: <strong>{enrollmentToken}</strong>
        </Alert>
      )}
      {importMessage && <Alert severity="info" onClose={() => setImportMessage(null)}>{importMessage}</Alert>}
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}><Paper sx={{ p: 2 }}><Typography color="text.secondary">Events received</Typography><Typography variant="h4">{metrics?.events ?? 0}</Typography></Paper></Grid>
        <Grid item xs={12} md={4}><Paper sx={{ p: 2 }}><Typography color="text.secondary">Average data quality</Typography><Typography variant="h4">{Math.round(metrics?.average_quality ?? 0)}%</Typography></Paper></Grid>
        <Grid item xs={12} md={4}><Paper sx={{ p: 2 }}><Typography color="text.secondary">Dead-letter items</Typography><Typography variant="h4">{deadLetters.length}</Typography></Paper></Grid>
      </Grid>
      <SectionCard title="Managed Data Sources">
        <Grid container spacing={2}>
          {dataSources.length === 0 && <Grid item xs={12}><Typography color="text.secondary">No managed data sources configured yet.</Typography></Grid>}
          {dataSources.map(source => (
            <Grid item xs={12} md={6} lg={4} key={source.id}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="h6">{source.name}</Typography>
                  <Chip size="small" label={source.health_status} color={source.health_status === 'healthy' ? 'success' : 'default'} />
                </Box>
                <Typography variant="body2" color="text.secondary">{source.source_type} · {source.parser_name} · {source.transport}</Typography>
                <Typography variant="caption">{source.accepted_count} accepted · {source.duplicate_count} duplicates · {source.rejected_count} rejected</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </SectionCard>
      <SectionCard title="Log Sources">
        <Grid container spacing={2}>
          {logSources.map(source => (
            <Grid item xs={12} md={6} lg={4} key={source.id}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{source.name}</Typography>
                  <StatusChip label={source.status} color={getStatusColor(source.status)} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Type: {source.type}
                </Typography>
                {source.description && (
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    {source.description}
                  </Typography>
                )}
                {source.last_seen && (
                  <Typography variant="caption" color="text.secondary">
                    Last seen: {formatDateTimePKT(source.last_seen)}
                  </Typography>
                )}
              </Paper>
            </Grid>
          ))}
        </Grid>
      </SectionCard>
      <SectionCard title="Collectors">
        <Grid container spacing={2}>
          {collectors.map(coll => (
            <Grid item xs={12} md={6} lg={4} key={coll.id}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{coll.name}</Typography>
                  <StatusChip label={coll.status} color={getStatusColor(coll.status)} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Type: {coll.type}
                </Typography>
                {coll.hostname && (
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Host: {coll.hostname}
                  </Typography>
                )}
                {coll.last_seen && (
                  <Typography variant="caption" color="text.secondary">
                    Last seen: {formatDateTimePKT(coll.last_seen)}
                  </Typography>
                )}
                <Typography variant="caption" display="block" color="text.secondary">
                  Health: {coll.health_status || coll.status} · Version: {coll.collector_version || 'unknown'}
                </Typography>
                <Typography variant="caption" display="block" color="text.secondary">
                  Queue: {coll.queue_depth || 0} · Accepted: {coll.events_accepted || 0} · Rejected: {coll.events_rejected || 0}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </SectionCard>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <SectionCard title="Collector Groups">
            {collectorGroups.length === 0 ? <Typography color="text.secondary">No groups configured.</Typography> :
              collectorGroups.map(group => <Paper key={group.id} sx={{ p: 1.5, mb: 1 }}><Typography fontWeight={600}>{group.name}</Typography><Typography variant="caption">{group.description || 'No description'}</Typography></Paper>)}
          </SectionCard>
        </Grid>
        <Grid item xs={12} md={6}>
          <SectionCard title="Collector Policies">
            {collectorPolicies.length === 0 ? <Typography color="text.secondary">No policies configured.</Typography> :
              collectorPolicies.map(policy => <Paper key={policy.id} sx={{ p: 1.5, mb: 1 }}><Typography fontWeight={600}>{policy.name}</Typography><Typography variant="caption">Active version: {policy.active_version || 'draft'}</Typography></Paper>)}
          </SectionCard>
        </Grid>
      </Grid>
      <SectionCard title="Dead-letter Queue">
        {deadLetters.length === 0 ? (
          <Typography color="text.secondary">No ingestion failures require attention.</Typography>
        ) : deadLetters.map(item => (
          <Paper key={item.id} sx={{ p: 2, mb: 1 }}>
            <Typography fontWeight={600}>{item.error_code}</Typography>
            <Typography variant="body2">{item.safe_error}</Typography>
            <Typography variant="caption">{item.stage} · {item.attempts} attempts · {formatDateTimePKT(item.created_at)}</Typography>
          </Paper>
        ))}
      </SectionCard>
      <Dialog open={openLogSourceDialog} onClose={() => setOpenLogSourceDialog(false)}>
        <DialogTitle>Add Log Source</DialogTitle>
        <DialogContent sx={{ width: 400 }}>
          <TextField
            label="Name"
            fullWidth
            margin="normal"
            value={newLogSource.name}
            onChange={e => setNewLogSource({ ...newLogSource, name: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Type</InputLabel>
            <Select
              value={newLogSource.type}
              label="Type"
              onChange={e => setNewLogSource({ ...newLogSource, type: e.target.value as any })}
            >
              <MenuItem value="windows_edr">Windows EDR</MenuItem>
              <MenuItem value="linux_audit">Linux Audit</MenuItem>
              <MenuItem value="firewall">Firewall</MenuItem>
              <MenuItem value="cloudtrail">CloudTrail</MenuItem>
              <MenuItem value="application_log">Application Log</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Description"
            fullWidth
            margin="normal"
            multiline
            rows={3}
            value={newLogSource.description}
            onChange={e => setNewLogSource({ ...newLogSource, description: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenLogSourceDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreateLogSource}>Create</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={openCollectorDialog} onClose={() => setOpenCollectorDialog(false)}>
        <DialogTitle>Register Collector</DialogTitle>
        <DialogContent sx={{ width: 400 }}>
          {registrationError && (
            <Alert severity="error" sx={{ mt: 1 }}>
              {registrationError}
            </Alert>
          )}
          <TextField
            label="Name"
            required
            fullWidth
            margin="normal"
            value={newCollector.name}
            onChange={e => {
              setNewCollector({ ...newCollector, name: e.target.value })
              setRegistrationError(null)
            }}
          />
          <TextField
            label="Type"
            required
            fullWidth
            margin="normal"
            value={newCollector.type}
            onChange={e => {
              setNewCollector({ ...newCollector, type: e.target.value })
              setRegistrationError(null)
            }}
          />
          <TextField
            label="Hostname"
            fullWidth
            margin="normal"
            value={newCollector.hostname}
            onChange={e => setNewCollector({ ...newCollector, hostname: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Associated Log Source</InputLabel>
            <Select
              value={newCollector.log_source_id}
              label="Associated Log Source"
              onChange={e => setNewCollector({ ...newCollector, log_source_id: e.target.value })}
            >
              <MenuItem value="">None</MenuItem>
              {logSources.map(source => (
                <MenuItem key={source.id} value={source.id}>{source.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setOpenCollectorDialog(false)
            setRegistrationError(null)
          }}>Cancel</Button>
          <Button variant="contained" onClick={handleRegisterCollector}>Register</Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={Boolean(collectorCredentials)}
        onClose={() => setCollectorCredentials(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Collector registered</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            These credentials are shown only once. Save them securely before closing this window.
            They belong only to the currently selected organization.
          </Alert>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Replace the matching values in <strong>collector-agent\.env</strong>, then restart the
            collector.
          </Typography>
          <TextField
            fullWidth
            multiline
            minRows={4}
            value={collectorConfiguration}
            InputProps={{
              readOnly: true,
              sx: { fontFamily: 'monospace' },
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ContentCopy />}
            onClick={copyCollectorConfiguration}
          >
            {credentialsCopied ? 'Copied' : 'Copy configuration'}
          </Button>
          <Button variant="contained" onClick={() => setCollectorCredentials(null)}>
            I saved it
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default LogSources
