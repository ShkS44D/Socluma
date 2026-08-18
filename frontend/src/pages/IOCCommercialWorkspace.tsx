import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Chip,
  FormControl,
  Grid,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import {
  Add as AddIcon,
  CloudSync as SyncIcon,
  PlayArrow as RunIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material'
import { usePermissionStore } from '../store'
import {
  CommercialJob,
  GraphEdge,
  GraphNode,
  HuntJob,
  SyncConfiguration,
  ThreatSource,
  addWatchlistMember,
  assignIOCReview,
  cancelHunt,
  createBulkAction,
  createIOCReport,
  createRecommendation,
  createSyncConfiguration,
  createThreatSource,
  createWatchlist,
  decideApproval,
  decideIOCReview,
  downloadIOCReport,
  fetchIOCGraph,
  generateIOCDetection,
  getIOCReviewHistory,
  getWatchlist,
  listBulkActions,
  listHunts,
  listIOCImports,
  listIOCReports,
  listRecommendations,
  listReviewQueue,
  listSyncConfigurations,
  listSyncJobs,
  listThreatSources,
  listWatchlists,
  removeWatchlistMember,
  retryHunt,
  runWatchlistHunt,
  runSync,
  testThreatSource,
  uploadIOCImport,
  confirmIOCImport,
} from '../services/api'
import { EmptyState, ErrorState, LoadingState, PageHeader, SectionCard, StatusChip } from '../components/ui'

export type IOCWorkspaceMode =
  | 'review'
  | 'watchlists'
  | 'hunts'
  | 'sources'
  | 'taxii'
  | 'misp'
  | 'bulk'
  | 'graph'
  | 'detections'
  | 'recommendations'
  | 'reports'

interface Props {
  mode: IOCWorkspaceMode
}

const workspaceCopy: Record<IOCWorkspaceMode, { title: string; subtitle: string }> = {
  review: { title: 'IOC Review Queue', subtitle: 'Assign, assess, and approve intelligence before activation.' },
  watchlists: { title: 'IOC Watchlists', subtitle: 'Manage intelligence collections, policies, and match activity.' },
  hunts: { title: 'Historical Hunts', subtitle: 'Track bounded IOC searches across historical telemetry.' },
  sources: { title: 'Threat Sources', subtitle: 'Manage encrypted provider credentials without plaintext disclosure.' },
  taxii: { title: 'TAXII Synchronization', subtitle: 'Configure and monitor tenant-scoped TAXII 2.1 collection pulls.' },
  misp: { title: 'MISP Synchronization', subtitle: 'Import and export approved intelligence using bounded MISP jobs.' },
  bulk: { title: 'Bulk IOC Operations', subtitle: 'Validate imports and run confirmed actions with partial-success reporting.' },
  graph: { title: 'IOC Relationship Graph', subtitle: 'Explore evidence-backed relationships with an accessible table fallback.' },
  detections: { title: 'IOC-to-Detection', subtitle: 'Generate typed draft rules that must pass review before publication.' },
  recommendations: { title: 'Response Recommendations', subtitle: 'Request human approval for precisely bound response recommendations.' },
  reports: { title: 'IOC Reports', subtitle: 'Generate TLP-filtered intelligence and exposure artifacts with checksums.' },
}

const statusColor = (status?: string): 'success' | 'warning' | 'error' | 'default' => {
  if (status === 'completed' || status === 'active' || status === 'validated') return 'success'
  if (status === 'failed' || status === 'disabled' || status === 'rejected') return 'error'
  if (status === 'running' || status === 'pending' || status === 'pending_approval') return 'warning'
  return 'default'
}

const JobTable = ({ jobs, onAction }: { jobs: CommercialJob[]; onAction?: (job: CommercialJob) => void }) => (
  <TableContainer component={Paper} variant="outlined">
    <Table size="small" aria-label="IOC job status">
      <TableHead>
        <TableRow>
          <TableCell>Job</TableCell>
          <TableCell>Status</TableCell>
          <TableCell>Progress</TableCell>
          <TableCell>Result</TableCell>
          <TableCell>Created</TableCell>
          {onAction ? <TableCell align="right">Action</TableCell> : null}
        </TableRow>
      </TableHead>
      <TableBody>
        {jobs.map((job) => (
          <TableRow key={job.id}>
            <TableCell>
              <Typography variant="body2">{job.original_filename || job.report_type || job.provider || job.format || job.id}</Typography>
              <Typography variant="caption" color="text.secondary">{job.id}</Typography>
            </TableCell>
            <TableCell><Chip size="small" label={job.status} color={statusColor(job.status)} /></TableCell>
            <TableCell sx={{ minWidth: 130 }}>
              <LinearProgress variant="determinate" value={job.progress ?? (job.status === 'completed' ? 100 : 0)} />
            </TableCell>
            <TableCell>{job.error_code || (job.counts ? JSON.stringify(job.counts) : job.checksum?.slice(0, 12) || '—')}</TableCell>
            <TableCell>{job.created_at ? new Date(job.created_at).toLocaleString() : '—'}</TableCell>
            {onAction ? <TableCell align="right"><Button size="small" onClick={() => onAction(job)}>Open</Button></TableCell> : null}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  </TableContainer>
)

const IOCCommercialWorkspace = ({ mode }: Props) => {
  const can = usePermissionStore((state) => state.can)
  const [loading, setLoading] = useState(true)
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [sources, setSources] = useState<ThreatSource[]>([])
  const [configs, setConfigs] = useState<SyncConfiguration[]>([])
  const [jobs, setJobs] = useState<CommercialJob[]>([])
  const [hunts, setHunts] = useState<HuntJob[]>([])
  const [records, setRecords] = useState<Array<Record<string, unknown>>>([])
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([])
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([])
  const [graphTruncated, setGraphTruncated] = useState(false)
  const [provider, setProvider] = useState<'virustotal' | 'abuseipdb' | 'otx' | 'taxii' | 'misp'>('virustotal')
  const [name, setName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [collectionId, setCollectionId] = useState('')
  const [iocId, setIocId] = useState('')
  const [action, setAction] = useState('block_ip')
  const [format, setFormat] = useState('csv')
  const [file, setFile] = useState<File | null>(null)
  const [queue, setQueue] = useState('new')
  const [selectedId, setSelectedId] = useState('')
  const [reviewerId, setReviewerId] = useState('')
  const [comment, setComment] = useState('')
  const [confidence, setConfidence] = useState('')
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null)
  const [history, setHistory] = useState<Array<Record<string, unknown>>>([])

  const syncProvider = mode === 'misp' ? 'misp' : 'taxii'

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      if (mode === 'sources') {
        setSources((await listThreatSources()).items)
      } else if (mode === 'taxii' || mode === 'misp') {
        const [configurationResult, jobResult, sourceResult] = await Promise.all([
          listSyncConfigurations(syncProvider),
          listSyncJobs(syncProvider),
          listThreatSources(),
        ])
        setConfigs(configurationResult.items)
        setJobs(jobResult.items)
        setSources(sourceResult.items.filter((item) => item.provider === syncProvider))
      } else if (mode === 'bulk') {
        const [imports, actions] = await Promise.all([listIOCImports(), listBulkActions()])
        setJobs([...imports.items, ...actions.items].sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))))
      } else if (mode === 'hunts') {
        setHunts((await listHunts()).items)
      } else if (mode === 'review') {
        setRecords((await listReviewQueue(queue)).items)
      } else if (mode === 'watchlists') {
        setRecords(await listWatchlists())
      } else if (mode === 'recommendations') {
        setRecords((await listRecommendations()).items.map((item) => ({ ...item })))
      } else if (mode === 'reports') {
        setJobs((await listIOCReports()).items)
      }
    } catch {
      setError('Unable to load this IOC workspace.')
    } finally {
      setLoading(false)
    }
  }, [mode, queue, syncProvider])

  useEffect(() => {
    void load()
  }, [load])

  const execute = async (operation: () => Promise<unknown>, message: string) => {
    setWorking(true)
    setError('')
    setNotice('')
    try {
      await operation()
      setNotice(message)
      await load()
    } catch {
      setError('The requested operation could not be completed. Review the supplied values and permissions.')
    } finally {
      setWorking(false)
    }
  }

  const downloadReport = async (job: CommercialJob) => {
    setWorking(true)
    setError('')
    setNotice('')
    try {
      const report = await downloadIOCReport(job)
      const objectUrl = URL.createObjectURL(report.blob)
      try {
        const anchor = document.createElement('a')
        anchor.href = objectUrl
        anchor.download = report.filename
        document.body.appendChild(anchor)
        anchor.click()
        anchor.remove()
      } finally {
        URL.revokeObjectURL(objectUrl)
      }
      setNotice(`Report downloaded as ${report.filename}.`)
    } catch (cause) {
      const status = Number((cause as { response?: { status?: number } })?.response?.status || 0)
      if (status === 401) setError('Your session expired. Sign in again to download this report.')
      else if (status === 403 || status === 404) setError('You are not authorized to download this report.')
      else if (status === 409) setError('This report is not ready yet. Refresh the jobs and try again when it is completed.')
      else if (status === 410) setError('This report has expired. Generate a new report before downloading it.')
      else setError('The report download failed. Retry or generate a new report.')
    } finally {
      setWorking(false)
    }
  }

  const credentialFields = useMemo(
    () => provider === 'taxii' ? { token: secret } : provider === 'misp' ? { api_key: secret } : { api_key: secret },
    [provider, secret],
  )

  const renderSources = () => (
    <Stack spacing={3}>
      {can('threat_intelligence.sources.manage') ? (
        <SectionCard title="Configure encrypted source" subtitle="The secret is encrypted immediately and is never returned by the API.">
          <Grid container spacing={2}>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth><InputLabel>Provider</InputLabel><Select label="Provider" value={provider} onChange={(event) => setProvider(event.target.value as typeof provider)}>
                {['virustotal', 'abuseipdb', 'otx', 'taxii', 'misp'].map((item) => <MenuItem key={item} value={item}>{item.toUpperCase()}</MenuItem>)}
              </Select></FormControl>
            </Grid>
            <Grid item xs={12} md={3}><TextField fullWidth label="Configuration name" value={name} onChange={(event) => setName(event.target.value)} /></Grid>
            <Grid item xs={12} md={3}><TextField fullWidth label="HTTPS URL (TAXII/MISP)" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} /></Grid>
            <Grid item xs={12} md={3}><TextField fullWidth type="password" autoComplete="new-password" label="API key or token" value={secret} onChange={(event) => setSecret(event.target.value)} /></Grid>
            <Grid item xs={12} md={1}><Button fullWidth sx={{ height: 56 }} variant="contained" disabled={working || !secret} onClick={() => execute(() => createThreatSource({ provider, name: name || provider, base_url: baseUrl || undefined, credentials: credentialFields }), 'Threat source saved securely.')}>Save</Button></Grid>
          </Grid>
        </SectionCard>
      ) : null}
      <SectionCard title="Configured threat sources">
        {sources.length === 0 ? <EmptyState title="No threat sources configured" description="An owner can add an encrypted provider configuration." /> : (
          <TableContainer><Table size="small"><TableHead><TableRow><TableCell>Provider</TableCell><TableCell>Name</TableCell><TableCell>Status</TableCell><TableCell>Credential</TableCell><TableCell>Last successful use</TableCell><TableCell align="right">Connection</TableCell></TableRow></TableHead>
            <TableBody>{sources.map((source) => <TableRow key={source.id}><TableCell>{source.provider.toUpperCase()}</TableCell><TableCell>{source.name}</TableCell><TableCell><StatusChip label={source.status} color={statusColor(source.status)} /></TableCell><TableCell>•••• {source.credential_fingerprint}</TableCell><TableCell>{source.last_successful_use_at ? new Date(source.last_successful_use_at).toLocaleString() : 'Never'}</TableCell><TableCell align="right">{can('threat_intelligence.sources.test') ? <Button size="small" disabled={working} onClick={() => execute(() => testThreatSource(source.id), `${source.provider.toUpperCase()} connection succeeded.`)}>Test</Button> : null}</TableCell></TableRow>)}</TableBody>
          </Table></TableContainer>
        )}
      </SectionCard>
    </Stack>
  )

  const renderSync = () => (
    <Stack spacing={3}>
      {can('threat_intelligence.sources.manage') ? (
        <SectionCard title={`Configure ${syncProvider.toUpperCase()} synchronization`}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}><TextField fullWidth label="Configuration name" value={name} onChange={(event) => setName(event.target.value)} /></Grid>
            <Grid item xs={12} md={3}><FormControl fullWidth><InputLabel>Credential</InputLabel><Select label="Credential" value={credentialId} onChange={(event) => setCredentialId(event.target.value)}>{sources.map((source) => <MenuItem key={source.id} value={source.id}>{source.name}</MenuItem>)}</Select></FormControl></Grid>
            <Grid item xs={12} md={3}><TextField fullWidth label="API root" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} /></Grid>
            <Grid item xs={12} md={2}><TextField fullWidth label={syncProvider === 'taxii' ? 'Collection ID' : 'Optional collection'} value={collectionId} onChange={(event) => setCollectionId(event.target.value)} /></Grid>
            <Grid item xs={12} md={1}><Button fullWidth sx={{ height: 56 }} variant="contained" disabled={working || !credentialId || !baseUrl} onClick={() => execute(() => createSyncConfiguration({ provider: syncProvider, name: name || `${syncProvider.toUpperCase()} Sync`, credential_id: credentialId, api_root: baseUrl, collection_id: collectionId || undefined, import_mode: 'review_required' }), 'Synchronization configuration created.')}>Add</Button></Grid>
          </Grid>
        </SectionCard>
      ) : null}
      <SectionCard title="Configurations">
        {configs.length === 0 ? <EmptyState title="No synchronization configured" description="Create a secure source and synchronization configuration first." /> : (
          <TableContainer><Table size="small"><TableHead><TableRow><TableCell>Name</TableCell><TableCell>Collection</TableCell><TableCell>Cursor</TableCell><TableCell>Status</TableCell><TableCell align="right">Manual run</TableCell></TableRow></TableHead>
            <TableBody>{configs.map((config) => <TableRow key={config.id}><TableCell>{config.name}</TableCell><TableCell>{config.collection_id || 'Default'}</TableCell><TableCell>{Object.keys(config.safe_cursor).length ? JSON.stringify(config.safe_cursor) : 'Not started'}</TableCell><TableCell>{config.enabled ? 'Scheduled' : 'Manual'}</TableCell><TableCell align="right"><Button startIcon={<RunIcon />} disabled={working || !can('threat_intelligence.sync')} onClick={() => execute(() => runSync(config.id), `${syncProvider.toUpperCase()} synchronization queued.`)}>Run</Button></TableCell></TableRow>)}</TableBody>
          </Table></TableContainer>
        )}
      </SectionCard>
      <SectionCard title="Synchronization history"><JobTable jobs={jobs} /></SectionCard>
    </Stack>
  )

  const renderBulk = () => (
    <Stack spacing={3}>
      <SectionCard title="Upload IOC import" subtitle="Uploads are encrypted, validated in the background, and require confirmation after dry run.">
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={5}><Button component="label" variant="outlined" fullWidth>{file?.name || 'Choose CSV, JSON, JSONL, STIX, or MISP file'}<input hidden type="file" accept=".csv,.json,.jsonl" onChange={(event) => setFile(event.target.files?.[0] || null)} /></Button></Grid>
          <Grid item xs={12} md={3}><FormControl fullWidth><InputLabel>Format</InputLabel><Select label="Format" value={format} onChange={(event) => setFormat(event.target.value)}>{['csv', 'json', 'jsonl', 'stix', 'misp'].map((item) => <MenuItem key={item} value={item}>{item.toUpperCase()}</MenuItem>)}</Select></FormControl></Grid>
          <Grid item xs={12} md={2}><Button variant="contained" fullWidth disabled={working || !file} onClick={() => file && execute(() => uploadIOCImport(file, format, { dry_run: true, lifecycle_status: 'new', tlp: 'TLP:AMBER' }), 'Import validation queued.')}>Validate</Button></Grid>
          <Grid item xs={12} md={2}><Button variant="outlined" fullWidth disabled={working || !iocId} onClick={() => execute(() => createBulkAction({ action: 'rescore', ioc_ids: iocId.split(',').map((item) => item.trim()).filter(Boolean) }, true), 'Bulk re-score queued.')}>Re-score IDs</Button></Grid>
          <Grid item xs={12}><TextField fullWidth label="IOC IDs for bulk action (comma-separated)" value={iocId} onChange={(event) => setIocId(event.target.value)} /></Grid>
        </Grid>
      </SectionCard>
      <SectionCard title="Import and bulk-action jobs"><JobTable jobs={jobs} onAction={(job) => job.status === 'validated' ? void execute(() => confirmIOCImport(job.id), 'Validated import confirmed.') : undefined} /></SectionCard>
    </Stack>
  )

  const renderReview = () => (
    <Stack spacing={3}>
      <SectionCard title="Queue selection">
        <FormControl sx={{ minWidth: 280 }}><InputLabel>Review queue</InputLabel><Select label="Review queue" value={queue} onChange={(event) => setQueue(event.target.value)}>
          {['new', 'under_review', 'high_risk', 'sighted', 'failed_enrichment', 'expiring'].map((item) => <MenuItem key={item} value={item}>{item.replace(/_/g, ' ')}</MenuItem>)}
        </Select></FormControl>
      </SectionCard>
      <SectionCard title="IOC candidates">
        {records.length === 0 ? <EmptyState title="Queue is clear" description="No IOCs currently match this review queue." /> : (
          <TableContainer><Table size="small"><TableHead><TableRow><TableCell>IOC</TableCell><TableCell>Type</TableCell><TableCell>Risk</TableCell><TableCell>Lifecycle</TableCell><TableCell>Sightings</TableCell></TableRow></TableHead><TableBody>{records.map((record) => <TableRow key={String(record.id)}><TableCell>{String(record.display_value || record.value || record.id)}</TableCell><TableCell>{String(record.type || '—')}</TableCell><TableCell>{String(record.risk_score ?? 0)}</TableCell><TableCell>{String(record.lifecycle_status || 'new')}</TableCell><TableCell>{String(record.internal_sighting_count ?? 0)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>
        )}
      </SectionCard>
      <SectionCard title="Review decision" subtitle="Use an IOC from the queue. Assignment is restricted to active members of this organization.">
        <Stack spacing={2}><TextField label="IOC ID" value={selectedId} onChange={(event) => setSelectedId(event.target.value)} /><TextField label="Reviewer user ID" value={reviewerId} onChange={(event) => setReviewerId(event.target.value)} /><TextField label="Review comment" multiline minRows={2} value={comment} onChange={(event) => setComment(event.target.value)} /><TextField label="Confidence (0–100, optional)" value={confidence} onChange={(event) => setConfidence(event.target.value.replace(/\D/g, '').slice(0, 3))} /><Stack direction={{ xs: 'column', md: 'row' }} spacing={1}><Button disabled={!selectedId || !reviewerId || working} onClick={() => execute(() => assignIOCReview(selectedId, reviewerId), 'Reviewer assigned.')}>Assign</Button><Button disabled={!selectedId || working} onClick={() => execute(async () => { const result = await getIOCReviewHistory(selectedId); setHistory(result.items) }, 'Review history loaded.')}>History</Button><Button color="success" disabled={!selectedId || working} onClick={() => execute(() => decideIOCReview(selectedId, { action: 'approve_activate', comment, confidence_score: confidence ? Number(confidence) : undefined }), 'IOC approved and activated.')}>Approve & activate</Button><Button disabled={!selectedId || working} onClick={() => execute(() => decideIOCReview(selectedId, { action: 'request_changes', comment }), 'Changes requested.')}>Request changes</Button><Button color="warning" disabled={!selectedId || working} onClick={() => execute(() => decideIOCReview(selectedId, { action: 'false_positive', comment }), 'IOC marked false positive.')}>False positive</Button></Stack>{history.length ? history.map((item) => <Typography key={String(item.id)} variant="body2">Revision {String(item.revision)} · {String(item.action)} · {String(item.comment || 'No comment')}</Typography>) : <Typography color="text.secondary">No decision history loaded.</Typography>}</Stack>
      </SectionCard>
    </Stack>
  )

  const renderWatchlists = () => (
    <Stack spacing={3}>
      {can('ioc.watchlists.manage') ? <SectionCard title="Create watchlist"><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField fullWidth label="Watchlist name" value={name} onChange={(event) => setName(event.target.value)} /><Button startIcon={<AddIcon />} variant="contained" disabled={working || !name.trim()} onClick={() => execute(() => createWatchlist({ name, policies: { continuous_matching: true, notification_cooldown_seconds: 900 }, tlp: 'TLP:AMBER' }), 'Watchlist created.')}>Create</Button></Stack></SectionCard> : null}
      <SectionCard title="Tenant watchlists">{records.length === 0 ? <EmptyState title="No watchlists" description="Create a watchlist to group monitored intelligence." /> : <Grid container spacing={2}>{records.map((record) => <Grid item xs={12} md={6} lg={4} key={String(record.id)}><Paper variant="outlined" sx={{ p: 2, height: '100%' }}><Stack spacing={1}><Typography variant="h6">{String(record.name)}</Typography><Typography color="text.secondary">{String(record.description || 'No description')}</Typography><Stack direction="row" spacing={1}><Chip size="small" label={String(record.status || 'active')} /><Chip size="small" label={String(record.tlp || 'TLP:AMBER')} /></Stack></Stack></Paper></Grid>)}</Grid>}</SectionCard>
      <SectionCard title="Watchlist details and membership"><Stack spacing={2}><TextField label="Watchlist ID" value={selectedId} onChange={(event) => setSelectedId(event.target.value)} /><Stack direction={{ xs: 'column', md: 'row' }} spacing={1}><Button disabled={!selectedId || working} onClick={() => execute(async () => setDetail(await getWatchlist(selectedId)), 'Watchlist details loaded.')}>Load details</Button><TextField fullWidth label="IOC ID" value={iocId} onChange={(event) => setIocId(event.target.value)} /><Button disabled={!selectedId || !iocId || working} onClick={() => execute(() => addWatchlistMember(selectedId, iocId), 'IOC added to watchlist.')}>Add</Button><Button color="error" disabled={!selectedId || !iocId || working} onClick={() => execute(() => removeWatchlistMember(selectedId, iocId), 'IOC removed from watchlist.')}>Remove</Button><Button disabled={!selectedId || working} onClick={() => execute(() => runWatchlistHunt(selectedId, 30), 'Bounded 30-day hunt queued.')}>Run hunt</Button></Stack>{detail ? <Alert severity="info">{String(detail.name)} · {String((detail.match_statistics as Record<string, unknown> | undefined)?.members || 0)} members · {String((detail.match_statistics as Record<string, unknown> | undefined)?.sightings || 0)} sightings · {String(detail.tlp)} · {String(detail.status)}</Alert> : null}</Stack></SectionCard>
    </Stack>
  )

  const renderHunts = () => (
    <Stack spacing={2}><SectionCard title="Historical hunt jobs" subtitle="Truncated results are explicitly marked and can be retried by authorized users.">
      {hunts.length === 0 ? <EmptyState title="No historical hunts" description="Start a hunt from an IOC detail or watchlist." /> : (
        <TableContainer><Table size="small"><TableHead><TableRow><TableCell>IOC</TableCell><TableCell>Status</TableCell><TableCell>Progress</TableCell><TableCell>Events</TableCell><TableCell>Matches</TableCell><TableCell>Coverage</TableCell><TableCell align="right">Action</TableCell></TableRow></TableHead><TableBody>{hunts.map((hunt) => <TableRow key={hunt.id}><TableCell>{hunt.ioc_id}</TableCell><TableCell><Chip size="small" label={hunt.status} color={statusColor(hunt.status)} /></TableCell><TableCell sx={{ minWidth: 130 }}><LinearProgress variant="determinate" value={hunt.progress || 0} /></TableCell><TableCell>{hunt.events_scanned}</TableCell><TableCell>{hunt.matches_found}</TableCell><TableCell>{hunt.truncated ? <Chip size="small" color="warning" label="Truncated" /> : 'Complete range'}</TableCell><TableCell align="right">{can('ioc.hunts.manage') && ['failed', 'cancelled', 'completed'].includes(hunt.status) ? <Button size="small" startIcon={<RefreshIcon />} onClick={() => execute(() => retryHunt(hunt.id), 'Historical hunt retried.')}>Retry</Button> : null}</TableCell></TableRow>)}</TableBody></Table></TableContainer>
      )}
    </SectionCard><SectionCard title="Cancel a queued or running hunt"><Stack direction={{ xs: 'column', md: 'row' }} spacing={1}><TextField fullWidth label="Hunt ID" value={selectedId} onChange={(event) => setSelectedId(event.target.value)} /><Button color="warning" disabled={!selectedId || working} onClick={() => execute(() => cancelHunt(selectedId), 'Hunt cancellation requested.')}>Cancel hunt</Button></Stack></SectionCard></Stack>
  )

  const renderGraph = () => (
    <Stack spacing={3}>
      <SectionCard title="Graph query"><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><TextField fullWidth label="IOC ID" value={iocId} onChange={(event) => setIocId(event.target.value)} /><Button startIcon={<RunIcon />} variant="contained" disabled={working || !iocId} onClick={() => execute(async () => { const graph = await fetchIOCGraph(iocId); setGraphNodes(graph.nodes); setGraphEdges(graph.edges); setGraphTruncated(graph.truncated) }, 'Relationship graph loaded.')}>Explore</Button></Stack></SectionCard>
      {graphTruncated ? <Alert severity="warning">The graph reached a configured safety limit and is truncated.</Alert> : null}
      <Grid container spacing={3}>
        <Grid item xs={12} lg={5}><SectionCard title="Nodes"><TableContainer><Table size="small" aria-label="Relationship graph nodes"><TableHead><TableRow><TableCell>Type</TableCell><TableCell>Label</TableCell><TableCell>ID</TableCell></TableRow></TableHead><TableBody>{graphNodes.map((node) => <TableRow key={`${node.type}:${node.id}`}><TableCell>{node.type}</TableCell><TableCell>{node.label}</TableCell><TableCell>{node.id}</TableCell></TableRow>)}</TableBody></Table></TableContainer></SectionCard></Grid>
        <Grid item xs={12} lg={7}><SectionCard title="Evidence-backed edges"><TableContainer><Table size="small" aria-label="Relationship graph edges"><TableHead><TableRow><TableCell>Relationship</TableCell><TableCell>Origin</TableCell><TableCell>Confidence</TableCell><TableCell>Evidence</TableCell></TableRow></TableHead><TableBody>{graphEdges.map((edge) => <TableRow key={edge.id}><TableCell>{edge.type}</TableCell><TableCell>{edge.origin}</TableCell><TableCell>{edge.confidence}%</TableCell><TableCell>{edge.evidence_count}</TableCell></TableRow>)}</TableBody></Table></TableContainer></SectionCard></Grid>
      </Grid>
    </Stack>
  )

  const renderDetection = () => (
    <SectionCard title="Generate typed draft detection" subtitle="Generated rules remain disabled drafts and never publish automatically.">
      <Stack spacing={2}><TextField label="Source IOC ID" value={iocId} onChange={(event) => setIocId(event.target.value)} /><FormControl><InputLabel>Severity</InputLabel><Select label="Severity" value={action} onChange={(event) => setAction(event.target.value)}>{['low', 'medium', 'high', 'critical'].map((item) => <MenuItem key={item} value={item}>{item}</MenuItem>)}</Select></FormControl><Button variant="contained" disabled={working || !iocId} onClick={() => execute(() => generateIOCDetection(iocId, { severity: ['low', 'medium', 'high', 'critical'].includes(action) ? action : 'medium', suppression_seconds: 300 }), 'Draft detection generated. Open Detection Engineering to validate and simulate it.')}>Generate draft</Button></Stack>
    </SectionCard>
  )

  const renderRecommendations = () => (
    <Stack spacing={3}>
      <SectionCard title="Create recommendation"><Grid container spacing={2}><Grid item xs={12} md={5}><TextField fullWidth label="IOC ID" value={iocId} onChange={(event) => setIocId(event.target.value)} /></Grid><Grid item xs={12} md={5}><FormControl fullWidth><InputLabel>Proposed action</InputLabel><Select label="Proposed action" value={action} onChange={(event) => setAction(event.target.value)}>{['block_ip', 'block_cidr', 'block_domain', 'block_url', 'quarantine_hash', 'add_to_edr_watchlist', 'investigate_affected_user'].map((item) => <MenuItem key={item} value={item}>{item.replace(/_/g, ' ')}</MenuItem>)}</Select></FormControl></Grid><Grid item xs={12} md={2}><Button fullWidth sx={{ height: 56 }} variant="contained" disabled={working || !iocId} onClick={() => execute(() => createRecommendation(iocId, { action }), 'Recommendation created and sent for human approval.')}>Request</Button></Grid></Grid></SectionCard>
      <SectionCard title="Recommendation status"><JobTable jobs={records as unknown as CommercialJob[]} /></SectionCard>
      <SectionCard title="Human approval decision" subtitle="The requester cannot approve their own recommendation."><Stack direction={{ xs: 'column', md: 'row' }} spacing={1}><TextField fullWidth label="Approval ID" value={selectedId} onChange={(event) => setSelectedId(event.target.value)} /><Button color="success" disabled={!selectedId || working || !can('ioc.response.approve')} onClick={() => execute(() => decideApproval(selectedId, 'approve'), 'Recommendation approved.')}>Approve</Button><Button color="error" disabled={!selectedId || working || !can('ioc.response.approve')} onClick={() => execute(() => decideApproval(selectedId, 'reject'), 'Recommendation rejected.')}>Reject</Button></Stack><Typography variant="caption" color="text.secondary">Approval is bound to the exact organization, IOC, action, target category, and request fingerprint. No unsupported connector action is executed.</Typography></SectionCard>
    </Stack>
  )

  const renderReports = () => (
    <Stack spacing={3}>
      <SectionCard title="Generate IOC report"><Stack direction={{ xs: 'column', md: 'row' }} spacing={2}><FormControl fullWidth><InputLabel>Format</InputLabel><Select label="Format" value={format} onChange={(event) => setFormat(event.target.value)}>{['csv', 'json', 'jsonl', 'markdown', 'html', 'stix', 'zip'].map((item) => <MenuItem key={item} value={item}>{item.toUpperCase()}</MenuItem>)}</Select></FormControl><Button startIcon={<SyncIcon />} variant="contained" disabled={working} onClick={() => execute(() => createIOCReport({ report_type: 'executive_summary', format }), 'IOC report queued.')}>Generate</Button></Stack></SectionCard>
      <SectionCard title="Report jobs"><JobTable jobs={jobs} onAction={(job) => { if (job.status === 'completed' && !working) void downloadReport(job) }} /></SectionCard>
    </Stack>
  )

  const content = () => {
    if (mode === 'sources') return renderSources()
    if (mode === 'taxii' || mode === 'misp') return renderSync()
    if (mode === 'bulk') return renderBulk()
    if (mode === 'review') return renderReview()
    if (mode === 'watchlists') return renderWatchlists()
    if (mode === 'hunts') return renderHunts()
    if (mode === 'graph') return renderGraph()
    if (mode === 'detections') return renderDetection()
    if (mode === 'recommendations') return renderRecommendations()
    return renderReports()
  }

  if (loading) return <LoadingState />
  return (
    <Box>
      <PageHeader title={workspaceCopy[mode].title} description={workspaceCopy[mode].subtitle} />
      <Stack spacing={2}>
        {error ? <ErrorState message={error} onRetry={() => void load()} /> : null}
        {notice ? <Alert severity="success" onClose={() => setNotice('')}>{notice}</Alert> : null}
        {content()}
      </Stack>
    </Box>
  )
}

export default IOCCommercialWorkspace
