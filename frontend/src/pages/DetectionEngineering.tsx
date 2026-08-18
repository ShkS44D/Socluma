import { useCallback, useEffect, useState } from 'react'
import { Alert, Box, Button, Stack, Tab, Tabs, TextField, Typography } from '@mui/material'
import { PageHeader, SectionCard, StatusChip } from '../components/ui'
import {
  getDetectionAnalytics,
  getDetectionContentPacks,
  getDetectionExceptions,
  getDetectionMaintenanceWindows,
  getMitreDetectionCoverage,
  importDetectionContentPack,
} from '../services/api/detectionRules'
import { usePermissionStore } from '../store'

const DetectionEngineering = () => {
  const can = usePermissionStore((state) => state.can)
  const [tab, setTab] = useState(0)
  const [analytics, setAnalytics] = useState<Array<Record<string, any>>>([])
  const [coverage, setCoverage] = useState<Array<Record<string, any>>>([])
  const [exceptions, setExceptions] = useState<Array<Record<string, any>>>([])
  const [maintenance, setMaintenance] = useState<Array<Record<string, any>>>([])
  const [packs, setPacks] = useState<Array<Record<string, any>>>([])
  const [manifest, setManifest] = useState('')
  const [report, setReport] = useState<Record<string, any> | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setError('')
    try {
      const requests: Array<Promise<void>> = []
      if (can('detections.analytics.view') || can('detections.metrics.view')) {
        requests.push(getDetectionAnalytics().then((data) => setAnalytics(data.rules)))
        requests.push(getMitreDetectionCoverage().then((data) => setCoverage(data.coverage)))
      }
      if (can('detections.exceptions.view') || can('detections.view')) {
        requests.push(getDetectionExceptions().then(setExceptions))
        requests.push(getDetectionMaintenanceWindows().then(setMaintenance))
      }
      if (can('detections.content_packs.view')) {
        requests.push(getDetectionContentPacks().then(setPacks))
      }
      await Promise.all(requests)
    } catch {
      setError('Unable to load one or more detection-engineering areas.')
    }
  }, [can])

  useEffect(() => { void load() }, [load])

  return (
    <Stack spacing={4}>
      <PageHeader
        title="Detection Engineering"
        description="Rule health, ATT&CK coverage, operational controls, and content packs"
        breadcrumbs={[{ label: 'Detection Rules', href: '/detection-rules' }, { label: 'Engineering' }]}
      />
      {error && <Alert severity="error">{error}</Alert>}
      <Tabs value={tab} onChange={(_, value) => setTab(value)} aria-label="Detection engineering areas">
        <Tab label="Rule Analytics" />
        <Tab label="ATT&CK Coverage" />
        <Tab label="Exceptions & Maintenance" />
        <Tab label="Content Packs" />
      </Tabs>

      {tab === 0 && <SectionCard title="Rule Health and Quality">
        <Stack spacing={2}>
          {analytics.length === 0 && <Typography color="text.secondary">No rule analytics are available.</Typography>}
          {analytics.map((rule) => <Box key={rule.rule_id} sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              <Typography fontWeight={600}>{rule.name}</Typography>
              <StatusChip label={rule.status} />
              <Typography variant="body2">Quality {rule.quality_score}/100</Typography>
              <Typography variant="body2">Matches {rule.match_volume}</Typography>
              <Typography variant="body2">FP rate {rule.false_positive_rate == null ? 'No feedback' : `${Math.round(rule.false_positive_rate * 100)}%`}</Typography>
            </Stack>
            {(rule.recommendations || []).map((item: string) => <Alert severity="info" key={item} sx={{ mt: 1 }}>{item}</Alert>)}
          </Box>)}
        </Stack>
      </SectionCard>}

      {tab === 1 && <SectionCard title="MITRE ATT&CK Coverage">
        <Stack spacing={2}>
          <Alert severity="info">Mappings show intended coverage; healthy telemetry and true-positive evidence are reported separately.</Alert>
          {coverage.map((item) => <Box key={item.technique_id} sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
            <Typography fontWeight={600}>{item.technique_id}</Typography>
            <Typography variant="body2">Production {item.production} · Tested {item.tested} · Draft {item.draft} · Healthy source {item.healthy_source} · Unhealthy source {item.unhealthy_source}</Typography>
          </Box>)}
        </Stack>
      </SectionCard>}

      {tab === 2 && <Stack spacing={3}>
        <SectionCard title="Exceptions">
          {exceptions.length === 0 ? <Typography color="text.secondary">No exceptions.</Typography> : exceptions.map((item) =>
            <Box key={item.id} sx={{ mb: 1 }}><Typography fontWeight={600}>{item.name}</Typography><Typography variant="body2">{item.reason} · {item.status}</Typography></Box>
          )}
        </SectionCard>
        <SectionCard title="Maintenance Windows">
          {maintenance.length === 0 ? <Typography color="text.secondary">No maintenance windows.</Typography> : maintenance.map((item) =>
            <Box key={item.id} sx={{ mb: 1 }}><Typography fontWeight={600}>{item.name}</Typography><Typography variant="body2">{item.starts_at} – {item.ends_at} · {item.status}</Typography></Box>
          )}
        </SectionCard>
      </Stack>}

      {tab === 3 && <SectionCard title="Content Packs">
        <Stack spacing={2}>
          {packs.map((pack) => <Typography key={pack.id}>{pack.name} {pack.version} · {pack.publisher}</Typography>)}
          {can('detections.content_pack.manage') && <>
            <TextField label="Content-pack manifest (JSON)" multiline rows={10} value={manifest} onChange={(event) => setManifest(event.target.value)} />
            <Stack direction="row" spacing={2}>
              <Button variant="outlined" onClick={async () => setReport(await importDetectionContentPack(JSON.parse(manifest), true))}>Validate Dry Run</Button>
              <Button variant="contained" onClick={async () => setReport(await importDetectionContentPack(JSON.parse(manifest), false))}>Install as Drafts</Button>
            </Stack>
          </>}
          {report && <Alert severity={report.valid ? 'success' : 'error'}>{report.valid ? `Validated ${report.rule_count} rules` : 'Validation failed'}</Alert>}
        </Stack>
      </SectionCard>}
    </Stack>
  )
}

export default DetectionEngineering
