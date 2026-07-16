import React, { useEffect, useMemo, useState } from 'react'
import {
  Box,
  Button,
  Grid,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { Add as AddIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import {
  getDetectionRules,
  updateDetectionRule,
  deleteDetectionRule,
  createDetectionRule,
} from '../services/api/detectionRules'
import { DetectionRule, Severity, DetectionRuleCreate, DetectionRuleUpdate } from '../services/api/types'
import { formatDateTime } from '../utils/formatters'
import {
  PageHeader,
  MetricCard,
  SectionCard,
  DataTable,
  DataTableColumn,
  StatusChip,
  LoadingState,
  ErrorState,
  EmptyState,
} from '../components/ui'
import DetectionRuleFormModal from '../components/detection-rules/DetectionRuleFormModal'

const DetectionRules: React.FC = () => {
  const navigate = useNavigate()
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [enabledFilter, setEnabledFilter] = useState<string>('') // 'true' | 'false' | ''
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<DetectionRule | null>(null)
  const [modalLoading, setModalLoading] = useState(false)

  const fetchRules = async () => {
    try {
      setLoading(true)
      setError('')
      const data = await getDetectionRules()
      setRules(data)
    } catch (err) {
      setError('Failed to load detection rules')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      const matchesSearch =
        !search || rule.name.toLowerCase().includes(search.toLowerCase())
      const matchesSeverity =
        !severityFilter || rule.severity === severityFilter
      const matchesEnabled =
        !enabledFilter ||
        (enabledFilter === 'true' && rule.enabled) ||
        (enabledFilter === 'false' && !rule.enabled)
      const matchesType = !typeFilter || rule.type === typeFilter
      return matchesSearch && matchesSeverity && matchesEnabled && matchesType
    })
  }, [rules, search, severityFilter, enabledFilter, typeFilter])

  const stats = useMemo(() => {
    const total = filteredRules.length
    const enabled = filteredRules.filter((r) => r.enabled).length
    const disabled = total - enabled
    const critical = filteredRules.filter((r) => r.severity === 'critical').length
    return { total, enabled, disabled, critical }
  }, [filteredRules])

  const handleCreate = async (data: DetectionRuleCreate | DetectionRuleUpdate) => {
    try {
      setModalLoading(true)
      await createDetectionRule(data as DetectionRuleCreate)
      fetchRules()
    } finally {
      setModalLoading(false)
    }
  }

  const handleEdit = async (data: DetectionRuleCreate | DetectionRuleUpdate) => {
    if (!editingRule) return
    try {
      setModalLoading(true)
      await updateDetectionRule(editingRule.id, data)
      fetchRules()
    } finally {
      setModalLoading(false)
    }
  }

  const handleDelete = async (ruleId: string) => {
    if (confirm('Are you sure you want to delete this detection rule?')) {
      try {
        await deleteDetectionRule(ruleId)
        fetchRules()
      } catch (err) {
        setError('Failed to delete detection rule')
        console.error(err)
      }
    }
  }

  const columns: DataTableColumn<DetectionRule>[] = [
    {
      key: 'name',
      header: 'Rule Name',
      render: (rule) => (
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle2" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {rule.name}
          </Typography>
          {rule.description && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
              {rule.description}
            </Typography>
          )}
        </Box>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      render: (rule) => (
        <StatusChip label={rule.type || rule.rule_type || '—'} />
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (rule) => (
        <StatusChip
          label={rule.severity}
          color={
            rule.severity === 'critical' || rule.severity === 'high'
              ? 'error'
              : rule.severity === 'medium'
              ? 'warning'
              : 'info'
          }
        />
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (rule) => (
        <StatusChip
          label={rule.enabled ? 'Enabled' : 'Disabled'}
          color={rule.enabled ? 'success' : 'default'}
        />
      ),
    },
    {
      key: 'query',
      header: 'Query',
      render: (rule) => (
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            maxWidth: 300,
            display: 'block',
          }}
        >
          {rule.query || '—'}
        </Typography>
      ),
    },
    {
      key: 'created',
      header: 'Created',
      render: (rule) => formatDateTime(rule.created_at),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (rule) => (
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => navigate(`/detection-rules/${rule.id}`)}
          >
            View
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={(e) => {
              e.stopPropagation()
              setEditingRule(rule)
              setModalOpen(true)
            }}
          >
            Edit
          </Button>
          <Button
            variant="outlined"
            size="small"
            color={rule.enabled ? 'warning' : 'success'}
            onClick={async () => {
              try {
                await updateDetectionRule(rule.id, { enabled: !rule.enabled })
                fetchRules()
              } catch (err) {
                setError('Failed to update detection rule status')
                console.error(err)
              }
            }}
          >
            {rule.enabled ? 'Disable' : 'Enable'}
          </Button>
          <Button
            variant="outlined"
            color="error"
            size="small"
            onClick={() => handleDelete(rule.id)}
          >
            Delete
          </Button>
        </Stack>
      ),
    },
  ]

  if (loading) {
    return <LoadingState title="Loading Detection Rules" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchRules} />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Detection Rules"
        description="Manage Sigma-based detection logic, queries, and security analytics rules"
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Detection Rules' },
        ]}
      />

      <Box sx={{ width: '100%', overflow: 'hidden' }}>
        <Grid container spacing={6}>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Total Rules"
              value={stats.total}
              severity="info"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Enabled Rules"
              value={stats.enabled}
              severity="success"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Disabled Rules"
              value={stats.disabled}
              severity="info"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Critical Rules"
              value={stats.critical}
              severity="error"
              icon={<AddIcon fontSize="small" />}
            />
          </Grid>
        </Grid>
      </Box>

      <SectionCard
        title="Detection Rules"
        action={
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => {
              setEditingRule(null)
              setModalOpen(true)
            }}
          >
            Create Detection Rule
          </Button>
        }
      >
        <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <TextField
            label="Search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            sx={{ minWidth: 300 }}
          />
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select
              value={severityFilter}
              label="Severity"
              onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={enabledFilter}
              label="Status"
              onChange={(e) => setEnabledFilter(e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="true">Enabled</MenuItem>
              <MenuItem value="false">Disabled</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Type</InputLabel>
            <Select
              value={typeFilter}
              label="Type"
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="sigma">Sigma</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </Select>
          </FormControl>
        </Box>

        {filteredRules.length === 0 ? (
          <EmptyState
            title="No detection rules found"
            description="Create your first detection rule to get started"
          />
        ) : (
          <DataTable
            columns={columns}
            rows={filteredRules}
            getRowId={(row) => row.id}
            onRowClick={(rule) => navigate(`/detection-rules/${rule.id}`)}
          />
        )}
      </SectionCard>

      <DetectionRuleFormModal
        open={modalOpen}
        onClose={() => {
          setModalOpen(false)
          setEditingRule(null)
        }}
        onSubmit={editingRule ? handleEdit : handleCreate}
        initialData={editingRule}
        loading={modalLoading}
      />
    </Stack>
  )
}

export default DetectionRules
