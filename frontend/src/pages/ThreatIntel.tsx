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
import { Add as AddIcon, Security as SecurityIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import {
  getIOCs,
  getIOCStats,
  createIOC,
  updateIOC,
  deleteIOC,
} from '../services/api/iocs'
import { IOC, Severity, IndicatorType, IOCStats } from '../services/api/types'
import { formatDatePKT } from '../utils/time'
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
import IOCFormModal from '../components/iocs/IOCFormModal'

const ThreatIntel: React.FC = () => {
  const navigate = useNavigate()
  const [iocs, setIocs] = useState<IOC[]>([])
  const [stats, setStats] = useState<IOCStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<IndicatorType | ''>('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [modalOpen, setModalOpen] = useState(false)
  const [editingIoc, setEditingIoc] = useState<IOC | null>(null)
  const [modalLoading, setModalLoading] = useState(false)

  const fetchData = async () => {
    try {
      setLoading(true)
      setError('')
      const [iocData, statsData] = await Promise.all([
        getIOCs(),
        getIOCStats(),
      ])
      setIocs(iocData.items)
      setStats(statsData)
    } catch (err) {
      setError('Failed to load threat intelligence data')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const filteredIocs = useMemo(() => {
    return iocs.filter((ioc) => {
      const matchesSearch =
        !search ||
        ioc.value.toLowerCase().includes(search.toLowerCase()) ||
        (ioc.description && ioc.description.toLowerCase().includes(search.toLowerCase()))
      const matchesType = !typeFilter || ioc.type === typeFilter
      const matchesSeverity = !severityFilter || ioc.severity === severityFilter
      return matchesSearch && matchesType && matchesSeverity
    })
  }, [iocs, search, typeFilter, severityFilter])

  const getReputation = (ioc: IOC): string => {
    const maliciousEnrichment = ioc.enrichments.find(e => e.malicious_count > 0)
    if (maliciousEnrichment) return 'Malicious'
    const cleanEnrichment = ioc.enrichments.find(e => e.reputation === 'clean')
    if (cleanEnrichment) return 'Clean'
    return 'Unknown'
  }

  const handleCreate = async (data: any) => {
    try {
      setModalLoading(true)
      await createIOC(data)
      fetchData()
    } finally {
      setModalLoading(false)
    }
  }

  const handleEdit = async (data: any) => {
    if (!editingIoc) return
    try {
      setModalLoading(true)
      await updateIOC(editingIoc.id, data)
      fetchData()
    } finally {
      setModalLoading(false)
    }
  }

  const handleDelete = async (iocId: string) => {
    if (confirm('Are you sure you want to delete this IOC?')) {
      try {
        await deleteIOC(iocId)
        fetchData()
      } catch (err) {
        setError('Failed to delete IOC')
        console.error(err)
      }
    }
  }

  const columns: DataTableColumn<IOC>[] = [
    {
      key: 'value',
      header: 'Indicator',
      render: (ioc) => (
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle2" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {ioc.value}
          </Typography>
          {ioc.description && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
              {ioc.description}
            </Typography>
          )}
        </Box>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      render: (ioc) => <StatusChip label={ioc.type} />,
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (ioc) => (
        <StatusChip
          label={ioc.severity}
          color={
            ioc.severity === 'critical' || ioc.severity === 'high'
              ? 'error'
              : ioc.severity === 'medium'
              ? 'warning'
              : 'info'
          }
        />
      ),
    },
    {
      key: 'confidence',
      header: 'Confidence',
      render: (ioc) => (
        <Typography variant="body2">{ioc.confidence_score}%</Typography>
      ),
    },
    {
      key: 'risk',
      header: 'Risk',
      render: (ioc) => (
        <StatusChip
          label={`${ioc.risk_score}/100`}
          color={ioc.risk_score >= 70 ? 'error' : ioc.risk_score >= 40 ? 'warning' : 'success'}
        />
      ),
    },
    {
      key: 'lifecycle',
      header: 'Lifecycle',
      render: (ioc) => <StatusChip label={ioc.lifecycle_status.replace(/_/g, ' ')} />,
    },
    {
      key: 'sightings',
      header: 'Sightings',
      render: (ioc) => <Typography variant="body2">{ioc.internal_sighting_count}</Typography>,
    },
    {
      key: 'source',
      header: 'Source',
      render: (ioc) => (
        <Typography variant="body2">{ioc.source || '—'}</Typography>
      ),
    },
    {
      key: 'reputation',
      header: 'Reputation',
      render: (ioc) => (
        <StatusChip
          label={getReputation(ioc)}
          color={
            getReputation(ioc) === 'Malicious'
              ? 'error'
              : getReputation(ioc) === 'Clean'
              ? 'success'
              : 'default'
          }
        />
      ),
    },
    {
      key: 'created',
      header: 'Created',
      render: (ioc) => formatDatePKT(ioc.created_at),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (ioc) => (
        <Stack direction="row" spacing={1}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => navigate(`/threat-intel/${ioc.id}`)}
          >
            View
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={(e) => {
              e.stopPropagation()
              setEditingIoc(ioc)
              setModalOpen(true)
            }}
          >
            Edit
          </Button>
          <Button
            variant="outlined"
            color="error"
            size="small"
            onClick={(e) => {
              e.stopPropagation()
              handleDelete(ioc.id)
            }}
          >
            Delete
          </Button>
        </Stack>
      ),
    },
  ]

  if (loading) {
    return <LoadingState title="Loading Threat Intelligence" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchData} />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Threat Intelligence"
        description="Manage Indicators of Compromise (IOCs) and threat enrichment data"
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Threat Intel' },
        ]}
      />

      <Box sx={{ width: '100%', overflow: 'hidden' }}>
        <Grid container spacing={6}>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Total IOCs"
              value={stats?.total_iocs || 0}
              severity="info"
              icon={<SecurityIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Active IOCs"
              value={stats?.active_iocs || 0}
              severity="error"
              icon={<SecurityIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="High Risk"
              value={stats?.high_risk_iocs || 0}
              severity="warning"
              icon={<SecurityIcon fontSize="small" />}
            />
          </Grid>
          <Grid item xs={12} sm={6} xl={3}>
            <MetricCard
              title="Internally Sighted"
              value={stats?.iocs_with_sightings || 0}
              severity="info"
              icon={<SecurityIcon fontSize="small" />}
            />
          </Grid>
        </Grid>
      </Box>

      <SectionCard
        title="Indicators of Compromise"
        action={
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => {
              setEditingIoc(null)
              setModalOpen(true)
            }}
          >
            Add IOC
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
            <InputLabel>Type</InputLabel>
            <Select
              value={typeFilter}
              label="Type"
              onChange={(e) => setTypeFilter(e.target.value as IndicatorType | '')}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="ip">IP</MenuItem>
              <MenuItem value="ipv4">IPv4</MenuItem>
              <MenuItem value="ipv6">IPv6</MenuItem>
              <MenuItem value="cidr">CIDR</MenuItem>
              <MenuItem value="domain">Domain</MenuItem>
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="email">Email</MenuItem>
              <MenuItem value="hash">Hash</MenuItem>
              <MenuItem value="sha256">SHA-256</MenuItem>
            </Select>
          </FormControl>
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
        </Box>

        {filteredIocs.length === 0 ? (
          <EmptyState
            title="No IOCs found"
            description="Add your first Indicator of Compromise to get started"
          />
        ) : (
          <DataTable
            columns={columns}
            rows={filteredIocs}
            getRowId={(row) => row.id}
            onRowClick={(ioc) => navigate(`/threat-intel/${ioc.id}`)}
          />
        )}
      </SectionCard>

      <IOCFormModal
        open={modalOpen}
        onClose={() => {
          setModalOpen(false)
          setEditingIoc(null)
        }}
        onSubmit={editingIoc ? handleEdit : handleCreate}
        initialData={
          editingIoc
            ? {
                type: editingIoc.type,
                value: editingIoc.value,
                description: editingIoc.description ?? undefined,
                source: editingIoc.source ?? undefined,
                severity: editingIoc.severity,
                confidence_score: editingIoc.confidence_score,
                tags: editingIoc.tags ?? undefined,
                is_active: editingIoc.is_active,
              }
            : null
        }
        loading={modalLoading}
      />
    </Stack>
  )
}

export default ThreatIntel
