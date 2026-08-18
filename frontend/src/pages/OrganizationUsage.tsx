import React, { useEffect, useState } from 'react'
import { Box, Grid } from '@mui/material'
import { BarChart as MetricIcon } from '@mui/icons-material'
import { ErrorState, LoadingState, MetricCard, PageHeader } from '../components/ui'
import { getCurrentOrganization, getOrganizationUsage, OrganizationUsage as Usage } from '../services/api'

const OrganizationUsage: React.FC = () => {
  const [usage, setUsage] = useState<Usage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const org = await getCurrentOrganization()
      setUsage(await getOrganizationUsage(org.id))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load usage')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />
  if (!usage) return <ErrorState message="Usage data unavailable" onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader title="Usage" description="Current tenant-scoped application usage for the active monthly period" />
      <Grid container spacing={3} sx={{ mt: 1 }}>
        <Grid item xs={12} md={4}><MetricCard title="Users" value={`${usage.user_count}/${usage.limits.max_users}`} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Collectors" value={`${usage.collector_count}/${usage.limits.max_collectors}`} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Application Payload Storage (estimate)" value={`${Math.round(usage.storage_bytes / 1024 / 1024)} MB`} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Events" value={usage.event_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Alerts" value={usage.alert_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Incidents" value={usage.incident_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Playbooks" value={usage.playbook_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="SOAR Executions" value={usage.soar_execution_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Playbook Executions" value={usage.playbook_execution_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="Triage AI Requests" value={usage.triage_ai_request_count} icon={<MetricIcon />} /></Grid>
        <Grid item xs={12} md={4}><MetricCard title="API Requests" value={usage.api_request_count} icon={<MetricIcon />} /></Grid>
      </Grid>
    </Box>
  )
}

export default OrganizationUsage
