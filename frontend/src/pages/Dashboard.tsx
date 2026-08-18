import React from 'react'
import { Alert, AlertTitle, Box, Button, Grid, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'
import {
  Assessment,
  CrisisAlert,
  Gavel,
  Security,
  Rule,
  Storage as StorageIcon,
} from '@mui/icons-material'
import {
  AlertTimelineWidget,
  DistributionList,
  RecentEventsList,
  RecentIncidentsTable,
} from '../components/dashboard'
import {
  ErrorState,
  LoadingState,
  MetricCard,
  PageHeader,
  SectionCard,
} from '../components/ui'
import useDashboardData from '../hooks/useDashboardData'
import { formatPercent } from '../utils'

const Dashboard: React.FC = () => {
  const { data, loading, error, reload } = useDashboardData()

  if (loading) {
    return <LoadingState title="Loading SOC dashboard" />
  }

  if (!data) {
    return <ErrorState message={error || 'Dashboard data is unavailable.'} onRetry={reload} />
  }

  const {
    metrics,
    incidentStats,
    severityDistribution,
    alertTimeline,
    riskOverview,
    mitreOverview,
    recentEvents,
    recentIncidents,
  } = data

  return (
    <Stack spacing={6}>
      <PageHeader
        title="SOC Dashboard"
        description="Monitor operational telemetry, active detections, incident posture, and MITRE-mapped activity from one analyst workspace."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Dashboard' },
        ]}
      />
      {error && (
        <Alert severity="warning" variant="outlined">
          {error}
        </Alert>
      )}
      {metrics.collectorsOnline.value === 0 && metrics.eventsToday.value === 0 && (
        <Alert
          severity="info"
          variant="outlined"
          action={(
            <Button
              color="inherit"
              size="small"
              component={RouterLink}
              to="/log-sources"
            >
              Connect collector
            </Button>
          )}
        >
          <AlertTitle>No telemetry connected to this organization</AlertTitle>
          Each organization has isolated collectors and events. Register a collector for this
          organization to begin receiving telemetry; collectors from another organization cannot
          share data here.
        </Alert>
      )}

      <Box sx={{ width: '100%', overflow: 'hidden' }}>
        <Grid container spacing={6}>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.openIncidents.title}
            value={metrics.openIncidents.value}
            trend={metrics.openIncidents.trend}
            severity={metrics.openIncidents.severity}
            icon={<Assessment fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.totalAlerts.title}
            value={metrics.totalAlerts.value}
            trend={metrics.totalAlerts.trend}
            severity={metrics.totalAlerts.severity}
            icon={<CrisisAlert fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.highRiskIncidents.title}
            value={metrics.highRiskIncidents.value}
            trend={metrics.highRiskIncidents.trend}
            severity={metrics.highRiskIncidents.severity}
            icon={<Gavel fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.activeIOCs.title}
            value={metrics.activeIOCs.value}
            trend={metrics.activeIOCs.trend}
            severity={metrics.activeIOCs.severity}
            icon={<Security fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.detectionCount.title}
            value={metrics.detectionCount.value}
            trend={metrics.detectionCount.trend}
            severity={metrics.detectionCount.severity}
            icon={<Rule fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.connectedSources.title}
            value={metrics.connectedSources.value}
            trend={metrics.connectedSources.trend}
            severity={metrics.connectedSources.severity}
            icon={<StorageIcon fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.collectorsOnline.title}
            value={metrics.collectorsOnline.value}
            trend={metrics.collectorsOnline.trend}
            severity={metrics.collectorsOnline.severity}
            icon={<Security fontSize="small" />}
          />
        </Grid>
        <Grid item xs={12} sm={6} xl={3}>
          <MetricCard
            title={metrics.eventsToday.title}
            value={metrics.eventsToday.value}
            trend={metrics.eventsToday.trend}
            severity={metrics.eventsToday.severity}
            icon={<CrisisAlert fontSize="small" />}
          />
        </Grid>

        <Grid item xs={12} lg={6}>
          <SectionCard
            title="Incident Severity Distribution"
            subtitle="Open incident posture by severity tier."
          >
            <DistributionList
              items={severityDistribution}
              emptyMessage="No open incidents are currently mapped by severity."
            />
          </SectionCard>
        </Grid>

        <Grid item xs={12} lg={6}>
          <SectionCard
            title="Alert Timeline"
            subtitle="Recent alert volume grouped across the latest operational window."
          >
            <AlertTimelineWidget points={alertTimeline} />
          </SectionCard>
        </Grid>

        <Grid item xs={12} lg={6}>
          <SectionCard
            title="Risk Overview"
            subtitle="Distribution of recent incidents by risk score band."
          >
            <DistributionList
              items={riskOverview}
              emptyMessage="Recent incidents are not available for risk band analysis."
            />
          </SectionCard>
        </Grid>

        <Grid item xs={12} lg={6}>
          <SectionCard
            title="MITRE ATT&CK Overview"
            subtitle="Most frequently mapped techniques in recent incidents."
          >
            <DistributionList
              items={mitreOverview}
              emptyMessage="No MITRE ATT&CK mappings are available yet."
            />
          </SectionCard>
        </Grid>

        <Grid item xs={12} lg={7}>
          <SectionCard
            title="Recent Security Events"
            subtitle="Latest normalized events entering the detection and correlation pipeline."
          >
            <RecentEventsList events={recentEvents} />
          </SectionCard>
        </Grid>

        <Grid item xs={12} lg={5}>
          <SectionCard
            title="Operational Snapshot"
            subtitle="Key workflow and response indicators from current incident telemetry."
          >
            <Stack spacing={2.5}>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  Average Risk Score
                </Typography>
                <Typography variant="h4" sx={{ mt: 0.5 }}>
                  {incidentStats?.average_risk_score.toFixed(1) || '0.0'}
                </Typography>
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      MTTD
                    </Typography>
                    <Typography variant="h6" sx={{ mt: 1 }}>
                      {incidentStats?.mean_time_to_detect_hours?.toFixed(1) || '0.0'}h
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      MTTR
                    </Typography>
                    <Typography variant="h6" sx={{ mt: 1 }}>
                      {incidentStats?.mean_time_to_respond_hours?.toFixed(1) || '0.0'}h
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      Active Investigations
                    </Typography>
                    <Typography variant="h6" sx={{ mt: 1 }}>
                      {incidentStats?.active_investigations || 0}
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={6}>
                  <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      Resolution Window
                    </Typography>
                    <Typography variant="h6" sx={{ mt: 1 }}>
                      {formatPercent(
                        Math.min(
                          ((incidentStats?.average_resolution_time_hours || 0) / 24) * 100,
                          100
                        )
                      )}
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Stack>
          </SectionCard>
        </Grid>

        <Grid item xs={12}>
          <SectionCard
            title="Recent Incidents"
            subtitle="Latest incident correlation results with severity, risk, workflow state, and priority."
          >
            <RecentIncidentsTable incidents={recentIncidents} />
          </SectionCard>
        </Grid>
      </Grid>
      </Box>
    </Stack>
  )
}

export default Dashboard
