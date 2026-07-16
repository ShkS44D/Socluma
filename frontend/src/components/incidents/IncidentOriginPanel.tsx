import React from 'react'
import { Box, Button, Chip, Divider, Paper, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'
import { IncidentExplanation } from '../../services/api'
import { formatDateTimePKT } from '../../utils/time'
import { EmptyState, SectionCard, StatusChip } from '../ui'

interface IncidentOriginPanelProps {
  explanation: IncidentExplanation | null
  error?: string | null
  onOpenCopilot: () => void
}

const chainSteps = ['Event', 'Detection Rule', 'Alert', 'Correlation', 'Incident']

const IncidentOriginPanel: React.FC<IncidentOriginPanelProps> = ({ explanation, error, onOpenCopilot }) => {
  if (!explanation) {
    return (
      <SectionCard title="How This Incident Was Created">
        <EmptyState
          title="Origin details are unavailable"
          description={error || "No provable alert and event chain is currently linked."}
        />
      </SectionCard>
    )
  }

  const primary = explanation.primary_alert
  const topEntities = explanation.affected_entities.slice(0, 10)
  const riskFactors = Object.entries(explanation.risk_score_breakdown).filter(
    ([key, value]) => key !== 'reason' && key !== 'total' && typeof value === 'number' && value !== 0
  )

  return (
    <SectionCard
      title="How This Incident Was Created"
      action={<Button variant="contained" onClick={onOpenCopilot}>Investigate with Copilot</Button>}
    >
      <Stack spacing={4}>
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', md: 'repeat(5, minmax(0, 1fr))' },
            gap: 1,
          }}
        >
          {chainSteps.map((step, index) => (
            <Paper key={step} variant="outlined" sx={{ p: 2, minHeight: 84 }}>
              <Typography variant="caption" color="text.secondary">Step {index + 1}</Typography>
              <Typography variant="subtitle2">{step}</Typography>
              <Typography variant="caption" color="text.secondary">
                {step === 'Event' && `${explanation.source_events.length} source event(s)`}
                {step === 'Detection Rule' && (primary?.detection_rule_name || 'Rule details unavailable')}
                {step === 'Alert' && (primary ? 'Primary alert identified' : 'No primary alert')}
                {step === 'Correlation' && explanation.correlation.rule_name}
                {step === 'Incident' && explanation.origin.creation_source.replace(/_/g, ' ')}
              </Typography>
            </Paper>
          ))}
        </Box>

        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>Creation reason</Typography>
          <Typography variant="body2">{explanation.origin.creation_reason}</Typography>
          {explanation.origin.provenance_status === 'legacy_derived' && (
            <Typography variant="body2" color="warning.main" sx={{ mt: 1 }}>
              Legacy incident: derived fields are labelled and are not presented as recorded historical provenance.
            </Typography>
          )}
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 2 }}>
            <Chip label={`First seen: ${formatDateTimePKT(explanation.origin.first_seen_at)}`} />
            <Chip label={`Last seen: ${formatDateTimePKT(explanation.origin.last_seen_at)}`} />
            <StatusChip label={`${explanation.correlation.score.toFixed(0)}% correlation`} color="info" />
          </Stack>
        </Box>

        <Divider />

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 3 }}>
          <Box>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>Primary and correlated alerts</Typography>
            {primary ? (
              <Stack spacing={1}>
                <Button component={RouterLink} to={`/alerts/${primary.id}`} variant="outlined" sx={{ justifyContent: 'flex-start' }}>
                  Primary: {primary.detection_rule_name || primary.id}
                </Button>
                <Typography variant="body2" color="text.secondary">{primary.why_matched || primary.attachment_reason}</Typography>
                {explanation.correlated_alerts.slice(0, 5).map((alert) => (
                  <Button key={alert.id} component={RouterLink} to={`/alerts/${alert.id}`} variant="text" sx={{ justifyContent: 'flex-start' }}>
                    Alert {alert.sequence_order}: {alert.detection_rule_name || alert.id}
                  </Button>
                ))}
              </Stack>
            ) : (
              <Typography variant="body2" color="text.secondary">No primary alert is available.</Typography>
            )}
          </Box>

          <Box>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>Correlation and risk</Typography>
            <Stack spacing={1}>
              {explanation.correlation.reasons.length > 0 ? explanation.correlation.reasons.map((reason) => (
                <Typography key={reason} variant="body2">{reason}</Typography>
              )) : <Typography variant="body2" color="text.secondary">No additional correlation condition was required.</Typography>}
              {riskFactors.map(([factor, value]) => (
                <Box key={factor} sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
                  <Typography variant="body2" color="text.secondary">{factor.replace(/_/g, ' ')}</Typography>
                  <Typography variant="body2">{Number(value) > 0 ? '+' : ''}{String(value)}</Typography>
                </Box>
              ))}
              {explanation.severity_reason && <Typography variant="body2">{explanation.severity_reason}</Typography>}
            </Stack>
          </Box>
        </Box>

        <Divider />

        <Box>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>Affected entities and evidence</Typography>
          {topEntities.length > 0 ? (
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
              {topEntities.map((entity) => {
                const path = entity.source_event_id ? `/events/${entity.source_event_id}` : entity.source_alert_id ? `/alerts/${entity.source_alert_id}` : null
                const chip = <Chip key={entity.id} label={`${entity.type.replace(/_/g, ' ')}: ${entity.value}`} clickable={Boolean(path)} />
                return path ? <Box key={entity.id} component={RouterLink} to={path} sx={{ textDecoration: 'none' }}>{chip}</Box> : chip
              })}
              {explanation.ioc_summary.map((ioc) => (
                <Box key={ioc.id} component={RouterLink} to={`/threat-intel/${ioc.id}`} sx={{ textDecoration: 'none' }}>
                  <Chip label={`IOC: ${ioc.value}`} clickable color={ioc.malicious_reports > 0 ? 'error' : 'default'} />
                </Box>
              ))}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">No structured entities were found in the linked evidence.</Typography>
          )}
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 2 }}>
            {explanation.evidence_summary.references.slice(0, 12).map((reference) => {
              return reference.available !== false && reference.navigation_path ? (
                <Button key={`${reference.type}-${reference.id}`} component={RouterLink} to={reference.navigation_path} size="small" variant="text">
                  {reference.type}: {reference.label}
                </Button>
              ) : (
                <Chip
                  key={`${reference.type}-${reference.id}`}
                  label={`${reference.type}: ${reference.label}`}
                  size="small"
                  title={reference.unavailable_reason || 'No safe navigation target is available.'}
                />
              )
            })}
          </Stack>
        </Box>

        {explanation.limitations.length > 0 && (
          <Box>
            <Typography variant="subtitle2" color="warning.main">Evidence limitations</Typography>
            {explanation.limitations.map((item) => <Typography key={item} variant="body2" color="text.secondary">{item}</Typography>)}
          </Box>
        )}
      </Stack>
    </SectionCard>
  )
}

export default IncidentOriginPanel
