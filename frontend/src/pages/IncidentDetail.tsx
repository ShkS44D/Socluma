import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Stack,
  Typography,
  Button,
  Chip,
  Paper,
} from '@mui/material'
import {
  getIncident,
  getIncidentTimeline,
  getIncidentExplanation,
  analyzeIncident,
  Incident,
  IncidentDetail as IncidentDetailType,
  IncidentRelatedAlert,
  IncidentExplanation,
  TimelineItem,
  ThreatIntelResult,
  IOC,
  getIncidentIOCs,
  enrichIncidentIOC,
} from '../services/api'
import { usePermissionStore } from '../store'
import toast from 'react-hot-toast'
import {
  IncidentHeader,
  IncidentTabs,
  IncidentTimeline,
  EvidencePanel,
  RelatedAlertsTable,
  ResponseActions,
  AIAnalysisPanel,
  IncidentOriginPanel,
} from '../components/incidents'
import { PageHeader, SectionCard, LoadingState, ErrorState, StatusChip } from '../components/ui'

const IncidentDetail: React.FC = () => {
  const { incidentId } = useParams<{ incidentId: string }>()
  const navigate = useNavigate()
  const id = incidentId
  const [incident, setIncident] = useState<IncidentDetailType | null>(null)
  const [timeline, setTimeline] = useState<TimelineItem[]>([])
  const [iocs, setIocs] = useState<IOC[]>([])
  const [explanation, setExplanation] = useState<IncidentExplanation | null>(null)
  const [explanationError, setExplanationError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState(0)
  const [loading, setLoading] = useState(true)
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [timelineLoaded, setTimelineLoaded] = useState(false)
  const [timelineError, setTimelineError] = useState<string | null>(null)
  const [iocsLoading, setIocsLoading] = useState(false)
  const [iocsLoaded, setIocsLoaded] = useState(false)
  const [iocsError, setIocsError] = useState<string | null>(null)
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const can = usePermissionStore((state) => state.can)
  const canAnalyze = can('incidents.update') && can('triage_ai.use')

  const evidence: ThreatIntelResult[] = incident?.threat_intel_results || []
  const relatedAlerts: IncidentRelatedAlert[] = incident?.related_alerts || []

  const getReputation = (ioc: IOC): string => {
    const maliciousEnrichment = ioc.enrichments?.find((e) => e.malicious_count > 0)
    if (maliciousEnrichment) return 'Malicious'
    const cleanEnrichment = ioc.enrichments?.find((e) => e.reputation === 'clean')
    if (cleanEnrichment) return 'Clean'
    return 'Unknown'
  }

  const fetchData = async (signal?: AbortSignal) => {
    if (!id) return
    try {
      setLoading(true)
      setError(null)
      const incidentData = await getIncident(id, { alert_page_size: 20, signal })
      setIncident(incidentData)
    } catch (err) {
      if (signal?.aborted) return
      setError('Failed to load incident details.')
      console.error(err)
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }

  const fetchExplanation = async (signal?: AbortSignal) => {
    if (!id) return
    try {
      setExplanation(await getIncidentExplanation(id, signal))
      setExplanationError(null)
    } catch {
      if (signal?.aborted) return
      setExplanation(null)
      setExplanationError('The explanation service is temporarily unavailable. Core incident data remains available.')
    }
  }

  const handleEnrichIOC = async (iocId: string) => {
    if (!id) return
    try {
      await enrichIncidentIOC(id, iocId)
      setIocs(await getIncidentIOCs(id))
    } catch (err) {
      console.error('Failed to enrich IOC:', err)
    }
  }

  const handleAnalyze = async () => {
    if (!id) return
    try {
      setAnalyzing(true)
      const analysis = await analyzeIncident(id)
      setIncident((prev) =>
        prev
          ? {
              ...prev,
              ai_summary: analysis.summary,
              why_suspicious: analysis.why_suspicious,
              attack_technique: analysis.attack_technique,
              recommended_actions: analysis.recommended_actions,
              threat_intel_results: analysis.threat_intel_results,
              ai_analyzed_at: new Date().toISOString(),
            }
          : prev
      )
      toast.success('AI analysis complete')
    } catch (err) {
      console.error('Failed to run AI analysis:', err)
      toast.error('Failed to generate AI analysis')
    } finally {
      setAnalyzing(false)
    }
  }

  useEffect(() => {
    const controller = new AbortController()
    setTimeline([])
    setTimelineLoaded(false)
    setIocs([])
    setIocsLoaded(false)
    fetchData(controller.signal)
    fetchExplanation(controller.signal)
    return () => controller.abort()
  }, [id])

  useEffect(() => {
    if (activeTab !== 1 || timelineLoaded || !id) return
    const controller = new AbortController()
    setTimelineLoading(true)
    setTimelineError(null)
    getIncidentTimeline(id, controller.signal)
      .then((items) => {
        setTimeline(items)
        setTimelineLoaded(true)
      })
      .catch(() => {
        if (!controller.signal.aborted) setTimelineError('Timeline is temporarily unavailable.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setTimelineLoading(false)
      })
    return () => controller.abort()
  }, [activeTab, id, timelineLoaded])

  useEffect(() => {
    if (activeTab !== 4 || iocsLoaded || !id) return
    const controller = new AbortController()
    setIocsLoading(true)
    setIocsError(null)
    getIncidentIOCs(id, controller.signal)
      .then((items) => {
        setIocs(items)
        setIocsLoaded(true)
      })
      .catch(() => {
        if (!controller.signal.aborted) setIocsError('IOC data is temporarily unavailable.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setIocsLoading(false)
      })
    return () => controller.abort()
  }, [activeTab, id, iocsLoaded])

  const loadMoreAlerts = async () => {
    if (!id || !incident?.related_alert_has_more || alertsLoading) return
    try {
      setAlertsLoading(true)
      const next = await getIncident(id, {
        alert_page: incident.related_alert_page + 1,
        alert_page_size: incident.related_alert_page_size,
      })
      setIncident({
        ...incident,
        related_alerts: [...incident.related_alerts, ...next.related_alerts],
        related_alert_page: next.related_alert_page,
        related_alert_has_more: next.related_alert_has_more,
      })
    } catch {
      toast.error('Failed to load additional alerts')
    } finally {
      setAlertsLoading(false)
    }
  }

  const handleStatusUpdate = (updatedIncident: Incident) => {
    if (incident) {
      setIncident({
        ...incident,
        ...updatedIncident
      })
    }
  }

  if (loading) {
    return <LoadingState title="Loading Incident Details" />
  }

  if (error || !incident) {
    return <ErrorState message={error || 'Incident not found'} onRetry={() => fetchData()} />
  }

  const incidentWithAlertCount: Incident = {
    ...incident,
    alert_count: incident.related_alert_total
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 0: // Overview
        return (
          <AIAnalysisPanel
            summary={incident.ai_summary}
            why_suspicious={incident.why_suspicious}
            aiAnalyzedAt={incident.ai_analyzed_at}
            attackTechnique={incident.attack_technique}
            recommendedActions={incident.recommended_actions}
            threatIntelResults={incident.threat_intel_results}
            analyzing={analyzing}
            canAnalyze={canAnalyze}
            onAnalyze={handleAnalyze}
          />
        )
      case 1: // Timeline
        if (timelineLoading) return <LoadingState title="Loading incident timeline" />
        if (timelineError) return <ErrorState message={timelineError} onRetry={() => setTimelineLoaded(false)} />
        return <IncidentTimeline items={timeline} />
      case 2: // Evidence
        return <EvidencePanel evidence={evidence} />
      case 3: // Related Alerts
        return (
          <Stack spacing={2}>
            <RelatedAlertsTable alerts={relatedAlerts} />
            {incident.related_alert_has_more && (
              <Button variant="outlined" disabled={alertsLoading} onClick={loadMoreAlerts}>
                {alertsLoading ? 'Loading...' : `Load more alerts (${relatedAlerts.length} of ${incident.related_alert_total})`}
              </Button>
            )}
          </Stack>
        )
      case 4: // Threat Intelligence
        if (iocsLoading) return <LoadingState title="Loading threat intelligence" />
        if (iocsError) return <ErrorState message={iocsError} onRetry={() => setIocsLoaded(false)} />
        return (
          <Stack spacing={4}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">Threat Intelligence</Typography>
            </Box>
            
            {/* Existing Threat Intel Results */}
            {evidence.length > 0 && (
              <SectionCard title="Indicator Lookups">
                <Box sx={{ p: 3 }}>
                  <EvidencePanel evidence={evidence} />
                </Box>
              </SectionCard>
            )}

            {/* IOCs */}
            <SectionCard 
              title="Indicators of Compromise (IOCs)"
              action={
                <Button variant="contained" onClick={() => navigate('/threat-intel')}>
                  Go to Threat Intel
                </Button>
              }
            >
              {iocs.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No IOCs associated with this incident.
                </Typography>
              ) : (
                <Stack spacing={3}>
                  {iocs.map((ioc) => (
                    <Paper key={ioc.id} sx={{ p: 3 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                        <Box>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
                            <StatusChip label={ioc.type} />
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
                            <Chip label={`Confidence: ${ioc.confidence_score}%`} />
                          </Box>
                          <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                            {ioc.value}
                          </Typography>
                          {ioc.description && (
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                              {ioc.description}
                            </Typography>
                          )}
                        </Box>
                        <Stack direction="row" gap={1}>
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() => navigate(`/threat-intel/${ioc.id}`)}
                          >
                            View IOC
                          </Button>
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() => handleEnrichIOC(ioc.id)}
                          >
                            Enrich
                          </Button>
                        </Stack>
                      </Box>

                      {ioc.enrichments && ioc.enrichments.length > 0 && (
                        <Box sx={{ mt: 2, borderTop: 1, borderColor: 'divider', pt: 2 }}>
                          <Typography variant="subtitle2" sx={{ mb: 2 }}>
                            Enrichment Data
                          </Typography>
                          <Stack spacing={2}>
                            {ioc.enrichments.map((enrichment, idx) => (
                              <Paper key={idx} variant="outlined" sx={{ p: 2 }}>
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                                  <Typography variant="subtitle2">
                                    {enrichment.provider.charAt(0).toUpperCase() + enrichment.provider.slice(1)}
                                  </Typography>
                                  <Box sx={{ display: 'flex', gap: 1 }}>
                                    {enrichment.reputation && (
                                      <StatusChip
                                        label={enrichment.reputation}
                                        color={
                                          enrichment.reputation === 'malicious' ||
                                          enrichment.reputation === 'Malicious'
                                            ? 'error'
                                            : enrichment.reputation === 'clean' ||
                                              enrichment.reputation === 'Clean'
                                            ? 'success'
                                            : 'default'
                                        }
                                        size="small"
                                      />
                                    )}
                                    {enrichment.malicious_count > 0 && (
                                      <Chip
                                        label={`Malicious Reports: ${enrichment.malicious_count}`}
                                        size="small"
                                        color="error"
                                      />
                                    )}
                                    {enrichment.total_reports > 0 && (
                                      <Chip
                                        label={`Total Reports: ${enrichment.total_reports}`}
                                        size="small"
                                      />
                                    )}
                                  </Box>
                                </Box>
                                {Object.keys(enrichment.safe_result || {}).length > 0 && (
                                  <Box
                                    sx={{
                                      bgcolor: 'background.paper',
                                      p: 2,
                                      borderRadius: 1,
                                      fontFamily: 'monospace',
                                      fontSize: '0.875rem',
                                      overflowX: 'auto',
                                    }}
                                  >
                                    <pre>{JSON.stringify(enrichment.safe_result, null, 2)}</pre>
                                  </Box>
                                )}
                              </Paper>
                            ))}
                          </Stack>
                        </Box>
                      )}
                    </Paper>
                  ))}
                </Stack>
              )}
            </SectionCard>
          </Stack>
        )
      case 5: // Response Actions
        return <ResponseActions incident={incidentWithAlertCount} onStatusUpdate={handleStatusUpdate} />
      default:
        return null
    }
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title={`Incident: ${incident.title}`}
        description={`Investigate and respond to security incident #${incident.id}`}
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Incidents', href: '/incidents' },
          { label: incident.id }
        ]}
      />
      <IncidentHeader incident={incidentWithAlertCount} />
      <IncidentOriginPanel
        explanation={explanation}
        error={explanationError}
        onOpenCopilot={() => navigate(`/ai/incident-copilot?incidentId=${incident.id}`)}
      />
      <SectionCard
        title="MITRE ATT&CK progression"
        action={<Button variant="outlined" onClick={() => navigate(`/mitre-matrix?incident_id=${incident.id}`)}>Open matrix</Button>}
      >
        {incident.mitre_mappings.length === 0 ? (
          <Typography color="text.secondary">No evidence-backed MITRE mappings are available for this incident.</Typography>
        ) : (
          <Stack spacing={2}>
            {incident.mitre_mappings.map((mapping) => (
              <Paper key={`${mapping.technique_id}-${mapping.mapping_source}`} variant="outlined" sx={{ p: 2 }}>
                <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1}>
                  <Box>
                    <Typography variant="overline">Stage {mapping.stage_order + 1}: {mapping.tactic}</Typography>
                    <Typography variant="subtitle1">
                      Parent technique: {mapping.parent_technique_id} {mapping.parent_technique_name}
                    </Typography>
                    <Typography variant="body2">
                      {mapping.sub_technique_id
                        ? `Sub-technique: ${mapping.sub_technique_id} ${mapping.sub_technique_name || 'Name unavailable'}`
                        : 'Sub-technique: None'}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Mapped technique ID: {mapping.technique_id}</Typography>
                  </Box>
                  <Stack direction="row" spacing={1} alignItems="flex-start">
                    <Chip size="small" label={`${mapping.confidence.toFixed(0)}% confidence`} />
                    <Chip
                      size="small"
                      color={mapping.mapping_source === 'correlated' ? 'primary' : 'default'}
                      label={mapping.mapping_source === 'correlated' ? 'Correlated evidence' : 'Historical metadata'}
                    />
                  </Stack>
                </Stack>
                <Typography variant="body2" sx={{ mt: 1 }}>
                  First seen: {mapping.first_seen_at ? new Date(mapping.first_seen_at).toLocaleString() : 'Unavailable'}
                </Typography>
                <Typography variant="body2">
                  Last seen: {mapping.last_seen_at ? new Date(mapping.last_seen_at).toLocaleString() : 'Unavailable'}
                </Typography>
                <Typography variant="subtitle2" sx={{ mt: 2 }}>Confidence reasons</Typography>
                {mapping.confidence_reasons.length
                  ? mapping.confidence_reasons.map((reason) => <Typography key={reason} variant="body2">• {reason}</Typography>)
                  : <Typography variant="body2" color="text.secondary">No confidence explanation was recorded.</Typography>}
                <Typography variant="subtitle2" sx={{ mt: 2 }}>Supporting source alerts</Typography>
                {mapping.source_alert_ids.length ? (
                  <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                    {mapping.source_alert_ids.map((alertId) => <Chip key={alertId} size="small" label={alertId} />)}
                  </Stack>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Historical legacy-derived metadata; verified supporting alert evidence was not recorded.
                  </Typography>
                )}
                <Typography variant="subtitle2" sx={{ mt: 2 }}>Stored evidence</Typography>
                {mapping.supporting_evidence.length ? (
                  <Stack spacing={1} sx={{ mt: 1 }}>
                    {mapping.supporting_evidence.map((evidence, index) => (
                      <Paper key={`${String(evidence.alert_id || index)}-${index}`} variant="outlined" sx={{ p: 1.5, bgcolor: 'background.default' }}>
                        <Typography variant="body2">Alert: {String(evidence.alert_id || 'Unavailable')}</Typography>
                        <Typography variant="caption" display="block">Event: {String(evidence.event_id || 'Unavailable')}</Typography>
                        <Typography variant="caption" display="block">Rule: {String(evidence.rule_id || 'Unavailable')}</Typography>
                        <Typography variant="caption" display="block">Observed: {evidence.observed_at ? new Date(String(evidence.observed_at)).toLocaleString() : 'Unavailable'}</Typography>
                        <Typography variant="caption" display="block">Match evidence: {String(evidence.why_matched || 'Not recorded')}</Typography>
                        {Object.entries((evidence.evidence_fields as Record<string, unknown>) || {}).map(([field, value]) => (
                          <Typography key={field} variant="caption" display="block">{field.replace(/_/g, ' ')}: {String(value)}</Typography>
                        ))}
                      </Paper>
                    ))}
                  </Stack>
                ) : (
                  <Typography variant="body2" color="text.secondary">No verified evidence fields are stored for this mapping.</Typography>
                )}
              </Paper>
            ))}
          </Stack>
        )}
      </SectionCard>
      <SectionCard title="Incident Details">
        <IncidentTabs activeTab={activeTab} setActiveTab={setActiveTab} />
        <Box sx={{ pt: 3 }}>
          {renderTabContent()}
        </Box>
      </SectionCard>
    </Stack>
  )
}

export default IncidentDetail
