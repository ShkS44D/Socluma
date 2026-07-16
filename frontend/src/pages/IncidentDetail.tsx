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
import { useAuthStore } from '../store'
import { canAccess, PERMISSIONS } from '../utils/permissions'
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
  const user = useAuthStore((state) => state.user)
  const canAnalyze = canAccess(user?.role ?? null, PERMISSIONS.analyzeIncidents as { requiredRole: import('../utils/permissions').UserRole })

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
                                {enrichment.raw_response && (
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
                                    <pre>{JSON.stringify(enrichment.raw_response, null, 2)}</pre>
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
