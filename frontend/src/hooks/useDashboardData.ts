import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Incident,
  IncidentStats,
  SecurityEvent,
  getAlerts,
  getEvents,
  getEventsTodayStats,
  getIncidentStats,
  getIncidents,
  getIOCStats,
  getDetectionRules,
  getLogSources,
  getCollectors,
  DetectionRule,
  LogSource,
  Collector,
} from '../services/api'
import { websocketService } from '../services/api/websocket'

export interface DashboardMetric {
  title: string
  value: number
  trend: string
  severity: 'info' | 'success' | 'warning' | 'error'
}

export interface DistributionItem {
  label: string
  value: number
  color: string
}

export interface TimelinePoint {
  label: string
  value: number
}

export interface DashboardData {
  metrics: {
    openIncidents: DashboardMetric
    totalAlerts: DashboardMetric
    highRiskIncidents: DashboardMetric
    activeIOCs: DashboardMetric
    detectionCount: DashboardMetric
    connectedSources: DashboardMetric
    collectorsOnline: DashboardMetric
    eventsToday: DashboardMetric
  }
  incidentStats: IncidentStats | null
  severityDistribution: DistributionItem[]
  alertTimeline: TimelinePoint[]
  riskOverview: DistributionItem[]
  mitreOverview: DistributionItem[]
  recentEvents: SecurityEvent[]
  recentIncidents: Incident[]
  partialErrors: string[]
}

const severityPalette: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#38bdf8',
}

const riskPalette = ['#38bdf8', '#22c55e', '#f59e0b', '#ef4444']

const buildTimeline = (alerts: Alert[]): TimelinePoint[] => {
  const buckets = new Map<string, number>()

  alerts.slice(0, 42).forEach((alert) => {
    const dayKey = new Date(alert.created_at).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    })
    buckets.set(dayKey, (buckets.get(dayKey) || 0) + 1)
  })

  return Array.from(buckets.entries())
    .slice(0, 7)
    .map(([label, value]) => ({ label, value }))
}

const buildRiskOverview = (incidents: Incident[]): DistributionItem[] => {
  const bands = [
    { label: 'Low 0-39', min: 0, max: 39 },
    { label: 'Guarded 40-69', min: 40, max: 69 },
    { label: 'Elevated 70-84', min: 70, max: 84 },
    { label: 'Critical 85-100', min: 85, max: 100 },
  ]

  return bands.map((band, index) => ({
    label: band.label,
    value: incidents.filter((incident) => incident.risk_score >= band.min && incident.risk_score <= band.max).length,
    color: riskPalette[index],
  }))
}

const buildMitreOverview = (incidents: Incident[]): DistributionItem[] => {
  const counts = new Map<string, number>()

  incidents.forEach((incident) => {
    const attackTechnique = incident.attack_technique
    if (!attackTechnique) return

    const techniqueId = attackTechnique.technique_id || 'Unknown'
    const techniqueName = attackTechnique.technique_name || 'Technique'
    const key = `${techniqueId} ${techniqueName}`
    counts.set(key, (counts.get(key) || 0) + 1)
  })

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5)
    .map(([label, value], index) => ({
      label,
      value,
      color: riskPalette[index % riskPalette.length],
    }))
}

const emptyIncidentStats: IncidentStats = {
  total_incidents: 0,
  critical_incidents: 0,
  average_risk_score: 0,
  active_investigations: 0,
  average_resolution_time_hours: 0,
  mean_time_to_detect_hours: 0,
  mean_time_to_respond_hours: 0,
  open_incidents_by_severity: {},
  top_alert_sources: [],
  analyst_activity: [],
}

type LoadKey =
  | 'events'
  | 'eventsTodayStats'
  | 'recentAlerts'
  | 'totalAlerts'
  | 'incidentStats'
  | 'recentIncidents'
  | 'openIncidents'
  | 'iocStats'
  | 'detectionRules'
  | 'logSources'
  | 'collectors'

const loadLabels: Record<LoadKey, string> = {
  events: 'recent events',
  eventsTodayStats: 'events ingested today',
  recentAlerts: 'alert timeline',
  totalAlerts: 'alert total',
  incidentStats: 'incident statistics',
  recentIncidents: 'recent incidents',
  openIncidents: 'open incidents',
  iocStats: 'IOC statistics',
  detectionRules: 'detection rules',
  logSources: 'log sources',
  collectors: 'collectors',
}

export const useDashboardData = () => {
  const [data, setData] = useState<DashboardData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const liveRefreshTimer = useRef<number | null>(null)
  const dataRef = useRef<DashboardData | null>(null)

  const loadDashboardData = useCallback(async (showLoading: boolean = false) => {
    try {
      if (showLoading) {
        setLoading(true)
      }
      setError('')

      const loaders = {
        events: getEvents({ sort_by: 'created_at', sort_order: 'desc', limit: 100 }),
        eventsTodayStats: getEventsTodayStats(),
        recentAlerts: getAlerts(1, 42),
        totalAlerts: getAlerts(1, 100),
        incidentStats: getIncidentStats(),
        recentIncidents: getIncidents({
          page: 1,
          page_size: 8,
          sort_by: 'updated_at',
          sort_order: 'desc',
        }),
        openIncidents: getIncidents({
          page: 1,
          page_size: 100,
          status: 'open',
        }),
        iocStats: getIOCStats(),
        detectionRules: getDetectionRules(),
        logSources: getLogSources(),
        collectors: getCollectors(),
      }

      const loadResults = await Promise.allSettled(Object.values(loaders))
      const keys = Object.keys(loaders) as LoadKey[]
      const partialErrors: string[] = []
      const result = <T,>(key: LoadKey, fallback: T): T => {
        const index = keys.indexOf(key)
        const settled = loadResults[index]
        if (settled.status === 'fulfilled') {
          return settled.value as T
        }
        partialErrors.push(loadLabels[key])
        console.warn(`Dashboard widget failed: ${loadLabels[key]}`, settled.reason)
        return fallback
      }

      const previous = dataRef.current
      const events = result<SecurityEvent[]>('events', previous?.recentEvents ?? [])
      const eventsTodayStats = result<{ count: number }>('eventsTodayStats', {
        count: previous?.metrics.eventsToday.value ?? 0,
      })
      const recentAlerts = result('recentAlerts', { items: [], total: 0, page: 1, page_size: 42 })
      const totalAlerts = result('totalAlerts', {
        items: [],
        total: previous?.metrics.totalAlerts.value ?? 0,
        page: 1,
        page_size: 100,
      })
      const incidentStats = result<IncidentStats>('incidentStats', previous?.incidentStats ?? emptyIncidentStats)
      const recentIncidentsResponse = result('recentIncidents', {
        items: previous?.recentIncidents ?? [],
        total: previous?.recentIncidents.length ?? 0,
        page: 1,
        page_size: 8,
      })
      const openIncidentsResponse = result('openIncidents', {
        items: [],
        total: previous?.metrics.openIncidents.value ?? 0,
        page: 1,
        page_size: 100,
      })
      const iocStats = result('iocStats', {
        total_iocs: previous?.metrics.activeIOCs.value ?? 0,
        malicious_iocs: 0,
      })
      const detectionRules = result<DetectionRule[]>('detectionRules', [])
      const logSources = result<LogSource[]>('logSources', [])
      const collectors = result<Collector[]>('collectors', [])

      const recentIncidents = recentIncidentsResponse.items
      const highRiskIncidents = openIncidentsResponse.items.filter((inc: Incident) => inc.risk_score >= 70).length
      const activeIOCs = iocStats.total_iocs
      const activeLogSources = logSources.filter((s: LogSource) => s.status === 'active').length
      const collectorsOnline = collectors.filter((c: Collector) => c.status === 'online').length
      const collectorsWithoutLogSource = collectors.filter((c: Collector) => c.status === 'online' && !c.log_source_id).length
      const connectedSources = activeLogSources + collectorsWithoutLogSource
      const staleCollectors = collectors.filter((c: Collector) => c.status !== 'online').length
      
      const eventsToday = eventsTodayStats.count

      const severityDistribution = Object.entries(incidentStats.open_incidents_by_severity || {}).map(
        ([label, value]) => ({
          label,
          value: value as number,
          color: severityPalette[label] || '#94a3b8',
        })
      )

      const nextData: DashboardData = {
        metrics: {
          openIncidents: {
            title: 'Open Incidents',
            value: openIncidentsResponse.total,
            trend: `${incidentStats.active_investigations} in investigating status`,
            severity: openIncidentsResponse.total > 0 ? 'warning' : 'success',
          },
          totalAlerts: {
            title: 'Total Alerts',
            value: totalAlerts.total,
            trend: 'Total security alerts generated by detection engine',
            severity: totalAlerts.total > 0 ? 'warning' : 'success',
          },
          highRiskIncidents: {
            title: 'High Risk Incidents',
            value: highRiskIncidents,
            trend: 'Incidents with risk score >= 70',
            severity: highRiskIncidents > 0 ? 'error' : 'success',
          },
          activeIOCs: {
            title: 'Active IOCs',
            value: activeIOCs,
            trend: `${iocStats.malicious_iocs} malicious IOCs identified`,
            severity: iocStats.malicious_iocs > 0 ? 'warning' : 'success',
          },
          detectionCount: {
            title: 'Detection Rules',
            value: detectionRules.length,
            trend: `${detectionRules.filter((r: DetectionRule) => r.enabled).length} active rules`,
            severity: 'info',
          },
          connectedSources: {
            title: 'Telemetry Sources',
            value: connectedSources,
            trend: `${activeLogSources} configured sources; ${collectorsWithoutLogSource} direct collectors`,
            severity: connectedSources > 0 ? 'success' : 'warning',
          },
          collectorsOnline: {
            title: 'Collectors Online',
            value: collectorsOnline,
            trend: `${collectors.length} registered; ${staleCollectors} offline or stale`,
            severity: collectorsOnline > 0 ? 'success' : 'warning',
          },
          eventsToday: {
            title: 'Events Ingested Today',
            value: eventsToday,
            trend: `${eventsToday} total today; ${events.length} recent events loaded`,
            severity: eventsToday > 0 ? 'success' : 'info',
          },
        },
        incidentStats,
        severityDistribution,
        alertTimeline: buildTimeline(recentAlerts.items),
        riskOverview: buildRiskOverview(recentIncidents),
        mitreOverview: buildMitreOverview(recentIncidents),
        recentEvents: events.slice(0, 6),
        recentIncidents,
        partialErrors,
      }
      dataRef.current = nextData
      setData(nextData)
      setError(partialErrors.length ? `Partial dashboard data unavailable: ${partialErrors.join(', ')}.` : '')
    } catch (err) {
      setError('Failed to load dashboard telemetry shell. Existing data is preserved where available.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial data load
  useEffect(() => {
    loadDashboardData(true)
  }, [loadDashboardData]) // Now safe, no data dependency

  // Polling: full dashboard refresh every 15 seconds
  useEffect(() => {
    const intervalId = setInterval(() => {
      loadDashboardData(false)
    }, 15000) // 15 seconds

    return () => clearInterval(intervalId)
  }, [loadDashboardData])

  // Live updates schedule a quick backend refresh. The dashboard counters use
  // API values as the source of truth so they cannot drift or jump backward.
  useEffect(() => {
    const unsubscribe = websocketService.onMessage(() => {
      if (liveRefreshTimer.current !== null) {
        window.clearTimeout(liveRefreshTimer.current)
      }
      liveRefreshTimer.current = window.setTimeout(() => {
        loadDashboardData(false)
        liveRefreshTimer.current = null
      }, 500)
    })
    return () => {
      unsubscribe()
      if (liveRefreshTimer.current !== null) {
        window.clearTimeout(liveRefreshTimer.current)
      }
    }
  }, [loadDashboardData])

  return {
    data,
    loading,
    error,
    reload: loadDashboardData,
  }
}

export default useDashboardData
