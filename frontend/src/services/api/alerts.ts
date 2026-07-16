import api from './client'
import { Alert, AlertCreate, AlertWithRule, Severity, AlertStatus, Incident, IOC } from './types'

export const getAlerts = async (
  page: number = 1,
  page_size: number = 20,
  severity?: Severity,
  status?: AlertStatus
): Promise<{ items: AlertWithRule[], total: number, page: number, page_size: number }> => {
  const params: Record<string, string | number> = { page, page_size }
  if (severity) params.severity = severity
  if (status) params.status = status

  const response = await api.get<{ items: AlertWithRule[], total: number, page: number, page_size: number }>('/api/v1/alerts', { params })
  return response.data
}

export const getAlert = async (alertId: string): Promise<AlertWithRule> => {
  const response = await api.get<AlertWithRule>(`/api/v1/alerts/${alertId}`)
  return response.data
}

export const createAlert = async (data: AlertCreate): Promise<Alert> => {
  const response = await api.post<Alert>('/api/v1/alerts', data)
  return response.data
}

export const updateAlertStatus = async (
  alertId: string,
  status: AlertStatus
): Promise<Alert> => {
  const response = await api.post<Alert>(`/api/v1/alerts/${alertId}/status`, { status })
  return response.data
}

export const createIncidentFromAlert = async (alertId: string): Promise<Incident> => {
  const response = await api.post<Incident>(`/api/v1/alerts/${alertId}/create-incident`)
  return response.data
}

export const getAlertIncident = async (alertId: string): Promise<Incident | null> => {
  const response = await api.get<Incident | null>(`/api/v1/alerts/${alertId}/incident`)
  return response.data
}

export const getAlertIOCs = async (alertId: string): Promise<IOC[]> => {
  const response = await api.get<IOC[]>(`/api/v1/alerts/${alertId}/iocs`)
  return response.data
}
