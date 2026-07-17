import api from './client'
import {
  AIAnalysisResponse,
  FeedbackCreate,
  FeedbackResponse,
  FeedbackStats,
  Incident,
  IncidentDetail,
  IncidentExplanation,
  IncidentListResponse,
  IncidentPriority,
  IncidentStats,
  MitreMatrixResponse,
  IncidentStatus,
  InvestigationNote,
  TimelineItem,
} from './types'

export interface GetIncidentsParams {
  page?: number
  page_size?: number
  severity?: string
  status?: IncidentStatus
  priority?: IncidentPriority
  assigned_to?: string
  search?: string
  created_from?: string
  created_to?: string
  sort_by?: 'created_at' | 'updated_at' | 'risk_score' | 'severity' | 'priority'
  sort_order?: 'asc' | 'desc'
}

export const getIncidents = async (
  pageOrParams: number | GetIncidentsParams = 1,
  page_size: number = 20,
  severity?: string,
  status?: IncidentStatus
): Promise<IncidentListResponse> => {
  const params =
    typeof pageOrParams === 'number'
      ? { page: pageOrParams, page_size, severity, status }
      : pageOrParams

  const response = await api.get<IncidentListResponse>('/api/v1/incidents', { params })
  return response.data
}

export const getIncident = async (
  incidentId: string,
  options: { alert_page?: number; alert_page_size?: number; signal?: AbortSignal } = {}
): Promise<IncidentDetail> => {
  const { signal, ...params } = options
  const response = await api.get<IncidentDetail>(`/api/v1/incidents/${incidentId}`, { params, signal })
  return response.data
}

export const getIncidentExplanation = async (incidentId: string, signal?: AbortSignal): Promise<IncidentExplanation> => {
  const response = await api.get<IncidentExplanation>(`/api/v1/incidents/${incidentId}/explanation`, { signal })
  return response.data
}

export const getIncidentStats = async (): Promise<IncidentStats> => {
  const response = await api.get<IncidentStats>('/api/v1/incidents/stats')
  return response.data
}

export const getMitreMatrix = async (params: Record<string, string | undefined> = {}): Promise<MitreMatrixResponse> => {
  const response = await api.get<MitreMatrixResponse>('/api/v1/incidents/mitre-matrix', { params })
  return response.data
}

export const updateIncidentStatus = async (
  incidentId: string,
  status: IncidentStatus
): Promise<Incident> => {
  const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/status`, { status })
  return response.data
}

export const assignIncident = async (
  incidentId: string,
  userId: string
): Promise<Incident> => {
  const response = await api.post<Incident>(`/api/v1/incidents/${incidentId}/assign`, { user_id: userId })
  return response.data
}

export const analyzeIncident = async (incidentId: string): Promise<AIAnalysisResponse> => {
  const response = await api.post<AIAnalysisResponse>(`/api/v1/incidents/${incidentId}/analyze`)
  return response.data
}

export const getAssignedIncidents = async (): Promise<Incident[]> => {
  const response = await api.get<Incident[]>('/api/v1/incidents/assigned')
  return response.data
}

export const createIncidentNote = async (
  incidentId: string,
  content: string
): Promise<InvestigationNote> => {
  const response = await api.post<InvestigationNote>(`/api/v1/incidents/${incidentId}/notes`, { content })
  return response.data
}

export const getIncidentNotes = async (incidentId: string): Promise<InvestigationNote[]> => {
  const response = await api.get<InvestigationNote[]>(`/api/v1/incidents/${incidentId}/notes`)
  return response.data
}

export const getIncidentTimeline = async (incidentId: string, signal?: AbortSignal): Promise<TimelineItem[]> => {
  const response = await api.get<TimelineItem[]>(`/api/v1/incidents/${incidentId}/timeline`, { signal })
  return response.data
}

export const createFeedback = async (
  incidentId: string,
  feedbackData: FeedbackCreate
): Promise<FeedbackResponse> => {
  const response = await api.post<FeedbackResponse>(`/api/v1/incidents/${incidentId}/feedback`, feedbackData)
  return response.data
}

export const getIncidentFeedback = async (incidentId: string): Promise<FeedbackResponse[]> => {
  const response = await api.get<FeedbackResponse[]>(`/api/v1/incidents/${incidentId}/feedback`)
  return response.data
}

export const getFeedbackStats = async (): Promise<FeedbackStats> => {
  const response = await api.get<FeedbackStats>('/api/v1/incidents/feedback/stats')
  return response.data
}
