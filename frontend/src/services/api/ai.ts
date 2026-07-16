import api from './client'
import {
  AIAlertExplanation,
  AIChatResponse,
  AIConversationDetail,
  AIConversationSummary,
  AIDetectionSuggestions,
  AIIncidentSummary,
  AIIocAnalysis,
  AIPlaybookSuggestions,
  AIReportResponse,
  AITimelineResponse,
} from './types'

export const generateIncidentSummary = async (incidentId: string): Promise<AIIncidentSummary> => {
  const response = await api.post<AIIncidentSummary>(`/api/v1/ai/incident/${incidentId}/summary`)
  return response.data
}

export const listIncidentConversations = async (incidentId: string): Promise<AIConversationSummary[]> => {
  const response = await api.get<AIConversationSummary[]>(`/api/v1/ai/incident/${incidentId}/conversations`)
  return response.data
}

export const getIncidentConversation = async (
  incidentId: string,
  conversationId: string
): Promise<AIConversationDetail> => {
  const response = await api.get<AIConversationDetail>(
    `/api/v1/ai/incident/${incidentId}/conversations/${conversationId}`
  )
  return response.data
}

export const chatWithIncidentCopilot = async (
  incidentId: string,
  message: string,
  conversationId?: string | null,
  requestId: string = crypto.randomUUID()
): Promise<AIChatResponse> => {
  const response = await api.post<AIChatResponse>(`/api/v1/ai/incident/${incidentId}/chat`, {
    message,
    conversation_id: conversationId,
  }, { headers: { 'X-Request-ID': requestId } })
  return response.data
}

export const generateInvestigationTimeline = async (incidentId: string): Promise<AITimelineResponse> => {
  const response = await api.post<AITimelineResponse>(`/api/v1/ai/incident/${incidentId}/timeline`)
  return response.data
}

export const generateIncidentReport = async (incidentId: string): Promise<AIReportResponse> => {
  const response = await api.post<AIReportResponse>(`/api/v1/ai/incident/${incidentId}/report`)
  return response.data
}

export const explainAlert = async (alertId: string): Promise<AIAlertExplanation> => {
  const response = await api.post<AIAlertExplanation>(`/api/v1/ai/alert/${alertId}/explain`)
  return response.data
}

export const analyzeIOC = async (iocId: string): Promise<AIIocAnalysis> => {
  const response = await api.post<AIIocAnalysis>(`/api/v1/ai/ioc/${iocId}/analyze`)
  return response.data
}

export const suggestDetectionRules = async (): Promise<AIDetectionSuggestions> => {
  const response = await api.post<AIDetectionSuggestions>('/api/v1/ai/detections/suggest')
  return response.data
}

export const suggestPlaybooks = async (incidentId?: string): Promise<AIPlaybookSuggestions> => {
  const response = await api.post<AIPlaybookSuggestions>('/api/v1/ai/playbooks/suggest', null, {
    params: incidentId ? { incident_id: incidentId } : undefined,
  })
  return response.data
}
