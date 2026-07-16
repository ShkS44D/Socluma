import api from './client'
import { EventAnalysisResponse, IngestionResponse, SecurityEvent } from './types'

export interface EventCreate {
  source: string
  event_type: string
  raw_event: Record<string, any>
  normalized_event?: Record<string, any>
  severity?: string
  timestamp?: string
}

export const getEvents = async (params?: {
  event_type?: string
  severity?: string
  limit?: number
  offset?: number
  sort_by?: 'timestamp' | 'created_at' | 'severity' | 'event_type'
  sort_order?: 'asc' | 'desc'
}): Promise<SecurityEvent[]> => {
  const response = await api.get<SecurityEvent[]>('/api/v1/events', { params })
  return response.data
}

export const getEventsTodayStats = async (): Promise<{ count: number }> => {
  const response = await api.get<{ count: number }>('/api/v1/events/stats/today', {
    params: { timezone_offset_minutes: new Date().getTimezoneOffset() },
  })
  return response.data
}

export const getEvent = async (eventId: string): Promise<SecurityEvent> => {
  const response = await api.get<SecurityEvent>(`/api/v1/events/${eventId}`)
  return response.data
}

export const ingestEvent = async (data: EventCreate): Promise<IngestionResponse> => {
  const response = await api.post<IngestionResponse>('/api/v1/events/ingest', data)
  return response.data
}

export const createEvent = ingestEvent

export const analyzeEvent = async (eventId: string): Promise<EventAnalysisResponse> => {
  const response = await api.post<EventAnalysisResponse>(`/api/v1/events/${eventId}/analyze`)
  return response.data
}
