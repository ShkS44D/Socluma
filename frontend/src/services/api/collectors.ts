import api from './client'
import type { Collector, CollectorCreate, CollectorRegistrationResponse } from './types'

export const getCollectors = async (): Promise<Collector[]> => {
  const response = await api.get<Collector[]>('/api/v1/collectors')
  return response.data
}

export const registerCollector = async (data: CollectorCreate): Promise<CollectorRegistrationResponse> => {
  const response = await api.post<CollectorRegistrationResponse>('/api/v1/collectors/register', data)
  return response.data
}

export const sendCollectorHeartbeat = async (id: string): Promise<Collector> => {
  const response = await api.post<Collector>(`/api/v1/collectors/${id}/heartbeat`)
  return response.data
}
