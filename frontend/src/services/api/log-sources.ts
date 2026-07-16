import api from './client'
import type { LogSource, LogSourceCreate, LogSourceUpdate } from './types'

export const getLogSources = async (): Promise<LogSource[]> => {
  const response = await api.get<LogSource[]>('/api/v1/log-sources')
  return response.data
}

export const createLogSource = async (data: LogSourceCreate): Promise<LogSource> => {
  const response = await api.post<LogSource>('/api/v1/log-sources', data)
  return response.data
}

export const updateLogSource = async (id: string, data: LogSourceUpdate): Promise<LogSource> => {
  const response = await api.patch<LogSource>(`/api/v1/log-sources/${id}`, data)
  return response.data
}
