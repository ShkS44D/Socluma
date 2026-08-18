import api from './client'
import type { DataSource, DeadLetterItem, EnrollmentTokenResponse, IngestionMetrics } from './types'

export const getDataSources = async (): Promise<DataSource[]> =>
  (await api.get<DataSource[]>('/api/v1/telemetry/sources')).data

export const createDataSource = async (data: {
  source_key: string; name: string; source_type: string; parser_name: string; transport?: string
}): Promise<DataSource> => (await api.post<DataSource>('/api/v1/telemetry/sources', data)).data

export const getIngestionMetrics = async (): Promise<IngestionMetrics> =>
  (await api.get<IngestionMetrics>('/api/v1/telemetry/metrics')).data

export const getDeadLetters = async (): Promise<DeadLetterItem[]> =>
  (await api.get<DeadLetterItem[]>('/api/v1/telemetry/dead-letter')).data

export const replayDeadLetter = async (id: string): Promise<void> => {
  await api.post(`/api/v1/telemetry/dead-letter/${id}/replay`)
}

export const createEnrollmentToken = async (data: {
  name: string; platform?: string; expires_minutes?: number
}): Promise<EnrollmentTokenResponse> =>
  (await api.post<EnrollmentTokenResponse>('/api/v1/collectors/enrollment-tokens', data)).data

export const rotateCollectorCredential = async (id: string) =>
  (await api.post(`/api/v1/collectors/${id}/credentials/rotate`)).data

export const getCollectorGroups = async (): Promise<Array<{ id: string; name: string; description?: string }>> =>
  (await api.get('/api/v1/telemetry/collector-groups')).data

export const getCollectorPolicies = async (): Promise<Array<{ id: string; name: string; active_version?: number }>> =>
  (await api.get('/api/v1/telemetry/collector-policies')).data

export const importTelemetry = async (file: File, formatName: 'json' | 'jsonl' | 'csv') => {
  const body = new FormData()
  body.append('file', file)
  body.append('format_name', formatName)
  return (await api.post('/api/v1/telemetry/imports', body, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })).data
}
