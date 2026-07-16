import api from './client'
import type {
  IOC,
  IOCListResponse,
  IOCCreate,
  IOCUpdate,
  IOCStats,
  IndicatorType,
} from './types'

export const getIOCs = async (
  params?: {
    ioc_type?: IndicatorType
    search?: string
    page?: number
    page_size?: number
  }
): Promise<IOCListResponse> => {
  const { data } = await api.get('/api/v1/iocs', { params })
  return data
}

export const getIOCStats = async (): Promise<IOCStats> => {
  const { data } = await api.get('/api/v1/iocs/stats')
  return data
}

export const getIOC = async (iocId: string): Promise<IOC> => {
  const { data } = await api.get(`/api/v1/iocs/${iocId}`)
  return data
}

export const getIncidentIOCs = async (incidentId: string, signal?: AbortSignal): Promise<IOC[]> => {
  const { data } = await api.get(`/api/v1/incidents/${incidentId}/iocs`, { signal })
  return data
}

export const createIOC = async (iocData: IOCCreate): Promise<IOC> => {
  const { data } = await api.post('/api/v1/iocs', iocData)
  return data
}

export const updateIOC = async (
  iocId: string,
  iocData: IOCUpdate
): Promise<IOC> => {
  const { data } = await api.patch(`/api/v1/iocs/${iocId}`, iocData)
  return data
}

export const deleteIOC = async (iocId: string): Promise<void> => {
  await api.delete(`/api/v1/iocs/${iocId}`)
}

export const enrichIOC = async (
  iocId: string
): Promise<Array<{ provider: string; result: Record<string, any> }>> => {
  const { data } = await api.post(`/api/v1/iocs/${iocId}/enrich`)
  return data
}

export const enrichIncidentIOC = async (
  incidentId: string,
  iocId: string
): Promise<Array<{ provider: string; result: Record<string, any> }>> => {
  const { data } = await api.post(`/api/v1/incidents/${incidentId}/iocs/${iocId}/enrich`)
  return data
}
