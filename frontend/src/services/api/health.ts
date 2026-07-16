import api from './client'
import { HealthCheck } from './types'

export const healthCheck = async (): Promise<HealthCheck> => {
  const response = await api.get<HealthCheck>('/health')
  return response.data
}
