import api from './client'
import {
  DetectionRule,
  DetectionRuleCreate,
  DetectionRuleUpdate,
  Severity
} from './types'

export type RuleType = 'sigma' | 'custom'

export interface GetDetectionRulesParams {
  page?: number
  page_size?: number
  severity?: Severity
  enabled?: boolean
  type?: RuleType
  search?: string
}

export const getDetectionRules = async (
  params: GetDetectionRulesParams = {}
): Promise<DetectionRule[]> => {
  const response = await api.get<DetectionRule[]>('/api/v1/detection-rules', { params })
  return response.data
}

export const getDetectionRule = async (ruleId: string): Promise<DetectionRule> => {
  const response = await api.get<DetectionRule>(`/api/v1/detection-rules/${ruleId}`)
  return response.data
}

export const createDetectionRule = async (
  data: DetectionRuleCreate
): Promise<DetectionRule> => {
  const response = await api.post<DetectionRule>('/api/v1/detection-rules', data)
  return response.data
}

export const importSigmaRule = async (
  content: string,
  enabled: boolean = true
): Promise<DetectionRule> => {
  const response = await api.post<DetectionRule>('/api/v1/detection-rules/import/sigma', {
    content,
    enabled,
  })
  return response.data
}

export const exportDetectionRule = async (ruleId: string): Promise<string> => {
  const response = await api.get<string>(`/api/v1/detection-rules/${ruleId}/export`, {
    responseType: 'text',
  })
  return response.data
}

export const testDetectionRule = async (
  ruleId: string,
  event: Record<string, any>
): Promise<{ matched: boolean; details: string }> => {
  const response = await api.post<{ matched: boolean; details: string }>(
    `/api/v1/detection-rules/${ruleId}/test`,
    { event }
  )
  return response.data
}

export const updateDetectionRule = async (
  ruleId: string,
  data: DetectionRuleUpdate
): Promise<DetectionRule> => {
  const response = await api.patch<DetectionRule>(`/api/v1/detection-rules/${ruleId}`, data)
  return response.data
}

export const deleteDetectionRule = async (ruleId: string): Promise<void> => {
  await api.delete(`/api/v1/detection-rules/${ruleId}`)
}
