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
): Promise<RuleTestResult> => {
  const response = await api.post<RuleTestResult>(
    `/api/v1/detection-rules/${ruleId}/test`,
    { event }
  )
  return response.data
}

export interface RuleTestFieldResult {
  field: string
  expression: string
  resolved_from?: string | null
  actual?: unknown
  expected?: unknown
  matched: boolean
}

export interface RuleTestResult {
  matched: boolean
  details: string
  explanation: {
    matched: boolean
    summary: string
    logsource: {
      matched: boolean
      summary: string
      checks: Array<{
        field: string
        expected: unknown
        actual?: unknown
        source?: string | null
        matched: boolean
      }>
    }
    selections: Array<{
      name: string
      matched: boolean
      fields: RuleTestFieldResult[]
    }>
    condition: {
      expression?: string
      matched: boolean
      details: string
    }
  }
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
