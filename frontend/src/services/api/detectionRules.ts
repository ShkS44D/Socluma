import api from './client'
import {
  DetectionRule,
  DetectionRuleCreate,
  DetectionRuleUpdate,
  DetectionRuleVersion,
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

export const getDetectionRuleVersions = async (ruleId: string): Promise<DetectionRuleVersion[]> => {
  const response = await api.get<DetectionRuleVersion[]>(
    `/api/v1/detection-engineering/rules/${ruleId}/versions`
  )
  return response.data
}

export const transitionDetectionVersion = async (
  versionId: string,
  target: string,
  comment?: string,
  reviewerId?: string
): Promise<DetectionRuleVersion> => {
  const response = await api.post<DetectionRuleVersion>(
    `/api/v1/detection-engineering/versions/${versionId}/transition`,
    { target, comment, reviewer_id: reviewerId }
  )
  return response.data
}

export const getDetectionAnalytics = async (): Promise<{ rules: Array<Record<string, any>>; missing_feedback_behavior: string }> => {
  const response = await api.get('/api/v1/detection-engineering/analytics')
  return response.data
}

export const getMitreDetectionCoverage = async (): Promise<{ coverage: Array<Record<string, any>>; limitations: string }> => {
  const response = await api.get('/api/v1/detection-engineering/mitre-coverage')
  return response.data
}

export const getDetectionExceptions = async (): Promise<Array<Record<string, any>>> => {
  const response = await api.get('/api/v1/detection-engineering/exceptions')
  return response.data
}

export const getDetectionMaintenanceWindows = async (): Promise<Array<Record<string, any>>> => {
  const response = await api.get('/api/v1/detection-engineering/maintenance-windows')
  return response.data
}

export const getDetectionContentPacks = async (): Promise<Array<Record<string, any>>> => {
  const response = await api.get('/api/v1/detection-engineering/content-packs')
  return response.data
}

export const importDetectionContentPack = async (
  manifest: Record<string, any>,
  dryRun = true
): Promise<Record<string, any>> => {
  const response = await api.post('/api/v1/detection-engineering/content-packs/import', {
    manifest,
    dry_run: dryRun,
  })
  return response.data
}
