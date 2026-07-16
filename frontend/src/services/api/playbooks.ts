import api from './client'
import {
  Playbook,
  PlaybookApproval,
  PlaybookCreate,
  PlaybookExecution,
  PlaybookExecutionStatus,
  PlaybookExecutionStep,
  PlaybookRunLog,
  PlaybookStatus,
  PlaybookVersion,
  PlaybookStepDefinition,
} from './types'

export const listPlaybooks = async (params?: {
  status?: PlaybookStatus
  limit?: number
  offset?: number
}): Promise<Playbook[]> => {
  const response = await api.get('/api/v1/playbooks', { params })
  return response.data
}

export const getPlaybook = async (playbookId: string): Promise<Playbook> => {
  const response = await api.get(`/api/v1/playbooks/${playbookId}`)
  return response.data
}

export const createPlaybook = async (data: PlaybookCreate): Promise<Playbook> => {
  const response = await api.post('/api/v1/playbooks', data)
  return response.data
}

export const listPlaybookVersions = async (playbookId: string): Promise<PlaybookVersion[]> => {
  const response = await api.get(`/api/v1/playbooks/${playbookId}/versions`)
  return response.data
}

export const createPlaybookVersion = async (
  playbookId: string,
  steps: PlaybookStepDefinition[],
  changelog?: string
): Promise<PlaybookVersion> => {
  const response = await api.post(`/api/v1/playbooks/${playbookId}/versions`, { steps, changelog })
  return response.data
}

export const publishPlaybookVersion = async (
  playbookId: string,
  versionId: string
): Promise<PlaybookVersion> => {
  const response = await api.post(`/api/v1/playbooks/${playbookId}/versions/${versionId}/publish`)
  return response.data
}

export const activatePlaybook = async (playbookId: string): Promise<Playbook> => {
  const response = await api.post(`/api/v1/playbooks/${playbookId}/activate`)
  return response.data
}

export const deactivatePlaybook = async (playbookId: string): Promise<Playbook> => {
  const response = await api.post(`/api/v1/playbooks/${playbookId}/deactivate`)
  return response.data
}

export const executePlaybook = async (
  playbookId: string,
  data: { incident_id?: string; alert_id?: string; context?: Record<string, any> } = {}
): Promise<PlaybookExecution> => {
  const response = await api.post(`/api/v1/playbooks/${playbookId}/execute`, data)
  return response.data
}

export const listPlaybookExecutions = async (params?: {
  playbook_id?: string
  incident_id?: string
  status?: PlaybookExecutionStatus
  limit?: number
  offset?: number
}): Promise<PlaybookExecution[]> => {
  const response = await api.get('/api/v1/playbooks/executions', { params })
  return response.data
}

export const listExecutionSteps = async (executionId: string): Promise<PlaybookExecutionStep[]> => {
  const response = await api.get(`/api/v1/playbooks/executions/${executionId}/steps`)
  return response.data
}

export const listExecutionLogs = async (executionId: string): Promise<PlaybookRunLog[]> => {
  const response = await api.get(`/api/v1/playbooks/executions/${executionId}/logs`)
  return response.data
}

export const pauseExecution = async (executionId: string): Promise<PlaybookExecution> => {
  const response = await api.post(`/api/v1/playbooks/executions/${executionId}/pause`)
  return response.data
}

export const resumeExecution = async (executionId: string): Promise<PlaybookExecution> => {
  const response = await api.post(`/api/v1/playbooks/executions/${executionId}/resume`)
  return response.data
}

export const cancelExecution = async (executionId: string): Promise<PlaybookExecution> => {
  const response = await api.post(`/api/v1/playbooks/executions/${executionId}/cancel`)
  return response.data
}

export const listPlaybookApprovals = async (executionId?: string): Promise<PlaybookApproval[]> => {
  const response = await api.get('/api/v1/playbooks/approvals', { params: { execution_id: executionId } })
  return response.data
}

export const approvePlaybookApproval = async (
  approvalId: string,
  comment?: string
): Promise<PlaybookApproval> => {
  const response = await api.post(`/api/v1/playbooks/approvals/${approvalId}/approve`, { comment })
  return response.data
}

export const rejectPlaybookApproval = async (
  approvalId: string,
  comment?: string
): Promise<PlaybookApproval> => {
  const response = await api.post(`/api/v1/playbooks/approvals/${approvalId}/reject`, { comment })
  return response.data
}
