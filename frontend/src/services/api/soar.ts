import api from './client'
import {
  ActionConnector,
  ActionConnectorCreate,
  ConnectorActionExecution,
  ConnectorActionLog,
  ConnectorCredential,
  SOARActionApproval,
} from './types'

export const listConnectorTypes = async (): Promise<Array<{ type: string; name: string }>> => {
  const response = await api.get('/api/v1/soar/connector-types')
  return response.data
}

export const listConnectors = async (): Promise<ActionConnector[]> => {
  const response = await api.get('/api/v1/soar/connectors')
  return response.data
}

export const getConnector = async (connectorId: string): Promise<ActionConnector> => {
  const response = await api.get(`/api/v1/soar/connectors/${connectorId}`)
  return response.data
}

export const createConnector = async (data: ActionConnectorCreate): Promise<ActionConnector> => {
  const response = await api.post('/api/v1/soar/connectors', data)
  return response.data
}

export const testConnector = async (
  connectorId: string,
  credentialId?: string
): Promise<{ success: boolean; message?: string; status_code?: number; response: Record<string, any> }> => {
  const response = await api.post(`/api/v1/soar/connectors/${connectorId}/test`, null, {
    params: credentialId ? { credential_id: credentialId } : undefined,
  })
  return response.data
}

export const listCredentials = async (connectorId?: string): Promise<ConnectorCredential[]> => {
  const response = await api.get('/api/v1/soar/credentials', {
    params: connectorId ? { connector_id: connectorId } : undefined,
  })
  return response.data
}

export const createCredential = async (data: {
  connector_id: string
  name: string
  secret: Record<string, any>
}): Promise<ConnectorCredential> => {
  const response = await api.post('/api/v1/soar/credentials', data)
  return response.data
}

export const listActionExecutions = async (connectorId?: string): Promise<ConnectorActionExecution[]> => {
  const response = await api.get('/api/v1/soar/executions', {
    params: connectorId ? { connector_id: connectorId } : undefined,
  })
  return response.data
}

export const createActionExecution = async (data: {
  connector_id: string
  credential_id?: string
  action_name: string
  request: Record<string, any>
  retry_policy?: Record<string, any>
  timeout_seconds?: number
  requires_approval?: boolean
}): Promise<ConnectorActionExecution> => {
  const response = await api.post('/api/v1/soar/executions', data)
  return response.data
}

export const getActionExecution = async (executionId: string): Promise<ConnectorActionExecution> => {
  const response = await api.get(`/api/v1/soar/executions/${executionId}`)
  return response.data
}

export const listActionLogs = async (executionId: string): Promise<ConnectorActionLog[]> => {
  const response = await api.get(`/api/v1/soar/executions/${executionId}/logs`)
  return response.data
}

export const listSOARApprovals = async (): Promise<SOARActionApproval[]> => {
  const response = await api.get('/api/v1/soar/approvals')
  return response.data
}

export const approveSOARAction = async (approvalId: string, comment?: string): Promise<SOARActionApproval> => {
  const response = await api.post(`/api/v1/soar/approvals/${approvalId}/approve`, { comment })
  return response.data
}

export const rejectSOARAction = async (approvalId: string, comment?: string): Promise<SOARActionApproval> => {
  const response = await api.post(`/api/v1/soar/approvals/${approvalId}/reject`, { comment })
  return response.data
}
