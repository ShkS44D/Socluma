import React, { useEffect, useState } from 'react'
import { Link as RouterLink, useParams } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material'
import {
  ActionConnector,
  ConnectorActionExecution,
  ConnectorCredential,
  SOARActionApproval,
  approveSOARAction,
  createActionExecution,
  createCredential,
  getConnector,
  listActionExecutions,
  listCredentials,
  listSOARApprovals,
  rejectSOARAction,
  testConnector,
} from '../services/api'

const ConnectorDetail: React.FC = () => {
  const { connectorId } = useParams<{ connectorId: string }>()
  const [connector, setConnector] = useState<ActionConnector | null>(null)
  const [credentials, setCredentials] = useState<ConnectorCredential[]>([])
  const [executions, setExecutions] = useState<ConnectorActionExecution[]>([])
  const [approvals, setApprovals] = useState<SOARActionApproval[]>([])
  const [credentialName, setCredentialName] = useState('')
  const [secret, setSecret] = useState('{}')
  const [actionName, setActionName] = useState('notify')
  const [requestBody, setRequestBody] = useState('{"message":"VigilantAI test action"}')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const load = async () => {
    if (!connectorId) return
    try {
      setError(null)
      const [connectorData, credentialData, executionData, approvalData] = await Promise.all([
        getConnector(connectorId),
        listCredentials(connectorId),
        listActionExecutions(connectorId),
        listSOARApprovals(),
      ])
      setConnector(connectorData)
      setCredentials(credentialData)
      setExecutions(executionData)
      setApprovals(approvalData.filter((approval) => executionData.some((execution) => execution.id === approval.execution_id)))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load connector')
    }
  }

  useEffect(() => {
    load()
  }, [connectorId])

  const run = async (action: () => Promise<unknown>, success: string) => {
    try {
      setError(null)
      setNotice(null)
      await action()
      setNotice(success)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed')
    }
  }

  if (!connectorId) return <Alert severity="error">Missing connector ID</Alert>

  return (
    <Stack spacing={3}>
      {error && <Alert severity="error">{error}</Alert>}
      {notice && <Alert severity="success">{notice}</Alert>}
      {connector && (
        <Paper sx={{ p: 3 }}>
          <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2}>
            <Box>
              <Typography variant="h4">{connector.name}</Typography>
              <Stack direction="row" spacing={1} mt={1}>
                <Chip label={connector.type.replace(/_/g, ' ')} />
                <Chip label={connector.status} color={connector.status === 'active' ? 'success' : 'default'} />
                {connector.requires_approval && <Chip label="approval required" color="warning" />}
              </Stack>
            </Box>
            <Button
              onClick={() => run(() => testConnector(connectorId, credentials[0]?.id), 'Connection test completed')}
            >
              Test Connection
            </Button>
          </Stack>
        </Paper>
      )}

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6">Credentials</Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} mt={2}>
          <TextField label="Name" value={credentialName} onChange={(event) => setCredentialName(event.target.value)} />
          <TextField label="Secret JSON" value={secret} onChange={(event) => setSecret(event.target.value)} fullWidth />
          <Button
            variant="contained"
            onClick={() => run(
              () => createCredential({ connector_id: connectorId, name: credentialName, secret: JSON.parse(secret) }),
              'Credential saved'
            )}
            disabled={!credentialName.trim()}
          >
            Save
          </Button>
        </Stack>
        <Table size="small" sx={{ mt: 2 }}>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Fingerprint</TableCell>
              <TableCell>Updated</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {credentials.map((credential) => (
              <TableRow key={credential.id}>
                <TableCell>{credential.name}</TableCell>
                <TableCell>{credential.status}</TableCell>
                <TableCell>{credential.secret_fingerprint.slice(0, 12)}...</TableCell>
                <TableCell>{new Date(credential.updated_at).toLocaleString()}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6">Manual Action</Typography>
        <Stack spacing={2} mt={2}>
          <TextField label="Action name" value={actionName} onChange={(event) => setActionName(event.target.value)} />
          <TextField label="Request JSON" value={requestBody} onChange={(event) => setRequestBody(event.target.value)} multiline minRows={5} />
          <Button
            variant="contained"
            onClick={() => run(
              () => createActionExecution({
                connector_id: connectorId,
                credential_id: credentials[0]?.id,
                action_name: actionName,
                request: JSON.parse(requestBody),
                retry_policy: { max_attempts: 2, backoff_seconds: 1, exponential_backoff: true },
              }),
              'Action submitted'
            )}
          >
            Execute
          </Button>
        </Stack>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6">Approvals</Typography>
        <Stack spacing={1} mt={2}>
          {approvals.map((approval) => (
            <Stack key={approval.id} direction={{ xs: 'column', md: 'row' }} spacing={1} justifyContent="space-between">
              <Typography>{approval.status} {approval.required_role ? `(${approval.required_role})` : ''}</Typography>
              {approval.status === 'pending' && (
                <Stack direction="row" spacing={1}>
                  <Button onClick={() => run(() => approveSOARAction(approval.id), 'Action approved')}>Approve</Button>
                  <Button color="error" onClick={() => run(() => rejectSOARAction(approval.id), 'Action rejected')}>Reject</Button>
                </Stack>
              )}
            </Stack>
          ))}
          {approvals.length === 0 && <Typography color="text.secondary">No approvals for this connector.</Typography>}
        </Stack>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6">Recent Action History</Typography>
        <Divider sx={{ my: 2 }} />
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Action</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Attempts</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell align="right">Details</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {executions.map((execution) => (
              <TableRow key={execution.id}>
                <TableCell>{execution.action_name}</TableCell>
                <TableCell>{execution.status}</TableCell>
                <TableCell>{execution.attempts}/{execution.max_attempts}</TableCell>
                <TableCell>{execution.duration_ms ?? 0} ms</TableCell>
                <TableCell align="right">
                  <Button size="small" component={RouterLink} to={`/soar/actions/${execution.id}`}>Open</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>
    </Stack>
  )
}

export default ConnectorDetail
