import React, { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Alert, Box, Chip, Paper, Stack, Typography } from '@mui/material'
import { ConnectorActionExecution, ConnectorActionLog, getActionExecution, listActionLogs } from '../services/api'

const JsonBlock: React.FC<{ value: unknown }> = ({ value }) => (
  <Box component="pre" sx={{ m: 0, p: 2, bgcolor: 'background.default', overflow: 'auto', fontSize: 12 }}>
    {JSON.stringify(value ?? {}, null, 2)}
  </Box>
)

const ActionExecutionDetail: React.FC = () => {
  const { executionId } = useParams<{ executionId: string }>()
  const [execution, setExecution] = useState<ConnectorActionExecution | null>(null)
  const [logs, setLogs] = useState<ConnectorActionLog[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!executionId) return
    Promise.all([getActionExecution(executionId), listActionLogs(executionId)])
      .then(([executionData, logData]) => {
        setExecution(executionData)
        setLogs(logData)
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load action execution'))
  }, [executionId])

  if (!executionId) return <Alert severity="error">Missing execution ID</Alert>

  return (
    <Stack spacing={3}>
      {error && <Alert severity="error">{error}</Alert>}
      {execution && (
        <>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h4">{execution.action_name}</Typography>
            <Stack direction="row" spacing={1} mt={2}>
              <Chip label={execution.status} />
              <Chip label={`attempts ${execution.attempts}/${execution.max_attempts}`} />
              <Chip label={`${execution.duration_ms ?? 0} ms`} />
            </Stack>
            <Typography variant="body2" color="text.secondary" mt={2}>
              Correlation: {execution.correlation_id} | Request: {execution.request_id || 'n/a'} | Worker: {execution.worker_id || 'n/a'}
            </Typography>
            {execution.error && <Alert severity="error" sx={{ mt: 2 }}>{execution.error}</Alert>}
          </Paper>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Request</Typography>
            <JsonBlock value={execution.request} />
          </Paper>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>Response</Typography>
            <JsonBlock value={execution.response} />
          </Paper>
        </>
      )}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>Logs</Typography>
        <Stack spacing={1}>
          {logs.map((log) => (
            <Typography key={log.id} variant="body2">
              [{new Date(log.created_at).toLocaleTimeString()}] {log.level.toUpperCase()} - {log.message}
            </Typography>
          ))}
        </Stack>
      </Paper>
    </Stack>
  )
}

export default ActionExecutionDetail
