import React, { useEffect, useState } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import { Alert, Button, Chip, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { ConnectorActionExecution, listActionExecutions } from '../services/api'

const ActionHistory: React.FC = () => {
  const [executions, setExecutions] = useState<ConnectorActionExecution[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listActionExecutions()
      .then(setExecutions)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load action history'))
  }, [])

  return (
    <Stack spacing={3}>
      <Typography variant="h4">Action History</Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <Paper>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Action</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Attempts</TableCell>
              <TableCell>Correlation ID</TableCell>
              <TableCell>Created</TableCell>
              <TableCell align="right">Details</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {executions.map((execution) => (
              <TableRow key={execution.id}>
                <TableCell>{execution.action_name}</TableCell>
                <TableCell>
                  <Chip size="small" label={execution.status} color={execution.status === 'completed' ? 'success' : execution.status === 'failed' ? 'error' : 'default'} />
                </TableCell>
                <TableCell>{execution.attempts}/{execution.max_attempts}</TableCell>
                <TableCell>{execution.correlation_id}</TableCell>
                <TableCell>{new Date(execution.created_at).toLocaleString()}</TableCell>
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

export default ActionHistory
