import React, { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Chip,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'
import { CheckCircle, Pause, PlayArrow, Stop } from '@mui/icons-material'
import {
  activatePlaybook,
  approvePlaybookApproval,
  cancelExecution,
  deactivatePlaybook,
  executePlaybook,
  listExecutionLogs,
  listExecutionSteps,
  listPlaybookApprovals,
  listPlaybookExecutions,
  listPlaybookVersions,
  getPlaybook,
  pauseExecution,
  publishPlaybookVersion,
  rejectPlaybookApproval,
  resumeExecution,
  Playbook,
  PlaybookApproval,
  PlaybookExecution,
  PlaybookExecutionStep,
  PlaybookRunLog,
  PlaybookVersion,
} from '../services/api'

const PlaybookDetail: React.FC = () => {
  const { playbookId } = useParams<{ playbookId: string }>()
  const [playbook, setPlaybook] = useState<Playbook | null>(null)
  const [versions, setVersions] = useState<PlaybookVersion[]>([])
  const [executions, setExecutions] = useState<PlaybookExecution[]>([])
  const [selectedExecutionId, setSelectedExecutionId] = useState<string>('')
  const [steps, setSteps] = useState<PlaybookExecutionStep[]>([])
  const [logs, setLogs] = useState<PlaybookRunLog[]>([])
  const [approvals, setApprovals] = useState<PlaybookApproval[]>([])
  const [error, setError] = useState<string | null>(null)

  const selectedExecution = useMemo(
    () => executions.find((execution) => execution.id === selectedExecutionId),
    [executions, selectedExecutionId]
  )

  const load = async () => {
    if (!playbookId) return
    setError(null)
    try {
      const [playbookData, versionsData, executionsData, approvalsData] = await Promise.all([
        getPlaybook(playbookId),
        listPlaybookVersions(playbookId),
        listPlaybookExecutions({ playbook_id: playbookId }),
        listPlaybookApprovals(),
      ])
      setPlaybook(playbookData)
      setVersions(versionsData)
      setExecutions(executionsData)
      setApprovals(approvalsData.filter((approval) => executionsData.some((execution) => execution.id === approval.execution_id)))
      if (!selectedExecutionId && executionsData[0]) {
        setSelectedExecutionId(executionsData[0].id)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load playbook')
    }
  }

  useEffect(() => {
    load()
  }, [playbookId])

  useEffect(() => {
    const loadExecutionDetails = async () => {
      if (!selectedExecutionId) {
        setSteps([])
        setLogs([])
        return
      }
      const [stepData, logData] = await Promise.all([
        listExecutionSteps(selectedExecutionId),
        listExecutionLogs(selectedExecutionId),
      ])
      setSteps(stepData)
      setLogs(logData)
    }
    loadExecutionDetails().catch((err) => setError(err instanceof Error ? err.message : 'Failed to load execution details'))
  }, [selectedExecutionId])

  const runAction = async (action: () => Promise<unknown>) => {
    try {
      await action()
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed')
    }
  }

  if (!playbookId) {
    return <Alert severity="error">Missing playbook ID</Alert>
  }

  return (
    <Stack spacing={3}>
      {error && <Alert severity="error">{error}</Alert>}
      {playbook && (
        <Paper sx={{ p: 3 }}>
          <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2}>
            <Box>
              <Typography variant="h4">{playbook.name}</Typography>
              <Typography color="text.secondary">{playbook.description || 'No description'}</Typography>
              <Stack direction="row" spacing={1} mt={2}>
                <Chip label={playbook.status} color={playbook.status === 'active' ? 'success' : 'default'} />
                <Chip label={playbook.trigger_type.replace(/_/g, ' ')} variant="outlined" />
              </Stack>
            </Box>
            <Stack direction="row" spacing={1} alignItems="flex-start">
              <Button startIcon={<PlayArrow />} variant="contained" onClick={() => runAction(() => executePlaybook(playbookId))}>
                Run
              </Button>
              <Button onClick={() => runAction(() => activatePlaybook(playbookId))}>Activate</Button>
              <Button onClick={() => runAction(() => deactivatePlaybook(playbookId))}>Deactivate</Button>
            </Stack>
          </Stack>
        </Paper>
      )}

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Versions
        </Typography>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Version</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Steps</TableCell>
              <TableCell>Published</TableCell>
              <TableCell align="right">Action</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {versions.map((version) => (
              <TableRow key={version.id}>
                <TableCell>v{version.version_number}</TableCell>
                <TableCell>{version.status}</TableCell>
                <TableCell>{version.definition.steps?.length ?? 0}</TableCell>
                <TableCell>{version.published_at ? new Date(version.published_at).toLocaleString() : 'Not published'}</TableCell>
                <TableCell align="right">
                  <Button size="small" onClick={() => runAction(() => publishPlaybookVersion(playbookId, version.id))}>
                    Publish
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ md: 'center' }}>
          <Typography variant="h6">Execution History</Typography>
          <FormControl size="small" sx={{ minWidth: 280 }}>
            <InputLabel>Execution</InputLabel>
            <Select
              label="Execution"
              value={selectedExecutionId}
              onChange={(event) => setSelectedExecutionId(event.target.value)}
            >
              {executions.map((execution) => (
                <MenuItem key={execution.id} value={execution.id}>
                  {execution.status} - {new Date(execution.created_at).toLocaleString()}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Stack>

        {selectedExecution && (
          <Stack direction="row" spacing={1} mt={2}>
            <Chip label={selectedExecution.status} />
            <Button size="small" startIcon={<Pause />} onClick={() => runAction(() => pauseExecution(selectedExecution.id))}>
              Pause
            </Button>
            <Button size="small" startIcon={<PlayArrow />} onClick={() => runAction(() => resumeExecution(selectedExecution.id))}>
              Resume
            </Button>
            <Button size="small" startIcon={<Stop />} onClick={() => runAction(() => cancelExecution(selectedExecution.id))}>
              Cancel
            </Button>
          </Stack>
        )}

        <Table size="small" sx={{ mt: 2 }}>
          <TableHead>
            <TableRow>
              <TableCell>Step</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Attempts</TableCell>
              <TableCell>Time</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {steps.map((step) => (
              <TableRow key={step.id}>
                <TableCell>{step.name}</TableCell>
                <TableCell>{step.type}</TableCell>
                <TableCell>{step.status}</TableCell>
                <TableCell>{step.attempts}/{step.max_attempts}</TableCell>
                <TableCell>{step.execution_time_ms ?? 0} ms</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Approvals
        </Typography>
        <Stack spacing={1}>
          {approvals.map((approval) => (
            <Stack key={approval.id} direction={{ xs: 'column', md: 'row' }} spacing={1} justifyContent="space-between">
              <Box>
                <Typography>{approval.message || 'Approval requested'}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {approval.status} - {new Date(approval.created_at).toLocaleString()}
                </Typography>
              </Box>
              {approval.status === 'pending' && (
                <Stack direction="row" spacing={1}>
                  <Button size="small" startIcon={<CheckCircle />} onClick={() => runAction(() => approvePlaybookApproval(approval.id))}>
                    Approve
                  </Button>
                  <Button size="small" color="error" onClick={() => runAction(() => rejectPlaybookApproval(approval.id))}>
                    Reject
                  </Button>
                </Stack>
              )}
            </Stack>
          ))}
          {approvals.length === 0 && <Typography color="text.secondary">No approval requests for this playbook.</Typography>}
        </Stack>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Execution Logs
        </Typography>
        <Stack spacing={1}>
          {logs.map((log) => (
            <Box key={log.id}>
              <Typography variant="body2">
                [{new Date(log.created_at).toLocaleTimeString()}] {log.level.toUpperCase()} - {log.message}
              </Typography>
            </Box>
          ))}
          {logs.length === 0 && <Typography color="text.secondary">No logs for the selected execution.</Typography>}
        </Stack>
      </Paper>
    </Stack>
  )
}

export default PlaybookDetail
