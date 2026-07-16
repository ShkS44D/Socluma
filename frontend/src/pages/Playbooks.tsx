import React, { useEffect, useState } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
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
import { Add, PlayArrow, Visibility } from '@mui/icons-material'
import {
  createPlaybook,
  executePlaybook,
  listPlaybooks,
  Playbook,
  PlaybookTriggerType,
} from '../services/api'

const triggerTypes: PlaybookTriggerType[] = [
  'manual_run',
  'alert_created',
  'incident_created',
  'incident_severity_changed',
  'scheduled',
  'webhook',
]

const Playbooks: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [triggerType, setTriggerType] = useState<PlaybookTriggerType>('manual_run')

  const loadPlaybooks = async () => {
    setLoading(true)
    setError(null)
    try {
      setPlaybooks(await listPlaybooks())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load playbooks')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadPlaybooks()
  }, [])

  const handleCreate = async () => {
    try {
      await createPlaybook({
        name,
        description,
        trigger_type: triggerType,
        steps: [
          {
            step_key: 'end',
            name: 'End',
            type: 'end',
            config: {},
          },
        ],
      })
      setOpen(false)
      setName('')
      setDescription('')
      setTriggerType('manual_run')
      await loadPlaybooks()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create playbook')
    }
  }

  const handleRun = async (playbookId: string) => {
    try {
      await executePlaybook(playbookId)
      await loadPlaybooks()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to execute playbook')
    }
  }

  return (
    <Stack spacing={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="h4">Playbooks</Typography>
        <Button variant="contained" startIcon={<Add />} onClick={() => setOpen(true)}>
          New Playbook
        </Button>
      </Box>

      {error && <Alert severity="error">{error}</Alert>}

      <Paper>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Trigger</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Updated</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {playbooks.map((playbook) => (
              <TableRow key={playbook.id}>
                <TableCell>
                  <Typography fontWeight={600}>{playbook.name}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {playbook.description || 'No description'}
                  </Typography>
                </TableCell>
                <TableCell>{playbook.trigger_type.replace(/_/g, ' ')}</TableCell>
                <TableCell>
                  <Chip size="small" label={playbook.status} color={playbook.status === 'active' ? 'success' : 'default'} />
                </TableCell>
                <TableCell>{new Date(playbook.updated_at).toLocaleString()}</TableCell>
                <TableCell align="right">
                  <Stack direction="row" spacing={1} justifyContent="flex-end">
                    <Button size="small" startIcon={<PlayArrow />} onClick={() => handleRun(playbook.id)}>
                      Run
                    </Button>
                    <Button size="small" startIcon={<Visibility />} component={RouterLink} to={`/playbooks/${playbook.id}`}>
                      Open
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
            {!loading && playbooks.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>
                  <Typography color="text.secondary">No playbooks have been created yet.</Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Create Playbook</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField label="Name" value={name} onChange={(event) => setName(event.target.value)} fullWidth />
            <TextField
              label="Description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              fullWidth
              multiline
              minRows={2}
            />
            <TextField
              select
              label="Trigger"
              value={triggerType}
              onChange={(event) => setTriggerType(event.target.value as PlaybookTriggerType)}
              fullWidth
            >
              {triggerTypes.map((trigger) => (
                <MenuItem key={trigger} value={trigger}>
                  {trigger.replace(/_/g, ' ')}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} variant="contained" disabled={!name.trim()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}

export default Playbooks
