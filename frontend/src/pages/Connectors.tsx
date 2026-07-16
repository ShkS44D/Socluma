import React, { useEffect, useState } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Checkbox,
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
import { Add, History, Visibility } from '@mui/icons-material'
import { ActionConnector, ConnectorType, createConnector, listConnectors } from '../services/api'

const connectorTypes: ConnectorType[] = ['webhook', 'slack', 'teams', 'smtp_email', 'generic_rest']

const Connectors: React.FC = () => {
  const [connectors, setConnectors] = useState<ActionConnector[]>([])
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [type, setType] = useState<ConnectorType>('webhook')
  const [config, setConfig] = useState('{"url":"https://example.com/webhook"}')
  const [requiresApproval, setRequiresApproval] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setError(null)
      setConnectors(await listConnectors())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load connectors')
    }
  }

  useEffect(() => {
    load()
  }, [])

  const create = async () => {
    try {
      await createConnector({
        name,
        type,
        config: JSON.parse(config),
        requires_approval: requiresApproval,
        approval_roles: requiresApproval ? ['admin'] : undefined,
      })
      setOpen(false)
      setName('')
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create connector')
    }
  }

  return (
    <Stack spacing={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="h4">Connectors</Typography>
        <Stack direction="row" spacing={1}>
          <Button component={RouterLink} to="/soar/actions" startIcon={<History />}>
            Action History
          </Button>
          <Button variant="contained" startIcon={<Add />} onClick={() => setOpen(true)}>
            New Connector
          </Button>
        </Stack>
      </Box>
      {error && <Alert severity="error">{error}</Alert>}
      <Paper>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Approval</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {connectors.map((connector) => (
              <TableRow key={connector.id}>
                <TableCell>{connector.name}</TableCell>
                <TableCell>{connector.type.replace(/_/g, ' ')}</TableCell>
                <TableCell>
                  <Chip size="small" label={connector.status} color={connector.status === 'active' ? 'success' : 'default'} />
                </TableCell>
                <TableCell>{connector.requires_approval ? 'Required' : 'Optional'}</TableCell>
                <TableCell align="right">
                  <Button size="small" component={RouterLink} to={`/soar/connectors/${connector.id}`} startIcon={<Visibility />}>
                    Open
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Create Connector</DialogTitle>
        <DialogContent>
          <Stack spacing={2} mt={1}>
            <TextField label="Name" value={name} onChange={(event) => setName(event.target.value)} fullWidth />
            <TextField select label="Type" value={type} onChange={(event) => setType(event.target.value as ConnectorType)} fullWidth>
              {connectorTypes.map((item) => (
                <MenuItem key={item} value={item}>
                  {item.replace(/_/g, ' ')}
                </MenuItem>
              ))}
            </TextField>
            <TextField label="Configuration JSON" value={config} onChange={(event) => setConfig(event.target.value)} fullWidth multiline minRows={5} />
            <Box>
              <Checkbox checked={requiresApproval} onChange={(event) => setRequiresApproval(event.target.checked)} />
              <Typography component="span">Require approval before execution</Typography>
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={create} variant="contained" disabled={!name.trim()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}

export default Connectors
