import React, { useEffect, useState } from 'react'
import {
  Box,
  Typography,
  Button,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  Paper,
} from '@mui/material'
import { Add, Security } from '@mui/icons-material'
import { PageHeader, SectionCard, StatusChip } from '../components/ui'
import { getLogSources, createLogSource, getCollectors, registerCollector, LogSource, Collector } from '../services/api'
import { formatDateTimePKT } from '../utils/time'

const LogSources: React.FC = () => {
  const [logSources, setLogSources] = useState<LogSource[]>([])
  const [collectors, setCollectors] = useState<Collector[]>([])
  const [loading, setLoading] = useState(true)
  const [openLogSourceDialog, setOpenLogSourceDialog] = useState(false)
  const [openCollectorDialog, setOpenCollectorDialog] = useState(false)
  const [newLogSource, setNewLogSource] = useState({ name: '', type: 'custom' as const, description: '' })
  const [newCollector, setNewCollector] = useState({ name: '', type: '', hostname: '', log_source_id: '' })

  const fetchData = async () => {
    try {
      const [sources, colls] = await Promise.all([getLogSources(), getCollectors()])
      setLogSources(sources)
      setCollectors(colls)
    } catch (err) {
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleCreateLogSource = async () => {
    try {
      const source = await createLogSource(newLogSource)
      setLogSources([...logSources, source])
      setOpenLogSourceDialog(false)
      setNewLogSource({ name: '', type: 'custom', description: '' })
    } catch (err) {
      console.error('Failed to create log source:', err)
    }
  }

  const handleRegisterCollector = async () => {
    try {
      const coll = await registerCollector(newCollector)
      alert(`Collector registered! Token: ${coll.token}`)
      await fetchData()
      setOpenCollectorDialog(false)
      setNewCollector({ name: '', type: '', hostname: '', log_source_id: '' })
    } catch (err) {
      console.error('Failed to register collector:', err)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'online':
        return 'success'
      case 'error':
        return 'error'
      default:
        return 'default'
    }
  }

  if (loading) {
    return <PageHeader title="Loading..." description="Please wait..." />
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <PageHeader
        title="Log Sources & Collectors"
        description="Manage your log sources and data collectors"
      />
      <Box sx={{ display: 'flex', gap: 2 }}>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => setOpenLogSourceDialog(true)}
        >
          Add Log Source
        </Button>
        <Button
          variant="outlined"
          startIcon={<Security />}
          onClick={() => setOpenCollectorDialog(true)}
        >
          Register Collector
        </Button>
      </Box>
      <SectionCard title="Log Sources">
        <Grid container spacing={2}>
          {logSources.map(source => (
            <Grid item xs={12} md={6} lg={4} key={source.id}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{source.name}</Typography>
                  <StatusChip label={source.status} color={getStatusColor(source.status)} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Type: {source.type}
                </Typography>
                {source.description && (
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    {source.description}
                  </Typography>
                )}
                {source.last_seen && (
                  <Typography variant="caption" color="text.secondary">
                    Last seen: {formatDateTimePKT(source.last_seen)}
                  </Typography>
                )}
              </Paper>
            </Grid>
          ))}
        </Grid>
      </SectionCard>
      <SectionCard title="Collectors">
        <Grid container spacing={2}>
          {collectors.map(coll => (
            <Grid item xs={12} md={6} lg={4} key={coll.id}>
              <Paper sx={{ p: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{coll.name}</Typography>
                  <StatusChip label={coll.status} color={getStatusColor(coll.status)} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  Type: {coll.type}
                </Typography>
                {coll.hostname && (
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Host: {coll.hostname}
                  </Typography>
                )}
                {coll.last_seen && (
                  <Typography variant="caption" color="text.secondary">
                    Last seen: {formatDateTimePKT(coll.last_seen)}
                  </Typography>
                )}
              </Paper>
            </Grid>
          ))}
        </Grid>
      </SectionCard>
      <Dialog open={openLogSourceDialog} onClose={() => setOpenLogSourceDialog(false)}>
        <DialogTitle>Add Log Source</DialogTitle>
        <DialogContent sx={{ width: 400 }}>
          <TextField
            label="Name"
            fullWidth
            margin="normal"
            value={newLogSource.name}
            onChange={e => setNewLogSource({ ...newLogSource, name: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Type</InputLabel>
            <Select
              value={newLogSource.type}
              label="Type"
              onChange={e => setNewLogSource({ ...newLogSource, type: e.target.value as any })}
            >
              <MenuItem value="windows_edr">Windows EDR</MenuItem>
              <MenuItem value="linux_audit">Linux Audit</MenuItem>
              <MenuItem value="firewall">Firewall</MenuItem>
              <MenuItem value="cloudtrail">CloudTrail</MenuItem>
              <MenuItem value="application_log">Application Log</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Description"
            fullWidth
            margin="normal"
            multiline
            rows={3}
            value={newLogSource.description}
            onChange={e => setNewLogSource({ ...newLogSource, description: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenLogSourceDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreateLogSource}>Create</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={openCollectorDialog} onClose={() => setOpenCollectorDialog(false)}>
        <DialogTitle>Register Collector</DialogTitle>
        <DialogContent sx={{ width: 400 }}>
          <TextField
            label="Name"
            fullWidth
            margin="normal"
            value={newCollector.name}
            onChange={e => setNewCollector({ ...newCollector, name: e.target.value })}
          />
          <TextField
            label="Type"
            fullWidth
            margin="normal"
            value={newCollector.type}
            onChange={e => setNewCollector({ ...newCollector, type: e.target.value })}
          />
          <TextField
            label="Hostname"
            fullWidth
            margin="normal"
            value={newCollector.hostname}
            onChange={e => setNewCollector({ ...newCollector, hostname: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Associated Log Source</InputLabel>
            <Select
              value={newCollector.log_source_id}
              label="Associated Log Source"
              onChange={e => setNewCollector({ ...newCollector, log_source_id: e.target.value })}
            >
              <MenuItem value="">None</MenuItem>
              {logSources.map(source => (
                <MenuItem key={source.id} value={source.id}>{source.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenCollectorDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleRegisterCollector}>Register</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default LogSources
