import React, { useState, useEffect } from 'react'
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
  Typography,
  Alert
} from '@mui/material'
import { DetectionRule, DetectionRuleCreate, DetectionRuleUpdate, Severity } from '../../services/api/types'

interface DetectionRuleFormModalProps {
  open: boolean
  onClose: () => void
  onSubmit: (data: DetectionRuleCreate | DetectionRuleUpdate) => Promise<void>
  initialData?: DetectionRule | null
  loading?: boolean
}

const DetectionRuleFormModal: React.FC<DetectionRuleFormModalProps> = ({
  open,
  onClose,
  onSubmit,
  initialData,
  loading = false
}) => {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<Severity>('medium')
  const [type, setType] = useState<string>('sigma')
  const [ruleContent, setRuleContent] = useState<string>('')
  const [error, setError] = useState<string>('')
  const [nameError, setNameError] = useState<string>('')
  const [sigmaError, setSigmaError] = useState<string>('')

  const isEdit = !!initialData

  useEffect(() => {
    if (initialData) {
      setName(initialData.name)
      setDescription(initialData.description || '')
      setSeverity(initialData.severity)
      setType(initialData.type || initialData.rule_type || 'sigma')
      if (initialData.sigma_rule) {
        setRuleContent(initialData.sigma_rule)
      } else {
        setRuleContent('')
      }
    } else {
      setName('')
      setDescription('')
      setSeverity('medium')
      setType('sigma')
      setRuleContent(JSON.stringify({
        title: 'New Detection Rule',
        logsource: {
          category: 'process_creation'
        },
        detection: {
          selection: {
            process: 'powershell.exe'
          },
          condition: 'selection'
        }
      }, null, 2))
    }
    setError('')
    setNameError('')
    setSigmaError('')
  }, [initialData, open])

  const handleSubmit = async () => {
    setError('')
    setNameError('')
    setSigmaError('')

    let hasErrors = false

    if (!name.trim()) {
      setNameError('Name is required')
      hasErrors = true
    }

    if (type === 'sigma' && !ruleContent.trim()) {
      setSigmaError('Sigma YAML or JSON is required')
      hasErrors = true
    }

    if (hasErrors) {
      return
    }

    try {
      const data: DetectionRuleCreate | DetectionRuleUpdate = {
        name,
        description: description || undefined,
        severity,
        rule_type: type,
        sigma_rule: type === 'sigma' ? ruleContent : undefined,
        enabled: initialData ? initialData.enabled : true
      }

      await onSubmit(data)
      onClose()
    } catch (err: any) {
      setError(err.message || 'Failed to save detection rule')
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{isEdit ? 'Edit Detection Rule' : 'Create Detection Rule'}</DialogTitle>
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            label="Name"
            value={name}
            onChange={(e) => {
              setName(e.target.value)
              if (nameError) setNameError('')
            }}
            error={!!nameError}
            helperText={nameError}
            fullWidth
            required
          />
          <TextField
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            multiline
            rows={2}
          />
          <FormControl fullWidth>
            <InputLabel>Severity</InputLabel>
            <Select
              value={severity}
              label="Severity"
              onChange={(e) => setSeverity(e.target.value as Severity)}
            >
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth>
            <InputLabel>Type</InputLabel>
            <Select
              value={type}
              label="Type"
              onChange={(e) => setType(e.target.value)}
            >
              <MenuItem value="sigma">Sigma</MenuItem>
              <MenuItem value="custom">Custom</MenuItem>
            </Select>
          </FormControl>
          {type === 'sigma' && (
            <Stack>
              <Typography variant="subtitle2" gutterBottom>
                Sigma Content (YAML or JSON)
              </Typography>
              <TextField
                value={ruleContent}
                onChange={(e) => {
                  setRuleContent(e.target.value)
                  if (sigmaError) setSigmaError('')
                }}
                error={!!sigmaError}
                helperText={sigmaError}
                fullWidth
                multiline
                rows={12}
                slotProps={{
                  input: {
                    sx: {
                      fontFamily: 'monospace',
                      fontSize: '0.875rem'
                    }
                  }
                }}
              />
            </Stack>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button onClick={handleSubmit} variant="contained" disabled={loading}>
          {isEdit ? 'Update' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

export default DetectionRuleFormModal
