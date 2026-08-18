import React, { useState, useEffect } from 'react'
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Stack,
} from '@mui/material'
import { IOCCreate, IOCUpdate, IndicatorType, Severity } from '../../services/api/types'

interface IOCFormModalProps {
  open: boolean
  onClose: () => void
  onSubmit: (data: IOCCreate | IOCUpdate) => Promise<void>
  initialData?: IOCCreate | null
  loading?: boolean
}

const IOCFormModal: React.FC<IOCFormModalProps> = ({
  open,
  onClose,
  onSubmit,
  initialData,
  loading = false,
}) => {
  const [formData, setFormData] = useState<IOCCreate>({
    type: 'ip',
    value: '',
    description: '',
    source: '',
    severity: 'medium',
    confidence_score: 0,
    source_reliability: 50,
    lifecycle_status: 'new',
    tlp: 'TLP:AMBER',
    tags: [],
    is_active: true,
  })

  const [tagsInput, setTagsInput] = useState('')

  useEffect(() => {
    if (initialData) {
      setFormData({
        type: initialData.type || 'ip',
        value: initialData.value || '',
        description: initialData.description || '',
        source: initialData.source || '',
        severity: initialData.severity || 'medium',
        confidence_score: initialData.confidence_score || 0,
        source_reliability: initialData.source_reliability ?? 50,
        lifecycle_status: initialData.lifecycle_status || 'new',
        tlp: initialData.tlp || 'TLP:AMBER',
        tags: initialData.tags || [],
        is_active: initialData.is_active !== undefined ? initialData.is_active : true,
      })
      setTagsInput((initialData.tags || []).join(', '))
    } else {
      setFormData({
        type: 'ip',
        value: '',
        description: '',
        source: '',
        severity: 'medium',
        confidence_score: 0,
        source_reliability: 50,
        lifecycle_status: 'new',
        tlp: 'TLP:AMBER',
        tags: [],
        is_active: true,
      })
      setTagsInput('')
    }
  }, [initialData])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await onSubmit({
      ...formData,
      tags: tagsInput
        .split(',')
        .map((t) => t.trim())
        .filter((t) => t),
    })
    onClose()
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <form onSubmit={handleSubmit}>
        <DialogTitle>
          {initialData ? 'Edit Indicator of Compromise' : 'Create Indicator of Compromise'}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <FormControl fullWidth>
              <InputLabel>Indicator Type</InputLabel>
              <Select
                value={formData.type}
                label="Indicator Type"
                onChange={(e) =>
                  setFormData({ ...formData, type: e.target.value as IndicatorType })
                }
              >
                <MenuItem value="ip">IP Address</MenuItem>
                <MenuItem value="ipv4">IPv4</MenuItem>
                <MenuItem value="ipv6">IPv6</MenuItem>
                <MenuItem value="cidr">CIDR</MenuItem>
                <MenuItem value="domain">Domain</MenuItem>
                <MenuItem value="url">URL</MenuItem>
                <MenuItem value="email">Email Address</MenuItem>
                <MenuItem value="hash">Hash</MenuItem>
                <MenuItem value="md5">MD5</MenuItem>
                <MenuItem value="sha1">SHA-1</MenuItem>
                <MenuItem value="sha256">SHA-256</MenuItem>
                <MenuItem value="sha512">SHA-512</MenuItem>
                <MenuItem value="file_name">File Name</MenuItem>
                <MenuItem value="file_path">File Path</MenuItem>
                <MenuItem value="registry_key">Registry Key</MenuItem>
                <MenuItem value="mutex">Mutex</MenuItem>
                <MenuItem value="user_agent">User Agent</MenuItem>
                <MenuItem value="certificate_fingerprint">Certificate Fingerprint</MenuItem>
                <MenuItem value="ja3">JA3</MenuItem>
                <MenuItem value="ja4">JA4</MenuItem>
                <MenuItem value="cryptocurrency_address">Cryptocurrency Address</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Indicator Value"
              fullWidth
              value={formData.value}
              onChange={(e) => setFormData({ ...formData, value: e.target.value })}
              required
            />
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
            <TextField
              label="Source"
              fullWidth
              value={formData.source}
              onChange={(e) => setFormData({ ...formData, source: e.target.value })}
            />
            <FormControl fullWidth>
              <InputLabel>Severity</InputLabel>
              <Select
                value={formData.severity}
                label="Severity"
                onChange={(e) =>
                  setFormData({ ...formData, severity: e.target.value as Severity })
                }
              >
                <MenuItem value="low">Low</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Confidence Score"
              type="number"
              fullWidth
              inputProps={{ min: 0, max: 100 }}
              value={formData.confidence_score}
              onChange={(e) =>
                setFormData({ ...formData, confidence_score: Number(e.target.value) })
              }
            />
            <TextField
              label="Source Reliability"
              type="number"
              fullWidth
              inputProps={{ min: 0, max: 100 }}
              value={formData.source_reliability}
              onChange={(e) =>
                setFormData({ ...formData, source_reliability: Number(e.target.value) })
              }
            />
            <FormControl fullWidth>
              <InputLabel>Lifecycle</InputLabel>
              <Select
                value={formData.lifecycle_status || 'new'}
                label="Lifecycle"
                onChange={(e) => setFormData({ ...formData, lifecycle_status: e.target.value })}
              >
                <MenuItem value="new">New</MenuItem>
                <MenuItem value="under_review">Under Review</MenuItem>
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="monitoring">Monitoring</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>TLP</InputLabel>
              <Select
                value={formData.tlp || 'TLP:AMBER'}
                label="TLP"
                onChange={(e) => setFormData({ ...formData, tlp: e.target.value })}
              >
                {['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'].map(value => (
                  <MenuItem key={value} value={value}>{value}</MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="Tags (comma separated)"
              fullWidth
              value={tagsInput}
              onChange={(e) => setTagsInput(e.target.value)}
            />
            <FormControl fullWidth>
              <InputLabel>Status</InputLabel>
              <Select
                value={formData.is_active ? 'active' : 'inactive'}
                label="Status"
                onChange={(e) =>
                  setFormData({ ...formData, is_active: e.target.value === 'active' })
                }
              >
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="inactive">Inactive</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button type="submit" variant="contained" disabled={loading}>
            {initialData ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  )
}

export default IOCFormModal
