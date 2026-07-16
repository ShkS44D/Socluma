import React, { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Box, Button, Stack, Typography, Chip } from '@mui/material'
import { ArrowBack as ArrowBackIcon, Edit as EditIcon } from '@mui/icons-material'
import {
  PageHeader,
  SectionCard,
  LoadingState,
  ErrorState,
  StatusChip
} from '../components/ui'
import { getDetectionRule, updateDetectionRule } from '../services/api/detectionRules'
import { DetectionRule } from '../services/api/types'
import { formatDateTimePKT } from '../utils/time'
import DetectionRuleFormModal from '../components/detection-rules/DetectionRuleFormModal'

const DetectionRuleDetail: React.FC = () => {
  const { ruleId } = useParams<{ ruleId: string }>()
  const navigate = useNavigate()
  const [rule, setRule] = useState<DetectionRule | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editModalOpen, setEditModalOpen] = useState(false)

  const fetchRule = async () => {
    if (!ruleId) return
    try {
      setLoading(true)
      setError('')
      const data = await getDetectionRule(ruleId)
      setRule(data)
    } catch (err) {
      setError('Failed to load detection rule')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRule()
  }, [ruleId])

  const handleUpdate = async (data: any) => {
    if (!ruleId) return
    await updateDetectionRule(ruleId, data)
    await fetchRule()
  }

  if (loading) {
    return <LoadingState title="Loading Detection Rule" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchRule} />
  }

  if (!rule) {
    return <ErrorState message="Detection rule not found" />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title={rule.name}
        description={rule.description || 'No description'}
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Detection Rules', href: '/detection-rules' },
          { label: rule.name },
        ]}
        actions={
          <Stack direction="row" spacing={2}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate('/detection-rules')}
            >
              Back
            </Button>
            <Button
              variant="contained"
              startIcon={<EditIcon />}
              onClick={() => setEditModalOpen(true)}
            >
              Edit Rule
            </Button>
          </Stack>
        }
      />

      <SectionCard title="Overview">
        <Stack spacing={3}>
          <Stack direction="row" spacing={3} flexWrap="wrap">
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Severity
              </Typography>
              <StatusChip
                label={rule.severity}
                color={
                  rule.severity === 'critical' || rule.severity === 'high'
                    ? 'error'
                    : rule.severity === 'medium'
                    ? 'warning'
                    : 'info'
                }
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Status
              </Typography>
              <StatusChip
                label={rule.enabled ? 'Enabled' : 'Disabled'}
                color={rule.enabled ? 'success' : 'default'}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Type
              </Typography>
              <Chip label={rule.type} />
            </Box>
          </Stack>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">
              Created At
            </Typography>
            <Typography variant="body2">
              {formatDateTimePKT(rule.created_at)}
            </Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">
              Updated At
            </Typography>
            <Typography variant="body2">
              {formatDateTimePKT(rule.updated_at)}
            </Typography>
          </Box>
        </Stack>
      </SectionCard>

      {rule.query && (
        <SectionCard title="Generated Query">
          <Typography
            variant="body2"
            sx={{
              fontFamily: 'monospace',
              p: 2,
              backgroundColor: 'rgba(0,0,0,0.2)',
              borderRadius: 1,
              overflowX: 'auto'
            }}
          >
            {rule.query}
          </Typography>
        </SectionCard>
      )}

      {rule.sigma_rule && (
        <SectionCard title="Sigma Rule">
          <Typography
            variant="body2"
            sx={{
              fontFamily: 'monospace',
              p: 2,
              backgroundColor: 'rgba(0,0,0,0.2)',
              borderRadius: 1,
              overflowX: 'auto',
              whiteSpace: 'pre-wrap'
            }}
          >
            {rule.sigma_rule}
          </Typography>
        </SectionCard>
      )}

      <DetectionRuleFormModal
        open={editModalOpen}
        onClose={() => setEditModalOpen(false)}
        onSubmit={handleUpdate}
        initialData={rule}
      />
    </Stack>
  )
}

export default DetectionRuleDetail
