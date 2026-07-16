import React, { useEffect, useState } from 'react'
import {
  Box,
  Button,
  Chip,
  Divider,
  Stack,
  Typography,
} from '@mui/material'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowBack as ArrowBackIcon } from '@mui/icons-material'
import { getIOC, enrichIOC } from '../services/api/iocs'
import { IOC } from '../services/api/types'
import { formatDateTimePKT } from '../utils/time'
import {
  PageHeader,
  SectionCard,
  StatusChip,
  LoadingState,
  ErrorState,
} from '../components/ui'

const IOCDetail: React.FC = () => {
  const navigate = useNavigate()
  const { iocId } = useParams<{ iocId: string }>()
  const [ioc, setIoc] = useState<IOC | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [enriching, setEnriching] = useState(false)

  const fetchIOC = async () => {
    if (!iocId) return
    try {
      setLoading(true)
      setError('')
      const data = await getIOC(iocId)
      setIoc(data)
    } catch (err) {
      setError('Failed to load IOC details')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleEnrich = async () => {
    if (!iocId) return
    try {
      setEnriching(true)
      await enrichIOC(iocId)
      fetchIOC()
    } catch (err) {
      setError('Failed to enrich IOC')
      console.error(err)
    } finally {
      setEnriching(false)
    }
  }

  useEffect(() => {
    fetchIOC()
  }, [iocId])

  if (loading) {
    return <LoadingState title="Loading IOC Details" />
  }

  if (error || !ioc) {
    return <ErrorState message={error || 'IOC not found'} onRetry={fetchIOC} />
  }

  return (
    <Stack spacing={6}>
      <PageHeader
        title="Indicator of Compromise"
        description={`${ioc.type.toUpperCase()}: ${ioc.value}`}
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Threat Intel', href: '/threat-intel' },
          { label: ioc.value },
        ]}
        actions={
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/threat-intel')}
          >
            Back to IOCs
          </Button>
        }
      />

      <SectionCard title="Indicator Details">
        <Stack spacing={2}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
            <StatusChip label={ioc.type} />
            <StatusChip
              label={ioc.severity}
              color={
                ioc.severity === 'critical' || ioc.severity === 'high'
                  ? 'error'
                  : ioc.severity === 'medium'
                  ? 'warning'
                  : 'info'
              }
            />
            <StatusChip
              label={ioc.is_active ? 'Active' : 'Inactive'}
              color={ioc.is_active ? 'success' : 'default'}
            />
            <Chip label={`Confidence: ${ioc.confidence_score}%`} />
          </Box>
          <Typography variant="body1">
            <strong>Value:</strong> {ioc.value}
          </Typography>
          {ioc.description && (
            <Typography variant="body1">
              <strong>Description:</strong> {ioc.description}
            </Typography>
          )}
          {ioc.source && (
            <Typography variant="body1">
              <strong>Source:</strong> {ioc.source}
            </Typography>
          )}
          {ioc.tags && ioc.tags.length > 0 && (
            <Box>
              <Typography variant="body1" gutterBottom>
                <strong>Tags:</strong>
              </Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap">
                {ioc.tags.map((tag, idx) => (
                  <Chip key={idx} label={tag} size="small" />
                ))}
              </Stack>
            </Box>
          )}
          <Typography variant="body2" color="text.secondary">
            Created: {formatDateTimePKT(ioc.created_at)}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Last updated: {formatDateTimePKT(ioc.updated_at)}
          </Typography>
        </Stack>
      </SectionCard>

      <SectionCard
        title="Enrichment Data"
        action={
          <Button variant="contained" onClick={handleEnrich} disabled={enriching}>
            {enriching ? 'Enriching...' : 'Enrich IOC'}
          </Button>
        }
      >
        {ioc.enrichments.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No enrichment data available. Click "Enrich IOC" to fetch threat intelligence from external providers.
          </Typography>
        ) : (
          <Stack spacing={3}>
            {ioc.enrichments.map((enrichment) => (
              <Box key={enrichment.id}>
                <Typography variant="subtitle2" gutterBottom>
                  {enrichment.provider.charAt(0).toUpperCase() + enrichment.provider.slice(1)}
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: 1 }}>
                  {enrichment.reputation && (
                    <StatusChip
                      label={`Reputation: ${enrichment.reputation}`}
                      color={
                        enrichment.reputation === 'malicious'
                          ? 'error'
                          : enrichment.reputation === 'clean'
                          ? 'success'
                          : 'default'
                      }
                    />
                  )}
                  <Chip label={`Malicious Reports: ${enrichment.malicious_count}`} />
                  <Chip label={`Total Reports: ${enrichment.total_reports}`} />
                </Box>
                <Typography variant="caption" color="text.secondary">
                  Enriched: {formatDateTimePKT(enrichment.created_at)}
                </Typography>
                {enrichment.raw_response && (
                  <>
                    <Divider sx={{ my: 2 }} />
                    <Typography variant="subtitle2" gutterBottom>
                      Raw Response
                    </Typography>
                    <Box
                      sx={{
                        bgcolor: 'background.paper',
                        p: 2,
                        borderRadius: 1,
                        fontFamily: 'monospace',
                        fontSize: '0.875rem',
                        overflowX: 'auto',
                      }}
                    >
                      <pre>{JSON.stringify(enrichment.raw_response, null, 2)}</pre>
                    </Box>
                  </>
                )}
              </Box>
            ))}
          </Stack>
        )}
      </SectionCard>
    </Stack>
  )
}

export default IOCDetail
