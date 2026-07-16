import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Box,
  Typography,
  Button,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stack,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Link
} from '@mui/material'
import { ArrowBack, ExpandMore, AddTask, Visibility } from '@mui/icons-material'
import { 
  getAlert, 
  Alert, 
  updateAlertStatus, 
  createIncidentFromAlert, 
  getAlertIncident, 
  Incident,
  getAlertIOCs,
  IOC
} from '../services/api'
import { formatDateTimePKT } from '../utils/time'
import {
  PageHeader,
  SectionCard,
  StatusChip,
  LoadingState,
  ErrorState
} from '../components/ui'
import {
  getAlertActivityName,
  getAlertClassName,
  getAlertCommandLine,
  getAlertHost,
  getAlertMessage,
  getAlertMitre,
  getAlertParentImage,
  getAlertProcessImage,
  getAlertProcessingState,
  getAlertRuleName,
  getAlertUser
} from '../utils/alertDisplay'

const AlertDetail: React.FC = () => {
  const { alertId } = useParams<{ alertId: string }>()
  const [alert, setAlert] = useState<Alert | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [iocs, setIocs] = useState<IOC[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const navigate = useNavigate()

  const fetchData = async () => {
    try {
      setLoading(true)
      setError('')
      if (alertId) {
        const [alertData, incidentData, iocData] = await Promise.all([
          getAlert(alertId),
          getAlertIncident(alertId).catch(() => null),
          getAlertIOCs(alertId).catch(() => [])
        ])
        setAlert(alertData)
        setIncident(incidentData)
        setIocs(iocData)
      }
    } catch (err) {
      setError('Failed to load alert details')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (alertId) {
      fetchData()
    }
  }, [alertId])

  const handleStatusChange = async (newStatus: string) => {
    if (!alertId) return
    try {
      setActionLoading(true)
      const updatedAlert = await updateAlertStatus(alertId, newStatus as any)
      setAlert(updatedAlert)
    } catch (err) {
      console.error('Failed to update status:', err)
    } finally {
      setActionLoading(false)
    }
  }

  const handleCreateIncident = async () => {
    if (!alertId) return
    try {
      setActionLoading(true)
      const newIncident = await createIncidentFromAlert(alertId)
      setIncident(newIncident)
      // Refresh alert data to get the new incident_id
      const updatedAlert = await getAlert(alertId)
      setAlert(updatedAlert)
    } catch (err) {
      console.error('Failed to create incident:', err)
    } finally {
      setActionLoading(false)
    }
  }

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'N/A'
    return formatDateTimePKT(dateStr)
  }

  const formatJson = (data: any) => {
    return JSON.stringify(data, null, 2)
  }

  if (loading) {
    return <LoadingState title="Loading Alert Details" />
  }

  if (error) {
    return <ErrorState message={error} onRetry={fetchData} />
  }

  if (!alert) {
    return <ErrorState message="Alert not found" onRetry={() => navigate('/alerts')} />
  }

  const processImage = getAlertProcessImage(alert)
  const commandLine = getAlertCommandLine(alert)
  const parentImage = getAlertParentImage(alert)
  const host = getAlertHost(alert)
  const userName = getAlertUser(alert)
  const mitreTechnique = getAlertMitre(alert)

  return (
    <Stack spacing={6}>
      <PageHeader
        title={getAlertRuleName(alert)}
        description={getAlertMessage(alert)}
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Alerts', href: '/alerts' },
          { label: alertId || '' }
        ]}
      />
      <Box>
        <Button
          startIcon={<ArrowBack />}
          onClick={() => navigate('/alerts')}
        >
          Back to Alert Queue
        </Button>
      </Box>
      
      <SectionCard title="Actions">
        <Stack direction="row" spacing={2} flexWrap="wrap">
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={alert.status}
              label="Status"
              onChange={(e) => handleStatusChange(e.target.value)}
              disabled={actionLoading}
            >
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="investigating">Investigating</MenuItem>
              <MenuItem value="resolved">Resolved</MenuItem>
              <MenuItem value="dismissed">Dismissed</MenuItem>
            </Select>
          </FormControl>
          
          {!incident && (
            <Button
              variant="contained"
              startIcon={<AddTask />}
              onClick={handleCreateIncident}
              disabled={actionLoading}
            >
              Create Incident
            </Button>
          )}
          
          {incident && (
            <Button
              variant="outlined"
              startIcon={<Visibility />}
              onClick={() => navigate(`/incidents/${incident.id}`)}
            >
              View Related Incident
            </Button>
          )}
        </Stack>
      </SectionCard>

      <SectionCard title="Alert Summary">
        <Stack spacing={3}>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <StatusChip
              label={alert.severity}
              color={alert.severity === 'critical' || alert.severity === 'high' ? 'error' : alert.severity === 'medium' ? 'warning' : 'info'}
            />
            <StatusChip
              label={alert.status}
              color={alert.status === 'open' ? 'default' : alert.status === 'investigating' ? 'primary' : alert.status === 'resolved' ? 'success' : 'secondary'}
            />
          </Box>

          <Stack spacing={2}>
            <Typography variant="subtitle1">
              <strong>Alert ID:</strong> {alert.id}
            </Typography>
            <Typography variant="subtitle1">
              <strong>Detection Rule:</strong> {getAlertRuleName(alert)}
            </Typography>
            <Typography variant="subtitle1">
              <strong>Class:</strong> {getAlertClassName(alert)}
            </Typography>
            <Typography variant="subtitle1">
              <strong>Activity:</strong> {getAlertActivityName(alert)}
            </Typography>
            {mitreTechnique && (
              <Typography variant="subtitle1">
                <strong>MITRE Technique:</strong> {mitreTechnique}
              </Typography>
            )}
            <Typography variant="subtitle1">
              <strong>Message:</strong> {getAlertMessage(alert)}
            </Typography>
            {alert.why_matched && (
              <Typography variant="body2">
                <strong>Why Matched:</strong> {alert.why_matched}
              </Typography>
            )}
            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' }, gap: 2 }}>
              <Typography variant="body2">
                <strong>Process:</strong> {processImage || 'Not captured'}
              </Typography>
              <Typography variant="body2">
                <strong>Parent Process:</strong> {parentImage || 'Not captured'}
              </Typography>
              <Typography variant="body2" sx={{ gridColumn: { md: '1 / -1' }, wordBreak: 'break-word' }}>
                <strong>Command Line:</strong> {commandLine || 'Not captured'}
              </Typography>
              <Typography variant="body2">
                <strong>Host:</strong> {host || 'Not captured'}
              </Typography>
              <Typography variant="body2">
                <strong>User:</strong> {userName || 'Not captured'}
              </Typography>
            </Box>
            <Typography variant="body2">
              <strong>Created:</strong> {formatDate(alert.created_at)}
            </Typography>
            <Typography variant="body2">
              <strong>Processing State:</strong> {getAlertProcessingState(alert)}
              {alert.processed_at ? ` at ${formatDate(alert.processed_at)}` : ''}
            </Typography>
          </Stack>
        </Stack>
      </SectionCard>

      {alert.matched_condition && (
        <SectionCard title="Matched Condition">
          <Box
            component="pre"
            sx={{
              background: 'rgba(0,0,0,0.2)',
              p: 2,
              overflow: 'auto',
              borderRadius: 2,
              boxSizing: 'border-box',
              color: 'text.primary',
              fontFamily: 'monospace',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word'
            }}
          >
            {typeof alert.matched_condition === 'string' ? alert.matched_condition : JSON.stringify(alert.matched_condition, null, 2)}
          </Box>
        </SectionCard>
      )}

      {incident && (
        <SectionCard title="Related Incident">
          <Stack spacing={2}>
            <Typography variant="h6">
              <Link href={`/incidents/${incident.id}`} style={{ textDecoration: 'none' }}>
                {incident.title}
              </Link>
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <StatusChip
                label={incident.severity}
                color={incident.severity === 'critical' || incident.severity === 'high' ? 'error' : incident.severity === 'medium' ? 'warning' : 'info'}
              />
              <StatusChip
                label={incident.status}
                color={incident.status === 'open' ? 'default' : incident.status === 'investigating' ? 'primary' : incident.status === 'resolved' ? 'success' : 'secondary'}
              />
              <StatusChip label={`Risk: ${incident.risk_score}`} color="default" />
            </Box>
            <Typography variant="body2">
              {incident.description || 'No description'}
            </Typography>
          </Stack>
        </SectionCard>
      )}

      {iocs.length > 0 && (
        <SectionCard title="Related IOCs">
          <Stack spacing={2}>
            {iocs.map((ioc) => (
              <Box key={ioc.id} sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle2">
                    {ioc.type.toUpperCase()}: {ioc.value}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <StatusChip
                      label={ioc.severity}
                      color={ioc.severity === 'critical' || ioc.severity === 'high' ? 'error' : ioc.severity === 'medium' ? 'warning' : 'info'}
                    />
                    <StatusChip label={`Confidence: ${ioc.confidence_score}`} color="default" />
                  </Box>
                </Box>
                {ioc.description && (
                  <Typography variant="body2" color="text.secondary">
                    {ioc.description}
                  </Typography>
                )}
              </Box>
            ))}
          </Stack>
        </SectionCard>
      )}

      <SectionCard title="Data Details">
        <Stack spacing={2}>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Typography variant="h6">OCSF Normalized Data</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box
                component="pre"
                sx={{
                  background: 'rgba(0,0,0,0.2)',
                  p: 2,
                  overflow: 'auto',
                  borderRadius: 2,
                  boxSizing: 'border-box',
                  color: 'text.primary',
                  fontFamily: 'monospace'
                }}
              >
                {formatJson(alert.ocsf_data)}
              </Box>
            </AccordionDetails>
          </Accordion>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMore />}>
              <Typography variant="h6">Raw Alert Data</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box
                component="pre"
                sx={{
                  background: 'rgba(0,0,0,0.2)',
                  p: 2,
                  overflow: 'auto',
                  borderRadius: 2,
                  boxSizing: 'border-box',
                  color: 'text.primary',
                  fontFamily: 'monospace'
                }}
              >
                {formatJson(alert.raw_data)}
              </Box>
            </AccordionDetails>
          </Accordion>
        </Stack>
      </SectionCard>
    </Stack>
  )
}

export default AlertDetail
