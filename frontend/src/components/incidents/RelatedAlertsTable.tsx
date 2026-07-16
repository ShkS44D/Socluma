import React from 'react'
import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography
} from '@mui/material'
import { IncidentRelatedAlert } from '../../services/api'
import StatusChip from '../ui/StatusChip'
import { formatDateTimePKT } from '../../utils/time'
import {
  getAlertActivityName,
  getAlertCommandLine,
  getAlertProcessImage,
  getAlertRuleName
} from '../../utils/alertDisplay'

interface RelatedAlertsTableProps {
  alerts: IncidentRelatedAlert[]
}

const RelatedAlertsTable: React.FC<RelatedAlertsTableProps> = ({ alerts }) => {
  const formatDate = (date: string) => formatDateTimePKT(date)

  const severityColorMap: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'info'
  }

  const statusColorMap: Record<string, 'default' | 'primary' | 'secondary' | 'success' | 'error' | 'info' | 'warning'> = {
    open: 'default',
    investigating: 'primary',
    resolved: 'success',
    dismissed: 'secondary'
  }

  if (alerts.length === 0) {
    return <Typography variant="body2" color="text.secondary">No related alerts.</Typography>
  }

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Severity</TableCell>
            <TableCell>Rule</TableCell>
            <TableCell>Activity</TableCell>
            <TableCell>Process</TableCell>
            <TableCell>Created</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {alerts.map((relatedAlert) => (
            <TableRow key={relatedAlert.id} hover>
              <TableCell>
                <StatusChip
                  label={relatedAlert.alert.severity}
                  color={severityColorMap[relatedAlert.alert.severity]}
                />
              </TableCell>
              <TableCell>{getAlertRuleName(relatedAlert.alert)}</TableCell>
              <TableCell>{getAlertActivityName(relatedAlert.alert)}</TableCell>
              <TableCell>
                <Typography variant="body2">{getAlertProcessImage(relatedAlert.alert) || 'Not captured'}</Typography>
                {getAlertCommandLine(relatedAlert.alert) && (
                  <Typography variant="caption" color="text.secondary" sx={{ wordBreak: 'break-word' }}>
                    {getAlertCommandLine(relatedAlert.alert)}
                  </Typography>
                )}
              </TableCell>
              <TableCell>{formatDate(relatedAlert.alert.created_at)}</TableCell>
              <TableCell>
                <StatusChip
                  label={relatedAlert.alert.status}
                  color={statusColorMap[relatedAlert.alert.status]}
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

export default RelatedAlertsTable
