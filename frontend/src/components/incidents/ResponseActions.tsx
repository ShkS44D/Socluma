import React from 'react'
import { Button, Paper, Stack, Typography } from '@mui/material'
import { Incident, IncidentStatus, updateIncidentStatus } from '../../services/api'

interface ResponseActionsProps {
  incident: Incident
  onStatusUpdate?: (incident: Incident) => void
}

const ResponseActions: React.FC<ResponseActionsProps> = ({ incident, onStatusUpdate }) => {
  const handleStatusUpdate = async (status: IncidentStatus) => {
    try {
      const updated = await updateIncidentStatus(incident.id, status)
      onStatusUpdate?.(updated)
    } catch (error) {
      console.error('Failed to update status:', error)
    }
  }

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>
        Response Actions
      </Typography>
      <Stack direction="row" spacing={2} flexWrap="wrap">
        <Button
          variant="contained"
          color="primary"
          disabled={incident.status === 'investigating'}
          onClick={() => handleStatusUpdate('investigating')}
        >
          Mark Investigating
        </Button>
        <Button
          variant="contained"
          color="success"
          disabled={incident.status === 'resolved' || incident.status === 'closed'}
          onClick={() => handleStatusUpdate('resolved')}
        >
          Resolve Incident
        </Button>
        <Button
          variant="contained"
          color="secondary"
          disabled={incident.status === 'closed'}
          onClick={() => handleStatusUpdate('closed')}
        >
          Close Incident
        </Button>
      </Stack>
    </Paper>
  )
}

export default ResponseActions
