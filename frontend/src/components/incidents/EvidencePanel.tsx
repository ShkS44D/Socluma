import React from 'react'
import { Box, Paper, Typography } from '@mui/material'
import StatusChip from '../ui/StatusChip'
import { ThreatIntelResult } from '../../services/api'

interface EvidencePanelProps {
  evidence: ThreatIntelResult[]
}

const EvidencePanel: React.FC<EvidencePanelProps> = ({ evidence }) => {
  if (evidence.length === 0) {
    return <Typography variant="body2" color="text.secondary">No evidence available.</Typography>
  }

  return (
    <Box sx={{ display: 'grid', gap: 2 }}>
      {evidence.map((item) => (
        <Paper key={`${item.source}-${item.indicator}`} sx={{ p: 2 }}>
          <Typography variant="h6">{item.indicator}</Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
            <StatusChip label={`Type: ${item.type}`} />
            <StatusChip label={`Source: ${item.source}`} />
            <StatusChip label={`Risk Impact: +${item.risk_impact}`} />
          </Box>
          {item.result?.reputation && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Reputation: {String(item.result.reputation)}
            </Typography>
          )}
        </Paper>
      ))}
    </Box>
  )
}

export default EvidencePanel
