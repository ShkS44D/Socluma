import React from 'react'
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Paper,
  Typography,
} from '@mui/material'
import { AutoAwesome as AIIcon } from '@mui/icons-material'
import { ThreatIntelResult } from '../../services/api'
import { formatDateTime } from '../../utils'

interface AIAnalysisPanelProps {
  summary?: string | null
  why_suspicious?: string | null
  aiAnalyzedAt?: string | null
  attackTechnique?: Record<string, any> | null
  recommendedActions?: string[] | null
  threatIntelResults?: ThreatIntelResult[] | null
  analyzing?: boolean
  canAnalyze?: boolean
  onAnalyze?: () => void
}

const AIAnalysisPanel: React.FC<AIAnalysisPanelProps> = ({
  summary,
  why_suspicious,
  aiAnalyzedAt,
  attackTechnique,
  recommendedActions,
  threatIntelResults,
  analyzing = false,
  canAnalyze = false,
  onAnalyze,
}) => {
  const hasAnalysis = Boolean(summary || why_suspicious || attackTechnique)

  return (
    <Box sx={{ display: 'grid', gap: 3 }}>
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography variant="h6">AI Investigation Summary</Typography>
            {aiAnalyzedAt && (
              <Typography variant="caption" color="text.secondary">
                Last analyzed: {formatDateTime(aiAnalyzedAt)}
              </Typography>
            )}
          </Box>
          {canAnalyze && onAnalyze && (
            <Button
              variant="contained"
              color="secondary"
              startIcon={analyzing ? <CircularProgress size={18} color="inherit" /> : <AIIcon />}
              onClick={onAnalyze}
              disabled={analyzing}
            >
              {analyzing ? 'Analyzing...' : hasAnalysis ? 'Regenerate AI Analysis' : 'Generate AI Analysis'}
            </Button>
          )}
        </Box>
        <Typography variant="body2" sx={{ mb: 2 }}>
          {summary || 'No AI summary available yet. Click "Generate AI Analysis" to run OpenAI-powered incident analysis.'}
        </Typography>

        <Typography variant="subtitle2" gutterBottom>
          Why Suspicious
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {why_suspicious || 'Run AI analysis to generate an analyst-focused explanation.'}
        </Typography>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          MITRE ATT&CK
        </Typography>
        {attackTechnique ? (
          <>
            <Chip
              label={`${attackTechnique.technique_id || 'UNKNOWN'} - ${attackTechnique.technique_name || 'Unknown Technique'}`}
              color="warning"
              sx={{ mb: 2 }}
            />
            <Typography variant="body2" color="text.secondary">
              {attackTechnique.description || 'No MITRE description available.'}
            </Typography>
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No MITRE ATT&CK mapping available yet.
          </Typography>
        )}
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Recommended Response
        </Typography>
        {recommendedActions && recommendedActions.length > 0 ? (
          <List dense>
            {recommendedActions.map((action) => (
              <ListItem key={action} disablePadding sx={{ mb: 1 }}>
                <ListItemText primary={action} />
              </ListItem>
            ))}
          </List>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No recommended actions available yet.
          </Typography>
        )}
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Threat Intelligence
        </Typography>
        {threatIntelResults && threatIntelResults.length > 0 ? (
          <Box sx={{ display: 'grid', gap: 2 }}>
            {threatIntelResults.map((result) => (
              <Box
                key={`${result.source}-${result.indicator}`}
                sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 2 }}
              >
                <Typography variant="body2" fontWeight={600}>
                  {result.indicator}
                </Typography>
                <Typography variant="caption" display="block" color="text.secondary">
                  Type: {result.type} | Source: {result.source}
                </Typography>
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Reputation: {String(result.result?.reputation || 'unknown')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Risk impact: +{result.risk_impact}
                </Typography>
              </Box>
            ))}
          </Box>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No threat intelligence results available for this incident.
          </Typography>
        )}
      </Paper>
    </Box>
  )
}

export default AIAnalysisPanel
