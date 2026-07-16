import React, { useEffect, useMemo, useState } from 'react'
import {
  Alert as MuiAlert,
  Box,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Container,
  Grid,
  List,
  ListItem,
  ListItemText,
  Typography,
} from '@mui/material'
import {
  Classification,
  FeedbackResponse,
  FeedbackStats,
  getFeedbackStats,
  getIncidentFeedback,
  getIncidents,
} from '../services/api'
import { formatDateTimePKT } from '../utils/time'

interface FeedbackHistoryItem extends FeedbackResponse {
  incidentTitle: string
}

const classificationColors: Record<Classification, 'error' | 'success' | 'info'> = {
  TRUE_POSITIVE: 'error',
  FALSE_POSITIVE: 'success',
  BENIGN: 'info',
}

const Feedback: React.FC = () => {
  const [feedbackStats, setFeedbackStats] = useState<FeedbackStats | null>(null)
  const [history, setHistory] = useState<FeedbackHistoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const fetchFeedback = async () => {
      try {
        setError('')
        setLoading(true)
        const [statsResponse, incidentsResponse] = await Promise.all([
          getFeedbackStats(),
          getIncidents(1, 100),
        ])
        const historyItems = await Promise.all(
          incidentsResponse.items.map(async (incident) => {
            const items = await getIncidentFeedback(incident.id)
            return items.map((entry) => ({ ...entry, incidentTitle: incident.title }))
          })
        )

        const flattened = historyItems.flat().sort(
          (left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime()
        )
        setFeedbackStats(statsResponse)
        setHistory(flattened)
      } catch (err) {
        setError('Failed to load feedback history')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    fetchFeedback()
  }, [])

  const falsePositiveRate = useMemo(() => {
    if (!feedbackStats?.total_reviewed) return '0.0%'
    return `${((feedbackStats.false_positives / feedbackStats.total_reviewed) * 100).toFixed(1)}%`
  }, [feedbackStats])

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 8 }}>
        <CircularProgress />
      </Box>
    )
  }

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" gutterBottom>
        Feedback
      </Typography>
      {error && <MuiAlert severity="error" sx={{ mt: 2 }}>{error}</MuiAlert>}
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>True Positives</Typography>
              <Typography variant="h3" color="error.main">{feedbackStats?.true_positives || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>False Positives</Typography>
              <Typography variant="h3" color="success.main">{feedbackStats?.false_positives || 0}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>Accuracy</Typography>
              <Typography variant="h3" color="info.main">
                {feedbackStats ? `${feedbackStats.accuracy_percentage.toFixed(1)}%` : '0.0%'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>False Positive Rate</Typography>
              <Typography variant="h3" color="warning.main">{falsePositiveRate}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Analyst Verdict History
              </Typography>
              {history.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  No analyst verdicts submitted yet.
                </Typography>
              ) : (
                <List disablePadding>
                  {history.map((entry) => (
                    <ListItem key={entry.id} disableGutters>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                            <Typography variant="body1" fontWeight={600}>
                              {entry.incidentTitle}
                            </Typography>
                            <Chip
                              label={entry.classification.replace('_', ' ')}
                              size="small"
                              color={classificationColors[entry.classification]}
                            />
                          </Box>
                        }
                        secondary={
                          <>
                            <Typography component="span" variant="body2" color="text.primary" sx={{ display: 'block', mt: 0.5 }}>
                              {entry.comment || 'No comment provided.'}
                            </Typography>
                            <Typography component="span" variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                              {entry.user?.full_name || entry.user?.email || 'Unknown analyst'} • {formatDateTimePKT(entry.created_at)}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  )
}

export default Feedback
