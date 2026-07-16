import React, { useEffect, useState } from 'react'
import { Box, Card, CardContent, Grid, LinearProgress, Typography } from '@mui/material'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import { getCurrentOrganization, getOrganizationSubscription, SubscriptionInfo } from '../services/api'

const OrganizationSubscription: React.FC = () => {
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const org = await getCurrentOrganization()
      setSubscription(await getOrganizationSubscription(org.id))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load subscription')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />
  if (!subscription) return <ErrorState message="Subscription unavailable" onRetry={load} />

  const usageRows = [
    ['Users', subscription.usage.user_count, subscription.limits.max_users],
    ['Collectors', subscription.usage.collector_count, subscription.limits.max_collectors],
  ] as const

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto' }}>
      <PageHeader title="Subscription" description="Current plan and enforced organization limits" />
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h5">{subscription.plan}</Typography>
          <Grid container spacing={3} sx={{ mt: 1 }}>
            {usageRows.map(([label, used, limit]) => {
              const percent = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0
              return (
                <Grid item xs={12} key={label}>
                  <Typography variant="body2" sx={{ mb: 1 }}>{label}: {used} of {limit}</Typography>
                  <LinearProgress variant="determinate" value={percent} />
                </Grid>
              )
            })}
          </Grid>
        </CardContent>
      </Card>
    </Box>
  )
}

export default OrganizationSubscription
