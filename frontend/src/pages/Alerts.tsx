import React from 'react'
import { Typography, Stack } from '@mui/material'
import { PageHeader, SectionCard } from '../components/ui'

const Alerts: React.FC = () => {
  return (
    <Stack spacing={6}>
      <PageHeader
        title="Alerts"
        description="Manage and triage security alerts from your monitoring systems."
        breadcrumbs={[
          { label: 'Operations', href: '/dashboard' },
          { label: 'Alerts' },
        ]}
      />
      <SectionCard title="Alert Queue">
        <Typography variant="body1" color="text.secondary">
          Alert management coming soon...
        </Typography>
      </SectionCard>
    </Stack>
  )
}

export default Alerts
