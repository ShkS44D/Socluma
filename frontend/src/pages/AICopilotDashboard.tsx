import React from 'react'
import { Box, Button, Card, CardContent, Grid, Typography } from '@mui/material'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '../components/ui'

const cards = [
  ['VigilantAI Copilot', '/ai/incident-copilot', 'Ask incident-scoped questions and generate summaries.'],
  ['AI Reports', '/ai/reports', 'Generate executive and technical incident reports.'],
  ['Timeline Viewer', '/ai/timeline', 'Build an investigation timeline from incident evidence.'],
  ['Alert Explanation', '/ai/alert-explanation', 'Explain why an alert triggered and how to triage it.'],
  ['IOC Analysis', '/ai/ioc-analysis', 'Analyze indicators with enrichment and hunting guidance.'],
  ['Detection Suggestions', '/ai/detection-suggestions', 'Suggest Sigma-style detections from recent incidents.'],
  ['Playbook Suggestions', '/ai/playbook-suggestions', 'Suggest playbooks for repeatable response.'],
]

const AICopilotDashboard: React.FC = () => {
  const navigate = useNavigate()
  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader title="VigilantAI Copilot" description="Tenant-scoped investigation assistance for SOC analysts" />
      <Grid container spacing={3} sx={{ mt: 1 }}>
        {cards.map(([title, path, description]) => (
          <Grid item xs={12} md={6} lg={4} key={path}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6">{title}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1, minHeight: 48 }}>{description}</Typography>
                <Button variant="outlined" sx={{ mt: 3 }} onClick={() => navigate(path)}>Open</Button>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  )
}

export default AICopilotDashboard
