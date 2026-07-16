import React from 'react'
import { Box, Tab, Tabs } from '@mui/material'

interface IncidentTabsProps {
  activeTab: number
  setActiveTab: (tab: number) => void
}

const IncidentTabs: React.FC<IncidentTabsProps> = ({ activeTab, setActiveTab }) => {
  const tabs = [
    'Overview',
    'Timeline',
    'Evidence',
    'Related Alerts',
    'Threat Intelligence',
    'Response Actions'
  ]

  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
      <Tabs
        value={activeTab}
        onChange={(_, newValue) => setActiveTab(newValue)}
        variant="scrollable"
        scrollButtons="auto"
      >
        {tabs.map((tab, index) => (
          <Tab key={index} label={tab} />
        ))}
      </Tabs>
    </Box>
  )
}

export default IncidentTabs
