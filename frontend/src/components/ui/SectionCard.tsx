import React from 'react'
import { Card, CardContent, Stack, Typography } from '@mui/material'

interface SectionCardProps {
  title: string
  subtitle?: string
  action?: React.ReactNode
  icon?: React.ReactNode
  children: React.ReactNode
  contentSx?: object
}

const SectionCard: React.FC<SectionCardProps> = ({
  title,
  subtitle,
  action,
  icon,
  children,
  contentSx,
}) => {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent sx={{ height: '100%', p: 3, ...contentSx }}>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2} sx={{ mb: 3 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            {icon && <div>{icon}</div>}
            <div>
              <Typography variant="h6">{title}</Typography>
              {subtitle && (
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                  {subtitle}
                </Typography>
              )}
            </div>
          </Stack>
          {action}
        </Stack>
        {children}
      </CardContent>
    </Card>
  )
}

export default SectionCard
