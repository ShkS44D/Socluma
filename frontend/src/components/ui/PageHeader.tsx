import React from 'react'
import { Breadcrumbs, Link, Stack, Typography } from '@mui/material'
import { NavigateNext } from '@mui/icons-material'
import { Link as RouterLink } from 'react-router-dom'

export interface BreadcrumbItem {
  label: string
  href?: string
}

interface PageHeaderProps {
  title: string
  description?: string
  breadcrumbs?: BreadcrumbItem[]
  actions?: React.ReactNode
}

const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  breadcrumbs = [],
  actions,
}) => {
  return (
    <Stack
      direction={{ xs: 'column', md: 'row' }}
      justifyContent="space-between"
      alignItems={{ xs: 'flex-start', md: 'center' }}
      spacing={2}
    >
      <Stack spacing={1}>
        {breadcrumbs.length > 0 && (
          <Breadcrumbs separator={<NavigateNext fontSize="small" />} aria-label="breadcrumb">
            {breadcrumbs.map((item, index) =>
              item.href && index < breadcrumbs.length - 1 ? (
                <Link
                  key={`${item.label}-${item.href}`}
                  component={RouterLink}
                  to={item.href}
                  underline="hover"
                  color="text.secondary"
                >
                  {item.label}
                </Link>
              ) : (
                <Typography key={`${item.label}-${index}`} color="text.secondary" variant="body2">
                  {item.label}
                </Typography>
              )
            )}
          </Breadcrumbs>
        )}
        <div>
          <Typography variant="h4">{title}</Typography>
          {description && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {description}
            </Typography>
          )}
        </div>
      </Stack>
      {actions}
    </Stack>
  )
}

export default PageHeader
