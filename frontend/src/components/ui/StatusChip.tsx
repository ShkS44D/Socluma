import React from 'react'
import { Chip, ChipProps } from '@mui/material'

type StatusVariant = 'severity' | 'status' | 'priority'

interface StatusChipProps {
  label: string
  color?: ChipProps['color']
  type?: StatusVariant | "hash" | "url" | "ip" | "domain" | string
  size?: ChipProps['size']
}

const toneMap: Record<StatusVariant, Record<string, ChipProps['color']>> = {
  severity: {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'info',
  },
  status: {
    open: 'default',
    investigating: 'primary',
    resolved: 'success',
    closed: 'secondary',
    dismissed: 'secondary',
  },
  priority: {
    p1: 'error',
    p2: 'warning',
    p3: 'info',
    p4: 'default',
  },
}

const typeColorMap: Record<string, ChipProps['color']> = {
  hash: 'secondary',
  url: 'info',
  ip: 'warning',
  domain: 'primary',
}

const formatLabel = (value: string) =>
  value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())

const StatusChip: React.FC<StatusChipProps> = ({
  label,
  color,
  type,
  size = 'small'
}) => {
  const normalized = label.toLowerCase()
  let chipColor: ChipProps['color'] = color || 'default'

  // If color is provided, use it
  if (!color && type) {
    // Check if type is a known StatusVariant
    if (type in toneMap) {
      chipColor = toneMap[type as StatusVariant][normalized] || 'default'
    } else if (type in typeColorMap) {
      chipColor = typeColorMap[type]
    }
  }

  return (
    <Chip
      label={formatLabel(label)}
      size={size}
      color={chipColor}
      variant={normalized === 'open' ? 'outlined' : 'filled'}
      sx={{ minWidth: 82 }}
    />
  )
}

export default StatusChip
