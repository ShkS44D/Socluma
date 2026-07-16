import React from 'react'
import { Box, FormControl, InputLabel, MenuItem, Select, Stack, TextField } from '@mui/material'

interface FilterBarProps {
  search?: string
  onSearchChange?: (value: string) => void
  severity?: string
  onSeverityChange?: (value: string) => void
  status?: string
  onStatusChange?: (value: string) => void
  priority?: string
  onPriorityChange?: (value: string) => void
  dateFrom?: string
  onDateFromChange?: (value: string) => void
  dateTo?: string
  onDateToChange?: (value: string) => void
}

const FilterBar: React.FC<FilterBarProps> = ({
  search,
  onSearchChange,
  severity,
  onSeverityChange,
  status,
  onStatusChange,
  priority,
  onPriorityChange,
  dateFrom,
  onDateFromChange,
  dateTo,
  onDateToChange,
}) => {
  return (
    <Box
      sx={{
        p: 2,
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 3,
        backgroundColor: 'background.paper',
      }}
    >
      <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
        {onSearchChange && (
          <TextField
            label="Search"
            value={search || ''}
            onChange={(event) => onSearchChange(event.target.value)}
            fullWidth
          />
        )}
        {onDateFromChange && (
          <TextField
            label="From"
            type="date"
            value={dateFrom || ''}
            onChange={(event) => onDateFromChange(event.target.value)}
            InputLabelProps={{ shrink: true }}
          />
        )}
        {onDateToChange && (
          <TextField
            label="To"
            type="date"
            value={dateTo || ''}
            onChange={(event) => onDateToChange(event.target.value)}
            InputLabelProps={{ shrink: true }}
          />
        )}
        {onSeverityChange && (
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select
              label="Severity"
              value={severity || ''}
              onChange={(event) => onSeverityChange(event.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="critical">Critical</MenuItem>
            </Select>
          </FormControl>
        )}
        {onStatusChange && (
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              label="Status"
              value={status || ''}
              onChange={(event) => onStatusChange(event.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="open">Open</MenuItem>
              <MenuItem value="investigating">Investigating</MenuItem>
              <MenuItem value="resolved">Resolved</MenuItem>
              <MenuItem value="closed">Closed</MenuItem>
            </Select>
          </FormControl>
        )}
        {onPriorityChange && (
          <FormControl sx={{ minWidth: 150 }}>
            <InputLabel>Priority</InputLabel>
            <Select
              label="Priority"
              value={priority || ''}
              onChange={(event) => onPriorityChange(event.target.value)}
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="p1">P1</MenuItem>
              <MenuItem value="p2">P2</MenuItem>
              <MenuItem value="p3">P3</MenuItem>
              <MenuItem value="p4">P4</MenuItem>
            </Select>
          </FormControl>
        )}
      </Stack>
    </Box>
  )
}

export default FilterBar
