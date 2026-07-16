import React from 'react'
import { Box, Card, CardContent, Chip, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material'
import { PageHeader } from '../components/ui'

const roleRows = [
  { role: 'owner', access: 'Full organization administration, member management, billing limits, and deletion' },
  { role: 'administrator', access: 'Organization settings, members, invitations, and operational administration' },
  { role: 'soc_manager', access: 'Member visibility, invitations, investigations, playbooks, and SOAR operations' },
  { role: 'analyst', access: 'Security operations, investigations, playbooks, detections, and SOAR execution' },
  { role: 'viewer', access: 'Read-only operational visibility for authorized organization data' },
]

const OrganizationRoles: React.FC = () => (
  <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
    <PageHeader title="Roles" description="Built-in organization roles enforced by the backend" />
    <Card sx={{ mt: 3 }}>
      <CardContent sx={{ p: 0 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Role</TableCell>
              <TableCell>Access</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {roleRows.map((row) => (
              <TableRow key={row.role}>
                <TableCell><Chip label={row.role} size="small" /></TableCell>
                <TableCell>{row.access}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  </Box>
)

export default OrganizationRoles
