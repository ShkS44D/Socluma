import React, { useEffect, useState } from 'react'
import { Box, Card, CardContent, Chip, MenuItem, Select, Switch, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import { getCurrentOrganization, listOrganizationMembers, OrganizationMembership, OrganizationRole, updateOrganizationMember } from '../services/api'

const roles: OrganizationRole[] = ['owner', 'administrator', 'soc_manager', 'analyst', 'viewer']

const OrganizationMembers: React.FC = () => {
  const [members, setMembers] = useState<OrganizationMembership[]>([])
  const [organizationId, setOrganizationId] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const org = await getCurrentOrganization()
      setOrganizationId(org.id)
      setMembers(await listOrganizationMembers(org.id))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load organization members')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const updateMember = async (member: OrganizationMembership, data: { role?: OrganizationRole; is_active?: boolean }) => {
    try {
      await updateOrganizationMember(organizationId, member.id, data)
      await load()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to update member')
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader title="Members" description="Manage organization membership, access level, and active status" />
      <Card sx={{ mt: 3 }}>
        <CardContent sx={{ p: 0 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Active</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {members.map((member) => (
                <TableRow key={member.id}>
                  <TableCell>{member.user?.full_name || member.user_id}</TableCell>
                  <TableCell>{member.user?.email || '-'}</TableCell>
                  <TableCell>
                    <Select size="small" value={member.role} onChange={(e) => updateMember(member, { role: e.target.value as OrganizationRole })}>
                      {roles.map((role) => <MenuItem key={role} value={role}>{role}</MenuItem>)}
                    </Select>
                  </TableCell>
                  <TableCell><Chip label={member.is_active ? 'Active' : 'Inactive'} color={member.is_active ? 'success' : 'default'} size="small" /></TableCell>
                  <TableCell><Switch checked={member.is_active} onChange={(e) => updateMember(member, { is_active: e.target.checked })} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </Box>
  )
}

export default OrganizationMembers
