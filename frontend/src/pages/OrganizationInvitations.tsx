import React, { useEffect, useState } from 'react'
import { Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Select, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { Add as AddIcon } from '@mui/icons-material'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import { createOrganizationInvitation, getCurrentOrganization, listOrganizationInvitations, OrganizationInvitation, OrganizationRole } from '../services/api'

const OrganizationInvitations: React.FC = () => {
  const [organizationId, setOrganizationId] = useState('')
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<OrganizationRole>('analyst')
  const [createdToken, setCreatedToken] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const org = await getCurrentOrganization()
      setOrganizationId(org.id)
      setInvitations(await listOrganizationInvitations(org.id))
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load invitations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const createInvitation = async () => {
    try {
      const invitation = await createOrganizationInvitation(organizationId, { email, role })
      setCreatedToken(invitation.token || null)
      setEmail('')
      setRole('analyst')
      await load()
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to create invitation')
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader
        title="Invitations"
        description="Invite users to the current organization"
        actions={<Button startIcon={<AddIcon />} variant="contained" onClick={() => setDialogOpen(true)}>Invite User</Button>}
      />
      {createdToken && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="subtitle2">Invitation token</Typography>
            <Typography variant="body2" sx={{ wordBreak: 'break-all', mt: 1 }}>{createdToken}</Typography>
          </CardContent>
        </Card>
      )}
      <Card sx={{ mt: 3 }}>
        <CardContent sx={{ p: 0 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Expires</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {invitations.map((invitation) => (
                <TableRow key={invitation.id}>
                  <TableCell>{invitation.email}</TableCell>
                  <TableCell>{invitation.role}</TableCell>
                  <TableCell><Chip label={invitation.status} size="small" color={invitation.status === 'pending' ? 'primary' : 'default'} /></TableCell>
                  <TableCell>{new Date(invitation.expires_at).toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Invite User</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          <TextField label="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <Select value={role} onChange={(e) => setRole(e.target.value as OrganizationRole)}>
            {['administrator', 'soc_manager', 'analyst', 'viewer'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
          </Select>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!email} onClick={createInvitation}>Create</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default OrganizationInvitations
