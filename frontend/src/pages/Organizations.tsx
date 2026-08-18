import React, { useEffect, useState } from 'react'
import {
  Box,
  Alert,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid,
  TextField,
  Typography,
} from '@mui/material'
import { Add as AddIcon, DeleteOutline as DeleteIcon, OpenInNew as OpenIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import {
  createOrganization,
  cancelOrganizationDeletion,
  deleteOrganization,
  listOrganizations,
  Organization,
  OrganizationCreate,
  switchOrganization,
  getMe,
} from '../services/api'
import { useAuthStore, usePermissionStore } from '../store'

const emptyForm: OrganizationCreate = {
  name: '',
  slug: '',
  deletion_pin: '',
  description: '',
  industry: '',
  country: '',
  timezone: 'UTC',
  subscription_plan: 'starter',
  max_users: 25,
  max_collectors: 25,
  max_storage: 10737418240,
}

const Organizations: React.FC = () => {
  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [form, setForm] = useState<OrganizationCreate>(emptyForm)
  const [createError, setCreateError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Organization | null>(null)
  const [deletionPin, setDeletionPin] = useState('')
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const { user, setUser } = useAuthStore()
  const can = usePermissionStore((state) => state.can)
  const navigate = useNavigate()

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      setOrganizations(await listOrganizations())
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load organizations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleCreate = async () => {
    try {
      setCreating(true)
      setCreateError(null)
      const org = await createOrganization(form)
      setDialogOpen(false)
      setForm(emptyForm)
      await load()
      navigate(`/organizations/settings?organizationId=${org.id}`)
    } catch (err: any) {
      setCreateError(err?.response?.data?.detail || err.message || 'Failed to create organization')
    } finally {
      setCreating(false)
    }
  }

  const handleSwitch = async (organizationId: string) => {
    const tokenPair = await switchOrganization(organizationId)
    useAuthStore.getState().login(tokenPair.access_token, tokenPair.refresh_token)
    setUser(await getMe())
    navigate('/dashboard')
  }

  const openDeleteDialog = (organization: Organization) => {
    setDeleteTarget(organization)
    setDeletionPin('')
    setDeleteError(null)
  }

  const closeDeleteDialog = () => {
    if (deleting) return
    setDeleteTarget(null)
    setDeletionPin('')
    setDeleteError(null)
  }

  const handleDelete = async () => {
    if (!deleteTarget || !/^\d{4}$/.test(deletionPin)) return
    try {
      setDeleting(true)
      setDeleteError(null)
      await deleteOrganization(deleteTarget.id, deletionPin)
      setDeleteTarget(null)
      setDeletionPin('')
      await load()
    } catch (err: any) {
      setDeleteError(err?.response?.data?.detail || 'Unable to delete organization')
    } finally {
      setDeleting(false)
    }
  }

  const handleCancelDeletion = async (organizationId: string) => {
    try {
      setError(null)
      await cancelOrganizationDeletion(organizationId)
      await load()
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Unable to cancel scheduled deletion')
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader
        title="Organizations"
        description="Manage the organizations available to your account"
        actions={
          <Button startIcon={<AddIcon />} variant="contained" onClick={() => { setCreateError(null); setDialogOpen(true) }}>
            New Organization
          </Button>
        }
      />
      <Grid container spacing={3} sx={{ mt: 1 }}>
        {organizations.map((org) => (
          <Grid item xs={12} md={6} key={org.id}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
                  <Box>
                    <Typography variant="h6">{org.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{org.slug}</Typography>
                  </Box>
                  <Chip label={org.status} color={org.status === 'active' ? 'success' : 'default'} size="small" />
                </Box>
                <Typography variant="body2" sx={{ mt: 2, minHeight: 40 }}>
                  {org.description || 'No description configured'}
                </Typography>
                {org.status === 'pending_deletion' && (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    Deletion scheduled{org.scheduled_purge_at ? ` for ${new Date(org.scheduled_purge_at).toLocaleString()}` : ''}.
                    Normal organization access is disabled during the cooling-off period.
                  </Alert>
                )}
                <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
                  <Chip label={org.subscription_plan} size="small" />
                  <Chip label={org.timezone} size="small" />
                  {org.id === user?.tenant_id && <Chip label="Current" color="primary" size="small" />}
                </Box>
                <Box sx={{ display: 'flex', gap: 1, mt: 3, flexWrap: 'wrap' }}>
                  {org.id === user?.tenant_id && can('organization.update') && <Button variant="outlined" onClick={() => navigate(`/organizations/settings?organizationId=${org.id}`)}>
                    Settings
                  </Button>}
                  <Button
                    variant="outlined"
                    startIcon={<OpenIcon />}
                    disabled={org.id === user?.tenant_id || org.status !== 'active'}
                    onClick={() => handleSwitch(org.id)}
                  >
                    Switch
                  </Button>
                  {org.id === user?.tenant_id && can('organization.delete') && <Button
                    variant="outlined"
                    color="error"
                    startIcon={<DeleteIcon />}
                    disabled={org.status !== 'active'}
                    onClick={() => openDeleteDialog(org)}
                  >
                    Schedule deletion
                  </Button>}
                  {org.status === 'pending_deletion' && can('organization.delete.cancel') && (
                    <Button variant="outlined" color="warning" onClick={() => handleCancelDeletion(org.id)}>
                      Cancel deletion
                    </Button>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Organization</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          {createError && <Alert severity="error">{createError}</Alert>}
          <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <TextField label="Slug" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
          <TextField
            label="Four-digit deletion PIN"
            required
            type="text"
            name="new-organization-deletion-code"
            autoComplete="off"
            value={form.deletion_pin}
            helperText="Required when deleting this organization."
            inputProps={{ inputMode: 'numeric', maxLength: 4, pattern: '[0-9]{4}', autoComplete: 'off' }}
            sx={{ '& input': { WebkitTextSecurity: 'disc' } }}
            onChange={(e) => setForm({ ...form, deletion_pin: e.target.value.replace(/\D/g, '').slice(0, 4) })}
          />
          <TextField label="Description" multiline minRows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <TextField label="Industry" value={form.industry} onChange={(e) => setForm({ ...form, industry: e.target.value })} />
          <TextField label="Country" value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)} disabled={creating}>Cancel</Button>
          <Button variant="contained" onClick={handleCreate} disabled={creating || !form.name || !form.slug || form.deletion_pin.length !== 4}>{creating ? 'Creating…' : 'Create'}</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onClose={closeDeleteDialog} maxWidth="xs" fullWidth>
        <DialogTitle>Schedule Organization Deletion</DialogTitle>
        <DialogContent>
          <Typography sx={{ mb: 2 }}>
            Enter the four-digit deletion PIN to schedule deletion of <strong>{deleteTarget?.name}</strong>.
            Access is disabled immediately. An owner can cancel during the cooling-off period before permanent purge.
          </Typography>
          {deleteError && <Alert severity="error" sx={{ mb: 2 }}>{deleteError}</Alert>}
          <TextField
            autoFocus
            fullWidth
            required
            label="Deletion PIN"
            type="text"
            name="organization-deletion-confirmation-code"
            autoComplete="off"
            value={deletionPin}
            inputProps={{ inputMode: 'numeric', maxLength: 4, pattern: '[0-9]*', autoComplete: 'off' }}
            sx={{ '& input': { WebkitTextSecurity: 'disc' } }}
            onChange={(event) => setDeletionPin(event.target.value.replace(/\D/g, '').slice(0, 4))}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && deletionPin.length === 4) void handleDelete()
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDeleteDialog} disabled={deleting}>Cancel</Button>
          <Button
            variant="contained"
            color="error"
            disabled={deleting || deletionPin.length !== 4}
            onClick={handleDelete}
          >
            {deleting ? 'Scheduling…' : 'Schedule Deletion'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default Organizations
