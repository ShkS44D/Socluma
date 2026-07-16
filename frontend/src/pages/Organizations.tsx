import React, { useEffect, useState } from 'react'
import {
  Box,
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
import { Add as AddIcon, OpenInNew as OpenIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import {
  createOrganization,
  listOrganizations,
  Organization,
  OrganizationCreate,
  switchOrganization,
  getMe,
} from '../services/api'
import { useAuthStore } from '../store'

const emptyForm: OrganizationCreate = {
  name: '',
  slug: '',
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
  const { user, setUser } = useAuthStore()
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
      const org = await createOrganization(form)
      setDialogOpen(false)
      setForm(emptyForm)
      await load()
      navigate(`/organizations/settings?organizationId=${org.id}`)
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to create organization')
    }
  }

  const handleSwitch = async (organizationId: string) => {
    const tokenPair = await switchOrganization(organizationId)
    useAuthStore.getState().login(tokenPair.access_token, tokenPair.refresh_token)
    setUser(await getMe())
    navigate('/dashboard')
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader
        title="Organizations"
        description="Manage the organizations available to your account"
        actions={
          <Button startIcon={<AddIcon />} variant="contained" onClick={() => setDialogOpen(true)}>
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
                <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
                  <Chip label={org.subscription_plan} size="small" />
                  <Chip label={org.timezone} size="small" />
                  {org.id === user?.tenant_id && <Chip label="Current" color="primary" size="small" />}
                </Box>
                <Box sx={{ display: 'flex', gap: 1, mt: 3 }}>
                  <Button variant="outlined" onClick={() => navigate(`/organizations/settings?organizationId=${org.id}`)}>
                    Settings
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<OpenIcon />}
                    disabled={org.id === user?.tenant_id}
                    onClick={() => handleSwitch(org.id)}
                  >
                    Switch
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create Organization</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <TextField label="Slug" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
          <TextField label="Description" multiline minRows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <TextField label="Industry" value={form.industry} onChange={(e) => setForm({ ...form, industry: e.target.value })} />
          <TextField label="Country" value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreate} disabled={!form.name || !form.slug}>Create</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

export default Organizations
