import React, { useEffect, useState } from 'react'
import { Alert, Box, Button, Card, CardContent, Grid, MenuItem, TextField } from '@mui/material'
import { useSearchParams } from 'react-router-dom'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import { getCurrentOrganization, getOrganization, Organization, setDeletionPin, updateOrganization } from '../services/api'

const OrganizationSettings: React.FC = () => {
  const [organization, setOrganization] = useState<Organization | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [pin, setPin] = useState('')
  const [currentPassword, setCurrentPassword] = useState('')
  const [pinError, setPinError] = useState<string | null>(null)
  const [pinSaved, setPinSaved] = useState(false)
  const [pinSaving, setPinSaving] = useState(false)
  const [searchParams] = useSearchParams()

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const organizationId = searchParams.get('organizationId')
      setOrganization(organizationId ? await getOrganization(organizationId) : await getCurrentOrganization())
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load organization settings')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [searchParams])

  const save = async () => {
    if (!organization) return
    try {
      setSaveError(null)
      const updated = await updateOrganization(organization.id, {
        name: organization.name,
        description: organization.description || undefined,
        industry: organization.industry || undefined,
        country: organization.country || undefined,
        timezone: organization.timezone,
        subscription_plan: organization.subscription_plan,
        max_users: organization.max_users,
        max_collectors: organization.max_collectors,
        max_storage: organization.max_storage,
        status: organization.status,
      })
      setOrganization(updated)
      setSaved(true)
      window.setTimeout(() => setSaved(false), 2500)
    } catch (err: any) {
      setSaveError(err?.response?.data?.detail || err.message || 'Failed to save organization settings')
    }
  }
  const savePin = async () => {
    if (!organization || !/^\d{4}$/.test(pin)) {
      setPinError('PIN must contain exactly four digits')
      return
    }
    try {
      setPinSaving(true)
      setPinError(null)
      setPinSaved(false)
      await setDeletionPin(organization.id, pin, currentPassword)
      setPin('')
      setCurrentPassword('')
      setPinSaved(true)
    } catch (err: any) {
      setPinError(err?.response?.data?.detail || 'Unable to update deletion PIN')
    } finally {
      setPinSaving(false)
    }
  }

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />
  if (!organization) return <ErrorState message="Organization not found" onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1000, mx: 'auto' }}>
      <PageHeader title="Organization Settings" description="Manage identity, limits, and status for the current organization" />
      <Card sx={{ mt: 3 }}>
        <CardContent>
          {saveError && <Alert severity="error" sx={{ mb: 2 }}>{saveError}</Alert>}
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <TextField fullWidth label="Name" value={organization.name} onChange={(e) => setOrganization({ ...organization, name: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField fullWidth label="Slug" value={organization.slug} disabled />
            </Grid>
            <Grid item xs={12}>
              <TextField fullWidth multiline minRows={3} label="Description" value={organization.description || ''} onChange={(e) => setOrganization({ ...organization, description: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField fullWidth label="Industry" value={organization.industry || ''} onChange={(e) => setOrganization({ ...organization, industry: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField fullWidth label="Country" value={organization.country || ''} onChange={(e) => setOrganization({ ...organization, country: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField fullWidth label="Timezone" value={organization.timezone} onChange={(e) => setOrganization({ ...organization, timezone: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField fullWidth label="Plan" value={organization.subscription_plan} onChange={(e) => setOrganization({ ...organization, subscription_plan: e.target.value })} />
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField fullWidth type="number" label="Max Users" value={organization.max_users} onChange={(e) => setOrganization({ ...organization, max_users: Number(e.target.value) })} />
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField fullWidth type="number" label="Max Collectors" value={organization.max_collectors} onChange={(e) => setOrganization({ ...organization, max_collectors: Number(e.target.value) })} />
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField fullWidth select label="Status" value={organization.status} onChange={(e) => setOrganization({ ...organization, status: e.target.value as Organization['status'] })}>
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="suspended">Suspended</MenuItem>
                <MenuItem value="disabled">Disabled</MenuItem>
              </TextField>
            </Grid>
          </Grid>
          <Button variant="contained" sx={{ mt: 3 }} onClick={save}>{saved ? 'Saved' : 'Save Changes'}</Button>
        </CardContent>
      </Card>
      <Card sx={{ mt: 3 }}><CardContent>
        <PageHeader title="Deletion PIN" description="Owner-only confirmation required to schedule organization deletion" />
        {pinError && <Alert severity="error" sx={{ mt: 2 }}>{pinError}</Alert>}
        {pinSaved && <Alert severity="success" sx={{ mt: 2 }}>Deletion PIN updated successfully.</Alert>}
        <Grid container spacing={2} sx={{mt:1}}>
          <Grid item xs={12} sm={4}><TextField fullWidth label="Four-digit PIN" type="text" name="organization-pin-setting-code" autoComplete="off" inputProps={{inputMode:'numeric',maxLength:4,pattern:'[0-9]{4}',autoComplete:'off'}} sx={{'& input':{WebkitTextSecurity:'disc'}}} value={pin} onChange={e=>{setPin(e.target.value.replace(/\D/g,'').slice(0,4));setPinError(null);setPinSaved(false)}}/></Grid>
          <Grid item xs={12} sm={5}><TextField fullWidth label="Current login password" helperText="Use the password you sign in with, not the deletion PIN." type="password" value={currentPassword} onChange={e=>{setCurrentPassword(e.target.value);setPinError(null);setPinSaved(false)}}/></Grid>
          <Grid item xs={12} sm={3}><Button fullWidth variant="outlined" sx={{height:'56px'}} disabled={pinSaving||pin.length!==4||!currentPassword} onClick={savePin}>{pinSaving ? 'Saving…' : 'Set / Reset PIN'}</Button></Grid>
        </Grid>
      </CardContent></Card>
    </Box>
  )
}

export default OrganizationSettings
