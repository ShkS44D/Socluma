import React, { useEffect, useState } from 'react'
import { Box, Button, Card, CardContent, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Grid, TextField, Typography } from '@mui/material'
import { createCustomRole, CustomRole, deleteCustomRole, listCustomRoles, listPermissions, PermissionDescriptor } from '../services/api'
import { PageHeader } from '../components/ui'
import { usePermissionStore } from '../store'

const OrganizationRoles: React.FC = () => {
  const [roles, setRoles] = useState<CustomRole[]>([]), [permissions, setPermissions] = useState<PermissionDescriptor[]>([])
  const [open, setOpen] = useState(false), [name, setName] = useState(''), [selected, setSelected] = useState<string[]>([])
  const load = async () => { setRoles(await listCustomRoles()); setPermissions(await listPermissions()) }
  useEffect(() => { void load() }, [])
  const can = usePermissionStore((state) => state.can)
  const create = async () => { await createCustomRole({ name, permissions: selected }); setOpen(false); setName(''); setSelected([]); await load() }
  return <Box>
    <PageHeader title="Roles & Permissions" description="Create least-privilege roles. Built-in owner privileges remain protected."
      actions={can('roles.create') ? <Button variant="contained" onClick={() => setOpen(true)}>New Custom Role</Button> : undefined} />
    <Grid container spacing={2} sx={{mt:1}}>{roles.map(role => <Grid item xs={12} md={6} key={role.id}><Card><CardContent>
      <Typography variant="h6">{role.name} {role.is_system && <Chip size="small" label="Protected" />}</Typography>
      <Typography color="text.secondary">{role.description}</Typography>
      <Box sx={{display:'flex',gap:.5,flexWrap:'wrap',mt:2}}>{role.permissions.map(p => <Chip size="small" key={p} label={p}/>)}</Box>
      {!role.is_system && !role.is_protected && can('roles.delete') && <Button color="error" sx={{mt:2}} onClick={async()=>{
        if (window.confirm('Delete this unassigned custom role?')) { await deleteCustomRole(role.id); await load() }
      }}>Delete</Button>}
    </CardContent></Card></Grid>)}</Grid>
    <Dialog open={open} onClose={()=>setOpen(false)} maxWidth="md" fullWidth><DialogTitle>Create custom role</DialogTitle><DialogContent>
      <TextField fullWidth label="Role name" value={name} onChange={e=>setName(e.target.value)} sx={{my:2}}/>
      {[...new Set(permissions.map((permission) => permission.category))].map((category) => <Box key={category} sx={{ mb: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>{category}</Typography>
        <Grid container>{permissions.filter((permission) => permission.category === category).map(permission =>
          <Grid item xs={12} sm={6} key={permission.identifier}><FormControlLabel control={<Checkbox
            disabled={permission.owner_only}
            checked={selected.includes(permission.identifier)}
            onChange={event=>setSelected(event.target.checked?[...selected,permission.identifier]:selected.filter(value=>value!==permission.identifier))}/>}
            label={`${permission.identifier} — ${permission.description}${permission.owner_only ? ' (Owner only)' : ''}`}/></Grid>)}</Grid>
      </Box>)}
    </DialogContent><DialogActions><Button onClick={()=>setOpen(false)}>Cancel</Button><Button variant="contained" disabled={name.length<2} onClick={create}>Create</Button></DialogActions></Dialog>
  </Box>
}
export default OrganizationRoles
