import React, { useEffect, useState } from 'react'
import {
  Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent,
  DialogTitle, MenuItem, Pagination, Tab, Table, TableBody, TableCell, TableHead,
  TableRow, Tabs, TextField, Typography,
} from '@mui/material'
import {
  AuditExportJob, AuditLog, LegalHold, RetentionPolicy, cancelAuditExport,
  createAuditExport, createLegalHold, downloadAuditExport, getAuditRetention,
  listAuditExports, listAuditLogs, listLegalHolds, releaseLegalHold,
  updateAuditRetention, verifyAuditIntegrity,
} from '../services/api'
import { PageHeader } from '../components/ui'
import { usePermissionStore } from '../store'

const AuditLogs: React.FC = () => {
  const can=usePermissionStore(s=>s.can)
  const [tab,setTab]=useState(0),[items,setItems]=useState<AuditLog[]>([]),[total,setTotal]=useState(0)
  const [page,setPage]=useState(1),[search,setSearch]=useState(''),[statusFilter,setStatusFilter]=useState('')
  const [category,setCategory]=useState(''),[integrity,setIntegrity]=useState<string>()
  const [policy,setPolicy]=useState<RetentionPolicy>(),[holds,setHolds]=useState<LegalHold[]>([])
  const [exports,setExports]=useState<AuditExportJob[]>([]),[tokens,setTokens]=useState<Record<string,string>>({})
  const [holdOpen,setHoldOpen]=useState(false),[holdName,setHoldName]=useState(''),[holdReason,setHoldReason]=useState('')
  const filters={search:search||undefined,status:statusFilter||undefined,category:category||undefined}
  const loadLogs=async()=>{const data=await listAuditLogs({page,page_size:50,...filters});setItems(data.items);setTotal(data.total)}
  const loadAdmin=async()=>{
    if(can('audit.view')) setPolicy(await getAuditRetention())
    if(can('audit.legal_hold.view')) setHolds(await listLegalHolds())
    if(can('audit.export')) setExports(await listAuditExports())
  }
  useEffect(()=>{void loadLogs()},[page])
  useEffect(()=>{void loadAdmin()},[])
  const requestExport=async(format:'csv'|'jsonl'|'evidence_zip')=>{
    const result=await createAuditExport(format,filters)
    setTokens(current=>({...current,[result.job.id]:result.download_token})); await loadAdmin()
  }
  const createHold=async()=>{await createLegalHold({name:holdName,reason:holdReason});setHoldOpen(false);setHoldName('');setHoldReason('');await loadAdmin()}
  return <Box>
    <PageHeader title="Audit Administration" description="Search tamper-evident activity, verify integrity, and manage protected evidence"/>
    <Tabs value={tab} onChange={(_,value)=>setTab(value)} sx={{mb:2}}>
      <Tab label="Explorer"/><Tab label="Integrity & retention"/><Tab label="Legal holds"/><Tab label="Exports"/>
    </Tabs>
    {tab===0&&<Card><CardContent>
      <Box sx={{display:'flex',gap:2,mb:2,flexWrap:'wrap'}}>
        <TextField size="small" label="Search" value={search} onChange={e=>setSearch(e.target.value)}/>
        <TextField size="small" select label="Result" value={statusFilter} onChange={e=>setStatusFilter(e.target.value)} sx={{minWidth:140}}>
          <MenuItem value="">All</MenuItem><MenuItem value="success">Success</MenuItem><MenuItem value="failure">Failure</MenuItem><MenuItem value="denied">Denied</MenuItem>
        </TextField>
        <TextField size="small" label="Category" value={category} onChange={e=>setCategory(e.target.value)}/>
        <Button onClick={()=>{setPage(1);void loadLogs()}}>Apply</Button>
      </Box>
      <Table size="small"><TableHead><TableRow><TableCell>Sequence / UTC</TableCell><TableCell>Actor</TableCell><TableCell>Action</TableCell><TableCell>Resource</TableCell><TableCell>Severity</TableCell><TableCell>Result</TableCell><TableCell>Request / correlation</TableCell></TableRow></TableHead>
        <TableBody>{items.map(item=><TableRow key={item.id}>
          <TableCell>#{item.sequence_number}<br/>{new Date(item.created_at).toISOString()}</TableCell>
          <TableCell>{item.actor_type}<br/>{item.user_id||'System'}</TableCell>
          <TableCell>{item.action}<br/><Typography variant="caption">{item.category}</Typography></TableCell>
          <TableCell>{item.resource_type||'—'} {item.resource_id||''}</TableCell>
          <TableCell><Chip size="small" label={item.severity}/></TableCell><TableCell><Chip size="small" label={item.status}/></TableCell>
          <TableCell>{item.request_id||'—'}<br/>{item.correlation_id||''}</TableCell>
        </TableRow>)}</TableBody>
      </Table>
      <Pagination sx={{mt:2}} page={page} count={Math.max(1,Math.ceil(total/50))} onChange={(_,value)=>setPage(value)}/>
    </CardContent></Card>}
    {tab===1&&<Card><CardContent>
      <Typography variant="h6">Audit integrity</Typography>
      <Typography color="text.secondary" sx={{mb:2}}>Verification detects missing or modified records. It never repairs the chain automatically.</Typography>
      {integrity&&<Alert severity={integrity.startsWith('Verified')?'success':'error'} sx={{mb:2}}>{integrity}</Alert>}
      {can('audit.integrity.verify')&&<Button variant="outlined" onClick={async()=>{const result=await verifyAuditIntegrity();setIntegrity(result.status==='verified'?`Verified ${result.verified_record_count} records`:`Failed at sequence ${result.first_invalid_sequence}: ${result.reason}`)}}>Verify integrity</Button>}
      {policy&&<Box sx={{mt:4}}><Typography variant="h6">Retention policy</Typography>
        <Alert severity="info" sx={{my:2}}>Critical audit categories must be retained for at least {policy.minimum_days} days. Active legal holds always override purge eligibility.</Alert>
        <Box sx={{display:'flex',gap:2,flexWrap:'wrap'}}>
          {(['default','security','administrative','authentication','export'] as const).map(name=>{
            const key=`${name}_retention_days` as keyof RetentionPolicy
            return <TextField key={name} type="number" label={`${name} days`} value={String(policy[key])}
              onChange={e=>setPolicy({...policy,[key]:Number(e.target.value)})}/>
          })}
        </Box>
        {can('audit.retention.manage')&&<Button sx={{mt:2}} variant="contained" onClick={async()=>{if(confirm('Apply this retention policy?'))setPolicy(await updateAuditRetention(policy))}}>Save retention policy</Button>}
      </Box>}
    </CardContent></Card>}
    {tab===2&&<Card><CardContent>
      <Box sx={{display:'flex',justifyContent:'space-between',mb:2}}><Typography variant="h6">Legal holds</Typography>
        {can('audit.legal_hold.manage')&&<Button onClick={()=>setHoldOpen(true)}>Create hold</Button>}</Box>
      <Table size="small"><TableHead><TableRow><TableCell>Name</TableCell><TableCell>Reason</TableCell><TableCell>Status</TableCell><TableCell>Created</TableCell><TableCell/></TableRow></TableHead>
        <TableBody>{holds.map(hold=><TableRow key={hold.id}><TableCell>{hold.name}</TableCell><TableCell>{hold.reason}</TableCell><TableCell>{hold.status}</TableCell><TableCell>{new Date(hold.created_at).toISOString()}</TableCell>
          <TableCell>{hold.status==='active'&&can('audit.legal_hold.manage')&&<Button color="warning" onClick={async()=>{if(confirm('Release this hold? Records are not purged until a later retention run.')){await releaseLegalHold(hold.id);await loadAdmin()}}}>Release</Button>}</TableCell>
        </TableRow>)}</TableBody></Table>
    </CardContent></Card>}
    {tab===3&&<Card><CardContent>
      {can('audit.export')&&<Box sx={{display:'flex',gap:1,mb:2}}><Button onClick={()=>requestExport('csv')}>Export CSV</Button><Button onClick={()=>requestExport('jsonl')}>Export JSONL</Button><Button onClick={()=>requestExport('evidence_zip')}>Evidence package</Button></Box>}
      <Table size="small"><TableHead><TableRow><TableCell>Created</TableCell><TableCell>Format</TableCell><TableCell>State</TableCell><TableCell>Records</TableCell><TableCell>Expires</TableCell><TableCell/></TableRow></TableHead>
        <TableBody>{exports.map(job=><TableRow key={job.id}><TableCell>{new Date(job.created_at).toISOString()}</TableCell><TableCell>{job.format}</TableCell><TableCell>{job.status}</TableCell><TableCell>{job.record_count}</TableCell><TableCell>{new Date(job.expires_at).toISOString()}</TableCell>
          <TableCell>{job.status==='completed'&&tokens[job.id]&&can('audit.export.download')&&<Button onClick={()=>downloadAuditExport(job,tokens[job.id])}>Download</Button>}
            {['pending','running'].includes(job.status)&&<Button onClick={async()=>{await cancelAuditExport(job.id);await loadAdmin()}}>Cancel</Button>}</TableCell>
        </TableRow>)}</TableBody></Table>
    </CardContent></Card>}
    <Dialog open={holdOpen} onClose={()=>setHoldOpen(false)}><DialogTitle>Create legal hold</DialogTitle><DialogContent sx={{display:'grid',gap:2,minWidth:420,pt:'12px!important'}}>
      <TextField label="Name" value={holdName} onChange={e=>setHoldName(e.target.value)}/><TextField multiline minRows={3} label="Reason" value={holdReason} onChange={e=>setHoldReason(e.target.value)}/>
    </DialogContent><DialogActions><Button onClick={()=>setHoldOpen(false)}>Cancel</Button><Button disabled={!holdName.trim()||!holdReason.trim()} onClick={createHold}>Create hold</Button></DialogActions></Dialog>
  </Box>
}
export default AuditLogs
