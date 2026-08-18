import { useEffect, useState } from 'react'
import { Alert, Chip, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { Link, useParams } from 'react-router-dom'
import { getEntity, getEntityGraph, getEntityTimeline } from '../services/api/search'

export default function EntityDetail() {
  const { entityId = '' } = useParams()
  const [entity, setEntity] = useState<any>()
  const [timeline, setTimeline] = useState<any[]>([])
  const [graph, setGraph] = useState<any>()
  const [error, setError] = useState('')
  useEffect(() => {
    Promise.all([getEntity(entityId), getEntityTimeline(entityId), getEntityGraph(entityId)])
      .then(([item, events, relationships]) => { setEntity(item); setTimeline(events.items); setGraph(relationships) })
      .catch((err) => setError(err?.response?.data?.detail?.message || 'Unable to load entity.'))
  }, [entityId])
  return <Stack spacing={3}>
    {error && <Alert severity="error">{error}</Alert>}
    <Paper sx={{ p: 2 }}>
      <Typography variant="overline">Extracted entity</Typography>
      <Typography variant="h4">{entity?.display_value || 'Loading…'}</Typography>
      {entity && <Stack direction="row" spacing={1} mt={1}><Chip label={entity.entity_type} /><Chip label={`${entity.sighting_count} sightings`} /></Stack>}
    </Paper>
    <Paper sx={{ p: 2 }}>
      <Typography variant="h6">Relationship graph</Typography>
      <Typography color="text.secondary">{graph?.nodes?.length || 0} nodes · {graph?.edges?.length || 0} observed relationships{graph?.truncated ? ' · bounded result' : ''}</Typography>
      <Stack direction="row" flexWrap="wrap" gap={1} mt={2}>{graph?.nodes?.map((node: any) => <Chip key={node.id} label={`${node.type}: ${node.label}`} />)}</Stack>
    </Paper>
    <Paper sx={{ p: 2 }}>
      <Typography variant="h6">Evidence timeline</Typography>
      <Table size="small"><TableHead><TableRow><TableCell>Time</TableCell><TableCell>Event</TableCell><TableCell>Severity</TableCell></TableRow></TableHead>
        <TableBody>{timeline.map((item) => <TableRow key={item.id}><TableCell>{new Date(item.timestamp).toLocaleString()}</TableCell><TableCell><Link to={item.path}>{item.title}</Link></TableCell><TableCell>{item.severity}</TableCell></TableRow>)}</TableBody>
      </Table>
    </Paper>
  </Stack>
}
