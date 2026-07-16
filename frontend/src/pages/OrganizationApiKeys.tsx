import React, { useEffect, useState } from 'react'
import { Box, Card, CardContent, Chip, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { ErrorState, LoadingState, PageHeader } from '../components/ui'
import { getCurrentOrganization, getOrganizationApiKeys } from '../services/api'

interface ApiKeyInventory {
  collectors?: Array<Record<string, any>>
  alert_sources?: Array<Record<string, any>>
}

const OrganizationApiKeys: React.FC = () => {
  const [inventory, setInventory] = useState<ApiKeyInventory>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      setError(null)
      const org = await getCurrentOrganization()
      setInventory(await getOrganizationApiKeys(org.id) as ApiKeyInventory)
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Failed to load API key inventory')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorState message={error} onRetry={load} />

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader title="API Keys" description="Review organization collector tokens and source keys without exposing secret values" />
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>Collectors</Typography>
          <Table size="small">
            <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Type</TableCell><TableCell>Status</TableCell><TableCell>Token</TableCell></TableRow></TableHead>
            <TableBody>
              {(inventory.collectors || []).map((collector) => (
                <TableRow key={collector.id}>
                  <TableCell>{collector.name}</TableCell>
                  <TableCell>{collector.type}</TableCell>
                  <TableCell>{collector.status}</TableCell>
                  <TableCell><Chip label={collector.has_token ? 'Configured' : 'Missing'} size="small" color={collector.has_token ? 'success' : 'default'} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Typography variant="h6" sx={{ mt: 4, mb: 2 }}>Alert Sources</Typography>
          <Table size="small">
            <TableHead><TableRow><TableCell>Name</TableCell><TableCell>Type</TableCell><TableCell>Enabled</TableCell><TableCell>Key</TableCell></TableRow></TableHead>
            <TableBody>
              {(inventory.alert_sources || []).map((source) => (
                <TableRow key={source.id}>
                  <TableCell>{source.name}</TableCell>
                  <TableCell>{source.type}</TableCell>
                  <TableCell>{source.enabled ? 'Yes' : 'No'}</TableCell>
                  <TableCell><Chip label={source.has_api_key ? 'Configured' : 'Missing'} size="small" color={source.has_api_key ? 'success' : 'default'} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </Box>
  )
}

export default OrganizationApiKeys
