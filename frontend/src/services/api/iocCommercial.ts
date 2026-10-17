import api from './client'

export interface DownloadedIOCReport {
  blob: Blob
  filename: string
  contentType: string
}

export interface PagedItems<T> {
  items: T[]
  total: number
}

export interface ThreatSource {
  id: string
  provider: string
  name: string
  base_url?: string
  configured: boolean
  credential_fingerprint: string
  encryption_key_version: number
  status: string
  tls_verify: boolean
  safe_metadata: Record<string, unknown>
  last_tested_at?: string
  last_successful_use_at?: string
  last_rotated_at?: string
}

export interface SyncConfiguration {
  id: string
  provider: 'taxii' | 'misp'
  name: string
  credential_id: string
  api_root: string
  collection_id?: string
  settings: Record<string, unknown>
  safe_cursor: Record<string, unknown>
  schedule_seconds?: number
  enabled: boolean
}

export interface CommercialJob {
  id: string
  status: string
  progress?: number
  provider?: string
  format?: string
  report_type?: string
  original_filename?: string
  counts?: Record<string, number>
  preview?: Record<string, unknown>
  results?: Array<Record<string, unknown>>
  manifest?: Record<string, unknown>
  checksum?: string
  error_code?: string
  created_at?: string
  expires_at?: string
}

export interface HuntJob extends CommercialJob {
  ioc_id: string
  query: Record<string, unknown>
  events_scanned: number
  matches_found: number
  truncated: boolean
  started_at?: string
  completed_at?: string
}

export interface GraphNode {
  id: string
  type: string
  label: string
  href?: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  type: string
  origin: string
  confidence: number
  evidence_count: number
}

export interface IOCGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  truncated: boolean
  limits: Record<string, number>
}

const root = '/api/v1/ioc-commercial'

export const listThreatSources = async () =>
  (await api.get<PagedItems<ThreatSource>>(`${root}/sources`)).data

export const createThreatSource = async (payload: Record<string, unknown>) =>
  (await api.post<ThreatSource>(`${root}/sources`, payload)).data

export const rotateThreatSource = async (id: string, credentials: Record<string, string>) =>
  (await api.post<ThreatSource>(`${root}/sources/${id}/rotate`, { credentials })).data

export const testThreatSource = async (id: string) =>
  (await api.post<{ connected: boolean; tested_at: string }>(`${root}/sources/${id}/test`)).data

export const updateThreatSource = async (id: string, payload: Record<string, unknown>) =>
  (await api.patch<ThreatSource>(`${root}/sources/${id}`, payload)).data

export const deleteThreatSource = async (id: string) => api.delete(`${root}/sources/${id}`)

export const listSyncConfigurations = async (provider?: string) =>
  (await api.get<PagedItems<SyncConfiguration>>(`${root}/sync/configurations`, { params: { provider } })).data

export const createSyncConfiguration = async (payload: Record<string, unknown>) =>
  (await api.post<SyncConfiguration>(`${root}/sync/configurations`, payload)).data

export const listSyncJobs = async (provider?: string) =>
  (await api.get<PagedItems<CommercialJob>>(`${root}/sync/jobs`, { params: { provider } })).data

export const runSync = async (id: string, direction = 'pull') =>
  (await api.post<CommercialJob>(`${root}/sync/configurations/${id}/run`, { direction })).data

export const cancelSync = async (id: string) =>
  (await api.post(`${root}/sync/jobs/${id}/cancel`)).data

export const uploadIOCImport = async (
  file: File,
  format: string,
  options: Record<string, unknown>,
) => {
  const body = new FormData()
  body.append('file', file)
  body.append('format_name', format)
  body.append('options_json', JSON.stringify(options))
  return (await api.post<CommercialJob>(`${root}/imports`, body, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })).data
}

export const listIOCImports = async () =>
  (await api.get<PagedItems<CommercialJob>>(`${root}/imports`)).data

export const confirmIOCImport = async (id: string) =>
  (await api.post<CommercialJob>(`${root}/imports/${id}/confirm`)).data

export const cancelIOCImport = async (id: string) =>
  (await api.post(`${root}/imports/${id}/cancel`)).data

export const listBulkActions = async () =>
  (await api.get<PagedItems<CommercialJob>>(`${root}/bulk-actions`)).data

export const createBulkAction = async (payload: Record<string, unknown>, confirmed = false) =>
  (await api.post<CommercialJob>(`${root}/bulk-actions`, payload, { params: { confirmed } })).data

export const confirmBulkAction = async (id: string) =>
  (await api.post<CommercialJob>(`${root}/bulk-actions/${id}/confirm`)).data

export const listHunts = async () =>
  (await api.get<PagedItems<HuntJob>>(`${root}/hunts`)).data

export const retryHunt = async (id: string) =>
  (await api.post<CommercialJob>(`${root}/hunts/${id}/retry`)).data

export const cancelHunt = async (id: string) =>
  (await api.post(`/api/v1/iocs/hunts/${id}/cancel`)).data

export const fetchIOCGraph = async (iocId: string, depth = 2) =>
  (await api.get<IOCGraph>(`${root}/graph/${iocId}`, { params: { depth } })).data

export const generateIOCDetection = async (iocId: string, payload: Record<string, unknown>) =>
  (await api.post<{ id: string; name: string; lifecycle_status: string }>(`${root}/detections/${iocId}`, payload)).data

export const listRecommendations = async () =>
  (await api.get<PagedItems<CommercialJob & { ioc_id: string; action: string; approval_id: string }>>(`${root}/recommendations`)).data

export const createRecommendation = async (iocId: string, payload: Record<string, unknown>) =>
  (await api.post<CommercialJob>(`${root}/recommendations/${iocId}`, payload)).data

export const listIOCReports = async () =>
  (await api.get<PagedItems<CommercialJob>>(`${root}/reports`)).data

export const createIOCReport = async (payload: Record<string, unknown>) =>
  (await api.post<CommercialJob>(`${root}/reports`, payload)).data

const safeReportFilename = (contentDisposition: string | undefined, fallback: string): string => {
  const encoded = contentDisposition?.match(/filename\*=UTF-8''([^;]+)/i)?.[1]
  const quoted = contentDisposition?.match(/filename="([^"]+)"/i)?.[1]
  const plain = contentDisposition?.match(/filename=([^;]+)/i)?.[1]
  let decoded = encoded
  if (encoded) {
    try {
      decoded = decodeURIComponent(encoded)
    } catch {
      decoded = encoded
    }
  }
  let candidate = decoded || quoted || plain || fallback
  candidate = candidate.split(/[\\/]/).pop() || fallback
  candidate = candidate.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_').trim().slice(0, 180)
  return candidate && candidate !== '.' && candidate !== '..' ? candidate : fallback
}

export const downloadIOCReport = async (job: Pick<CommercialJob, 'id' | 'format'>): Promise<DownloadedIOCReport> => {
  const fallback = `socluma-ioc-report-${job.id}.${job.format || 'bin'}`
  const response = await api.get<Blob>(`${root}/reports/${job.id}/download`, { responseType: 'blob' })
  const contentType = String(response.headers['content-type'] || response.data.type || 'application/octet-stream')
  return {
    blob: response.data.type === contentType ? response.data : new Blob([response.data], { type: contentType }),
    filename: safeReportFilename(response.headers['content-disposition'], fallback),
    contentType,
  }
}

export const listReviewQueue = async (queue = 'new') =>
  (await api.get<PagedItems<Record<string, unknown>>>('/api/v1/iocs/review/queue', { params: { queue } })).data

export const assignIOCReview = async (iocId: string, reviewerId: string) =>
  (await api.post(`${root}/review/${iocId}/assign`, { reviewer_id: reviewerId })).data

export const decideIOCReview = async (iocId: string, payload: Record<string, unknown>) =>
  (await api.post(`${root}/review/${iocId}/decision`, payload)).data

export const getIOCReviewHistory = async (iocId: string) =>
  (await api.get<PagedItems<Record<string, unknown>>>(`${root}/review/${iocId}/history`)).data

export const listWatchlists = async () =>
  (await api.get<Array<Record<string, unknown>>>('/api/v1/iocs/watchlists')).data

export const createWatchlist = async (payload: Record<string, unknown>) =>
  (await api.post('/api/v1/iocs/watchlists', payload)).data

export const getWatchlist = async (id: string) =>
  (await api.get<Record<string, unknown>>(`${root}/watchlists/${id}`)).data

export const addWatchlistMember = async (watchlistId: string, iocId: string) =>
  (await api.post(`/api/v1/iocs/watchlists/${watchlistId}/members/${iocId}`)).data

export const removeWatchlistMember = async (watchlistId: string, iocId: string) =>
  api.delete(`/api/v1/iocs/watchlists/${watchlistId}/members/${iocId}`)

export const runWatchlistHunt = async (watchlistId: string, days = 30) =>
  (await api.post(`${root}/watchlists/${watchlistId}/hunt`, { days })).data

export const decideApproval = async (approvalId: string, decision: 'approve' | 'reject') =>
  (await api.post(`/api/v1/access-control/approvals/${approvalId}/decision`, { decision })).data
