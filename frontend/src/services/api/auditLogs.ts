import api from './client'

export interface AuditLog {
  id:string; created_at:string; sequence_number?:number; actor_type:string; user_id?:string
  actor_role?:string; action:string; category:string; severity:string; resource_type?:string
  resource_id?:string; status:string; ip_address?:string; request_id?:string
  correlation_id?:string; before_values?:Record<string,unknown>; after_values?:Record<string,unknown>
  details?:Record<string,unknown>
}
export interface AuditLogPage { items: AuditLog[]; total:number; page:number; page_size:number; has_more:boolean }
export interface IntegrityResult { status:'verified'|'failed'; verified_record_count:number; first_invalid_sequence?:number; reason?:string }
export interface RetentionPolicy {
  default_retention_days:number; security_retention_days:number; administrative_retention_days:number
  authentication_retention_days:number; export_retention_days:number; archive_before_purge:boolean
  archive_retention_days:number; minimum_days?:number; maximum_days?:number
}
export interface LegalHold {
  id:string; name:string; reason:string; status:string; created_at:string; released_at?:string
  start_at?:string; end_at?:string; category_filters:string[]; resource_filters:Array<Record<string,string>>
}
export interface AuditExportJob {
  id:string; format:'csv'|'jsonl'|'evidence_zip'; status:string; record_count:number
  created_at:string; expires_at:string; completed_at?:string; checksum?:string
}

export const listAuditLogs = async (params: Record<string, string | number | undefined>) =>
  (await api.get<AuditLogPage>('/api/v1/audit-logs', { params })).data
export const verifyAuditIntegrity = async () =>
  (await api.post<IntegrityResult>('/api/v1/audit-logs/integrity/verify')).data
export const getAuditRetention = async () =>
  (await api.get<RetentionPolicy>('/api/v1/audit-logs/retention')).data
export const updateAuditRetention = async (policy: Partial<RetentionPolicy>) =>
  (await api.put<RetentionPolicy>('/api/v1/audit-logs/retention', policy)).data
export const listLegalHolds = async () =>
  (await api.get<LegalHold[]>('/api/v1/audit-logs/legal-holds')).data
export const createLegalHold = async (values: Record<string,unknown>) =>
  (await api.post<LegalHold>('/api/v1/audit-logs/legal-holds', values)).data
export const releaseLegalHold = async (id:string) =>
  (await api.post<LegalHold>(`/api/v1/audit-logs/legal-holds/${id}/release`)).data
export const listAuditExports = async () =>
  (await api.get<AuditExportJob[]>('/api/v1/audit-logs/exports')).data
export const createAuditExport = async (format:'csv'|'jsonl'|'evidence_zip', filters:Record<string,unknown>) =>
  (await api.post<{job:AuditExportJob;download_token:string}>('/api/v1/audit-logs/exports', {format,filters})).data
export const cancelAuditExport = async (id:string) =>
  (await api.post<AuditExportJob>(`/api/v1/audit-logs/exports/${id}/cancel`)).data
export const downloadAuditExport = async (job:AuditExportJob, token:string) => {
  const response = await api.get(`/api/v1/audit-logs/exports/${job.id}/download`, {params:{token},responseType:'blob'})
  const extension=job.format==='evidence_zip'?'zip':job.format
  const url=URL.createObjectURL(response.data); const link=document.createElement('a')
  link.href=url; link.download=`vigilantai-audit-${job.id}.${extension}`; link.click(); URL.revokeObjectURL(url)
}
