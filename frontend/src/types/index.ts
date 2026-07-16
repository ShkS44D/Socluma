export interface HealthCheck {
  status: string
  database: string
  redis: string
  request_id?: string
  service?: string
  version?: string
  environment?: string
  timestamp?: string
  checks?: Record<string, {
    status: string
    latency_ms?: number
    detail?: string
  }>
}
