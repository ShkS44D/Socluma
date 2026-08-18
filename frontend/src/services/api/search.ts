import api from './client'

export type SearchResource = 'events' | 'alerts' | 'incidents' | 'entities'

export interface SearchField {
  name: string
  type: string
  operators: string[]
  sortable: boolean
  description?: string
  example?: string
}

export interface SearchResultItem {
  id: string
  type: string
  timestamp?: string
  title: string
  severity?: string
  status?: string
  entity_type?: string
  path: string
  [key: string]: unknown
}

export interface SearchResults {
  query_id: string
  items: SearchResultItem[]
  page: number
  page_size: number
  result_count: number
  total_count: number
  has_next: boolean
  execution_time_ms: number
}

export interface SavedSearch {
  id: string
  name: string
  display_query: string
  resource_scope: SearchResource
  visibility: string
  pinned: boolean
}

export interface Investigation {
  id: string
  title: string
  description?: string
  status: string
  priority: string
  created_at: string
  updated_at: string
}

export const getSearchFields = async () =>
  (await api.get<{ fields: SearchField[] }>('/api/v1/search/fields')).data.fields

export const runSearch = async (payload: {
  query: string
  resource_scope: SearchResource
  page: number
  page_size?: number
}) => (await api.post<SearchResults>('/api/v1/search', payload)).data

export const getSearchHistory = async () =>
  (await api.get<Array<{ id: string; display_query: string; resource_scope: SearchResource; created_at: string }>>('/api/v1/search/history')).data

export const getSavedSearches = async () =>
  (await api.get<SavedSearch[]>('/api/v1/search/saved')).data

export const saveSearch = async (payload: {
  name: string
  query: string
  resource_scope: SearchResource
}) => (await api.post<SavedSearch>('/api/v1/search/saved', payload)).data

export const getSearchTemplates = async () =>
  (await api.get<Array<{ id: string; name: string; description?: string; display_query: string; resource_scope: SearchResource }>>('/api/v1/search/templates')).data

export const getEntity = async (id: string) =>
  (await api.get<Record<string, unknown>>(`/api/v1/entities/${id}`)).data

export const getEntityTimeline = async (id: string) =>
  (await api.get<{ items: SearchResultItem[] }>(`/api/v1/entities/${id}/timeline`)).data

export const getEntityGraph = async (id: string) =>
  (await api.get<{ nodes: Array<{ id: string; type: string; label: string }>; edges: Array<{ id: string; source: string; target: string; type: string }>; truncated: boolean }>(`/api/v1/entities/${id}/graph`)).data

export const listInvestigations = async () =>
  (await api.get<Investigation[]>('/api/v1/investigations')).data

export const createInvestigation = async (payload: { title: string; description?: string }) =>
  (await api.post<Investigation>('/api/v1/investigations', payload)).data

export const getInvestigation = async (id: string) =>
  (await api.get<Record<string, any>>(`/api/v1/investigations/${id}`)).data

export const addInvestigationNote = async (id: string, content: string) =>
  (await api.post(`/api/v1/investigations/${id}/notes`, { content, tags: [], pinned: false })).data
