import { getStoredAuthToken } from './authStorage'

export type NotificationType = 'new_event' | 'new_alert' | 'new_incident' | 'ioc_update'

export interface NotificationData {
  id: string
  [key: string]: any
}

export interface WebSocketMessage {
  type: NotificationType
  data: NotificationData
  timestamp: string
}

type MessageHandler = (message: WebSocketMessage) => void
type ConnectionStatusHandler = (connected: boolean) => void

class WebSocketService {
  private ws: WebSocket | null = null
  private tenantId: string | null = null
  private messageHandlers: Set<MessageHandler> = new Set()
  private connectionStatusHandlers: Set<ConnectionStatusHandler> = new Set()
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000 // 1 second
  private reconnectTimer: number | null = null
  private closedByClient = false

  connect(tenantId: string) {
    if (this.ws && this.tenantId === tenantId) {
      return
    }

    this.clearReconnectTimer()
    this.closedByClient = false
    this.tenantId = tenantId
    this.attemptConnect()
  }

  private attemptConnect() {
    if (this.closedByClient || !this.tenantId) {
      return
    }

    const token = getStoredAuthToken()
    if (!token) {
      console.warn('No auth token available for WebSocket connection')
      return
    }

    const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL || window.location.origin
    const httpUrl = new URL(configuredBaseUrl, window.location.origin)
    httpUrl.protocol = httpUrl.protocol === 'https:' ? 'wss:' : 'ws:'
    httpUrl.pathname = `${httpUrl.pathname.replace(/\/$/, '')}/api/v1/ws/${this.tenantId}`
    httpUrl.search = new URLSearchParams({ token }).toString()
    const wsUrl = httpUrl.toString()

    this.ws = new WebSocket(wsUrl)

    this.ws.onopen = () => {
      this.reconnectAttempts = 0
      this.notifyConnectionStatus(true)
    }

    this.ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data)
        this.notifyMessageHandlers(message)
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    this.ws.onclose = () => {
      this.ws = null
      this.notifyConnectionStatus(false)
      if (!this.closedByClient) {
        this.attemptReconnect()
      }
    }

    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error)
    }
  }

  private attemptReconnect() {
    this.clearReconnectTimer()
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1)
      this.reconnectTimer = window.setTimeout(() => {
        this.reconnectTimer = null
        this.attemptConnect()
      }, delay)
    } else {
      console.error('Max reconnect attempts reached')
    }
  }

  disconnect() {
    this.closedByClient = true
    this.clearReconnectTimer()
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
    this.tenantId = null
    this.reconnectAttempts = 0
  }

  private clearReconnectTimer() {
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  onMessage(handler: MessageHandler) {
    this.messageHandlers.add(handler)
    return () => this.messageHandlers.delete(handler)
  }

  onConnectionStatusChange(handler: ConnectionStatusHandler) {
    this.connectionStatusHandlers.add(handler)
    return () => this.connectionStatusHandlers.delete(handler)
  }

  private notifyMessageHandlers(message: WebSocketMessage) {
    this.messageHandlers.forEach(handler => handler(message))
  }

  private notifyConnectionStatus(connected: boolean) {
    this.connectionStatusHandlers.forEach(handler => handler(connected))
  }
}

export const websocketService = new WebSocketService()
