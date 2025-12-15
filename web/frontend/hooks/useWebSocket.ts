'use client'

import { useEffect, useRef, useState, useCallback } from 'react'

interface WebSocketMessage {
  type: string
  [key: string]: any
}

interface UseWebSocketOptions {
  onMessage?: (message: WebSocketMessage) => void
  onConnect?: () => void
  onDisconnect?: () => void
  onError?: (error: Event) => void
  autoReconnect?: boolean
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    autoReconnect = true,
    reconnectInterval = 3000,
    maxReconnectAttempts = 5,
  } = options

  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  const getWebSocketUrl = useCallback(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = process.env.NEXT_PUBLIC_API_URL?.replace(/^https?:\/\//, '') || window.location.host
    return `${protocol}//${host}/api/v1/ws${token ? `?token=${token}` : ''}`
  }, [])

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    try {
      const url = getWebSocketUrl()
      wsRef.current = new WebSocket(url)

      wsRef.current.onopen = () => {
        setIsConnected(true)
        reconnectAttempts.current = 0
        onConnect?.()
      }

      wsRef.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          setLastMessage(message)
          onMessage?.(message)
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e)
        }
      }

      wsRef.current.onclose = () => {
        setIsConnected(false)
        onDisconnect?.()

        // Auto-reconnect if enabled
        if (autoReconnect && reconnectAttempts.current < maxReconnectAttempts) {
          reconnectAttempts.current += 1
          reconnectTimeoutRef.current = setTimeout(() => {
            connect()
          }, reconnectInterval)
        }
      }

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error)
        onError?.(error)
      }
    } catch (e) {
      console.error('Failed to connect WebSocket:', e)
    }
  }, [getWebSocketUrl, onConnect, onMessage, onDisconnect, onError, autoReconnect, reconnectInterval, maxReconnectAttempts])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
    }
    reconnectAttempts.current = maxReconnectAttempts // Prevent auto-reconnect
    wsRef.current?.close()
  }, [maxReconnectAttempts])

  const sendMessage = useCallback((message: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message))
    }
  }, [])

  const subscribeToScan = useCallback((scanId: number) => {
    sendMessage({ action: 'subscribe_scan', scan_id: scanId })
  }, [sendMessage])

  const unsubscribeFromScan = useCallback((scanId: number) => {
    sendMessage({ action: 'unsubscribe_scan', scan_id: scanId })
  }, [sendMessage])

  const ping = useCallback(() => {
    sendMessage({ action: 'ping' })
  }, [sendMessage])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect()
    }
  }, [disconnect])

  return {
    isConnected,
    lastMessage,
    connect,
    disconnect,
    sendMessage,
    subscribeToScan,
    unsubscribeFromScan,
    ping,
  }
}

// Hook specifically for scan updates
export function useScanWebSocket(scanIds: number[], onUpdate?: (scanId: number, data: any) => void) {
  const [scanUpdates, setScanUpdates] = useState<Record<number, any>>({})

  const handleMessage = useCallback((message: WebSocketMessage) => {
    if (message.type === 'scan_progress' || message.type === 'scan_status' ||
        message.type === 'scan_completed' || message.type === 'scan_failed') {
      const scanId = message.scan_id
      setScanUpdates(prev => ({
        ...prev,
        [scanId]: message,
      }))
      onUpdate?.(scanId, message)
    }
  }, [onUpdate])

  const { isConnected, connect, disconnect, subscribeToScan, unsubscribeFromScan } = useWebSocket({
    onMessage: handleMessage,
    autoReconnect: true,
  })

  // Connect and subscribe to scans on mount
  useEffect(() => {
    if (scanIds.length === 0) return

    connect()

    // Subscribe to each scan after connection
    const subscribeTimeout = setTimeout(() => {
      scanIds.forEach(id => subscribeToScan(id))
    }, 500) // Small delay to ensure connection is established

    return () => {
      clearTimeout(subscribeTimeout)
      scanIds.forEach(id => unsubscribeFromScan(id))
    }
  }, [scanIds, connect, subscribeToScan, unsubscribeFromScan])

  return {
    isConnected,
    scanUpdates,
    connect,
    disconnect,
  }
}
