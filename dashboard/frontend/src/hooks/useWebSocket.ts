import { useEffect, useRef, useState } from 'react'

interface WebSocketMessage {
  type: string
  data: any
}

export function useWebSocket(url: string) {
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [readyState, setReadyState] = useState<number>(WebSocket.CONNECTING)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!url) return

    const connect = () => {
      ws.current = new WebSocket(url)

      ws.current.onopen = () => {
        setReadyState(WebSocket.OPEN)
      }

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setLastMessage(data)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      ws.current.onerror = () => {
        setReadyState(WebSocket.CLOSED)
      }

      ws.current.onclose = () => {
        setReadyState(WebSocket.CLOSED)
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (!ws.current || ws.current.readyState === WebSocket.CLOSED) {
            connect()
          }
        }, 3000)
      }
    }

    connect()

    return () => {
      ws.current?.close()
    }
  }, [url])

  return { lastMessage, readyState }
}

