import { useEffect, useRef, useState, useCallback } from 'react'
import type { SecurityEvent, Source, WsMessage } from '../types'

const SSE_URL = '/ws/events'
const MAX_EVENTS = 500

interface UseEventStreamReturn {
  events: SecurityEvent[]
  sources: Source[]
  connected: boolean
  paused: boolean
  setPaused: (p: boolean) => void
  clear: () => void
  clearStoppedSources: () => Promise<void>
}

export function useEventStream(): UseEventStreamReturn {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [sources, setSources] = useState<Source[]>([])
  const [connected, setConnected] = useState(false)
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(paused)
  const esRef = useRef<EventSource | null>(null)

  pausedRef.current = paused

  // Load historical events & initial sources on mount
  useEffect(() => {
    fetch('/api/events?n=500')
      .then(r => r.json())
      .then((data: SecurityEvent[]) => {
        if (Array.isArray(data) && data.length > 0) {
          setEvents(data.reverse()) // API returns oldest first; we prepend newest
        }
      })
      .catch(() => {/* ignore if server not ready yet */})

    fetch('/api/sources')
      .then(r => r.json())
      .then((data: Source[]) => {
        if (Array.isArray(data)) {
          setSources(data)
        }
      })
      .catch(() => {})
  }, [])

  // SSE connection
  useEffect(() => {
    const connect = () => {
      const es = new EventSource(SSE_URL)
      esRef.current = es

      es.onopen = () => setConnected(true)
      es.onerror = () => {
        setConnected(false)
        es.close()
        // Reconnect after 3 s
        setTimeout(connect, 3000)
      }

      es.onmessage = (e) => {
        try {
          const msg: WsMessage = JSON.parse(e.data)
          if (msg.msg_type === 'sources') {
            setSources(msg.payload as Source[])
          } else if (msg.msg_type === 'event' && !pausedRef.current) {
            const event = msg.payload as SecurityEvent
            setEvents(prev => {
              const next = [event, ...prev]
              return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next
            })
          }
        } catch {
          // Ignore heartbeat comments and malformed messages
        }
      }
    }

    connect()
    return () => {
      esRef.current?.close()
      esRef.current = null
    }
  }, [])

  const clear = useCallback(() => setEvents([]), [])

  const clearStoppedSources = useCallback(async () => {
    try {
      const res = await fetch('/api/sources/clear', { method: 'POST' })
      const data = await res.json()
      if (Array.isArray(data)) {
        setSources(data)
      }
    } catch {
      // ignore
    }
  }, [])

  return { events, sources, connected, paused, setPaused, clear, clearStoppedSources }
}
