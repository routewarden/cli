import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import http from 'node:http'
import fs from 'node:fs'

function resolveSpecialOrPrivateGeo(ip: string) {
  const clean = (ip || '').trim()
  const lower = clean.toLowerCase()

  if (lower === '127.0.0.1' || lower === 'localhost' || lower === '::1') {
    return {
      ip: clean,
      country_code: 'LAN',
      country_name: 'Localhost',
      flag_emoji: '🏠',
      region: 'Loopback Interface',
      city: 'Local Machine',
      zip: '',
      lat: 0,
      lon: 0,
      timezone: 'UTC',
      isp: 'Software Loopback Interface',
      org: 'Localhost',
      as: 'AS0 Local',
      is_private: true,
    }
  }

  // IPv4 parsing
  const parts = clean.split('.').map(Number)
  if (parts.length === 4 && parts.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
    const [p0, p1, p2] = parts

    // Tailscale and NetBird CGNAT range: 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
    // NetBird default peer subnet is 100.64.0.0/16
    if (p0 === 100 && (p1 & 0xc0) === 64) {
      const isNetbirdDefault = p1 === 64
      return {
        ip: clean,
        country_code: 'VPN',
        country_name: isNetbirdDefault ? 'NetBird / Tailscale Mesh' : 'Tailscale / NetBird Mesh',
        flag_emoji: '🔒',
        region: isNetbirdDefault
          ? 'NetBird Overlay Network (100.64.0.0/16)'
          : 'Tailscale Overlay Network (100.64.0.0/10)',
        city: isNetbirdDefault ? 'NetBird Peer' : 'Tailscale Peer',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: 'UTC',
        isp: isNetbirdDefault ? 'NetBird WireGuard Mesh Overlay' : 'Tailscale Encrypted WireGuard Overlay',
        org: 'Private Mesh VPN Overlay',
        as: 'AS-CGNAT (RFC 6598)',
        is_private: true,
      }
    }

    // RFC 5737 Test Networks
    if (
      (p0 === 192 && p1 === 0 && p2 === 2) ||
      (p0 === 198 && p1 === 51 && p2 === 100) ||
      (p0 === 203 && p1 === 0 && p2 === 113)
    ) {
      const label = p0 === 203 ? 'TEST-NET-3' : p1 === 51 ? 'TEST-NET-2' : 'TEST-NET-1'
      return {
        ip: clean,
        country_code: 'LAN',
        country_name: 'Reserved Test Network',
        flag_emoji: '🏠',
        region: `RFC 5737 Test Network (${label})`,
        city: 'Documentation Subnet',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: 'UTC',
        isp: 'IANA Special-Purpose / Reserved',
        org: 'Reserved Test Network',
        as: 'AS0 Reserved',
        is_private: true,
      }
    }

    // RFC 1918 Private LAN: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if (
      p0 === 10 ||
      (p0 === 172 && p1 >= 16 && p1 <= 31) ||
      (p0 === 192 && p1 === 168)
    ) {
      return {
        ip: clean,
        country_code: 'LAN',
        country_name: 'Local Network',
        flag_emoji: '🏠',
        region: 'Private Subnet (RFC 1918)',
        city: 'Internal Host',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: 'UTC',
        isp: 'Local Area Network',
        org: 'Private Network',
        as: 'AS0 Local',
        is_private: true,
      }
    }
  }

  // IPv6 parsing
  if (clean.includes(':')) {
    // Tailscale IPv6 prefix: fd7a:115c:a1e0::/48
    if (lower.startsWith('fd7a:115c:a1e0:') || lower.startsWith('fd7a:115c:a1e0::')) {
      return {
        ip: clean,
        country_code: 'VPN',
        country_name: 'Tailscale Mesh IPv6',
        flag_emoji: '🔒',
        region: 'Tailscale IPv6 Overlay (fd7a:115c:a1e0::/48)',
        city: 'Tailscale Peer',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: 'UTC',
        isp: 'Tailscale Encrypted WireGuard Mesh',
        org: 'Tailscale Mesh Network',
        as: 'AS-TAILSCALE',
        is_private: true,
      }
    }

    // NetBird IPv6 ULA prefix: fd00::/8 (or fc00::/7)
    if (lower.startsWith('fd') || lower.startsWith('fc')) {
      return {
        ip: clean,
        country_code: 'VPN',
        country_name: 'NetBird Mesh IPv6',
        flag_emoji: '🔒',
        region: 'NetBird IPv6 Overlay (fd00::/8 ULA)',
        city: 'NetBird Peer',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: 'UTC',
        isp: 'NetBird WireGuard Overlay',
        org: 'NetBird Mesh Network',
        as: 'AS-NETBIRD',
        is_private: true,
      }
    }
  }

  return null
}


import { execSync, spawn } from 'node:child_process'

// ── In-Memory dev server state ──────────────────────────────────────────
const devEvents: any[] = []
const sseClients = new Set<any>()
const activeLogStreams = new Set<string>()
let isWatchingLogs = false
let lastSourcesKey = ''

function broadcastDev(msg: any) {
  const line = `data: ${JSON.stringify(msg)}\n\n`
  for (const client of sseClients) {
    try {
      client.write(line)
    } catch {
      sseClients.delete(client)
    }
  }
}

function ingestDevEvent(raw: any, defaultSource = 'tcp-warden', defaultPlugin = 'tcp-warden') {
  if (!raw) return
  if (!raw.type && !raw.reason && !raw.action && !raw.service) return
  const ev = { ...raw }
  if (!ev.source) ev.source = defaultSource
  if (!ev.plugin || ev.plugin === 'unknown') ev.plugin = defaultPlugin
  if (!ev.timestamp) ev.timestamp = new Date().toISOString()
  if (!ev.action) {
    if (ev.reason && (ev.reason.includes('blocked') || ev.reason.includes('disabled') || ev.reason.includes('failed'))) {
      ev.action = 'blocked'
    } else {
      ev.action = 'blocked'
    }
  }

  if (ev.client_ip && (!ev.country_code || ev.country_code === 'XX')) {
    const geo = resolveSpecialOrPrivateGeo(ev.client_ip)
    if (geo) {
      ev.country_code = geo.country_code
      ev.country_name = geo.country_name
      ev.flag_emoji = geo.flag_emoji
    }
  }

  // Deduplicate: only drop if it's the exact same timestamp, IP, action and path/service
  const exists = devEvents.some(e => {
    if (e.timestamp !== ev.timestamp || e.client_ip !== ev.client_ip) return false
    if (ev.path && e.path && ev.path !== e.path) return false
    if (ev.service && e.service && ev.service !== e.service) return false
    return e.action === ev.action && e.reason === ev.reason
  })

  if (!exists) {
    devEvents.unshift(ev)
    if (devEvents.length > 500) devEvents.pop()
    broadcastDev({ msg_type: 'event', payload: ev })
  }
}

// Line buffer per stream source to handle fragmented JSON across TCP chunks
const streamBuffers = new Map<string, string>()

function extractDevJsonLines(chunkStr: string, defaultSource: string, defaultPlugin: string, streamKey = defaultSource) {
  const prev = streamBuffers.get(streamKey) || ''
  const combined = prev + chunkStr
  const lines = combined.split('\n')
  // Keep the last incomplete fragment in buffer
  streamBuffers.set(streamKey, lines.pop() || '')

  for (const line of lines) {
    const start = line.indexOf('{')
    const end = line.lastIndexOf('}')
    if (start !== -1 && end > start) {
      const candidate = line.slice(start, end + 1)
      if (
        candidate.includes('"security_event"') ||
        candidate.includes('"routewarden_block"') ||
        candidate.includes('"path_blocked"') ||
        candidate.includes('"plugin_unavailable"') ||
        candidate.includes('"upstream_connect_failed"') ||
        candidate.includes('"blocked"') ||
        candidate.includes('"tarpit"') ||
        candidate.includes('"silentDrop"') ||
        candidate.includes('"fakeSuccess"')
      ) {
        try {
          const parsed = JSON.parse(candidate)
          ingestDevEvent(parsed, defaultSource, defaultPlugin)
        } catch {}
      }
    }
  }
}

function getDevDockerSocket(): string | null {
  const sockPaths = [
    `${process.env.HOME}/.docker/run/docker.sock`,
    '/var/run/docker.sock',
    `${process.env.HOME}/.colima/default/docker.sock`,
    `${process.env.HOME}/.orbstack/run/docker.sock`,
  ]
  return sockPaths.find(p => p && fs.existsSync(p)) || null
}

function queryDevDockerCli(): any[] {
  try {
    const raw = execSync('docker ps --format "{{json .}}"', { encoding: 'utf8', timeout: 2500 })
    const list: any[] = []
    for (const line of raw.trim().split('\n')) {
      if (!line.trim()) continue
      try {
        const item = JSON.parse(line.trim())
        const rawNames = item.Names || ''
        const names = Array.isArray(rawNames)
          ? rawNames
          : rawNames.split(',').map((s: string) => s.trim().replace(/^\//, ''))
        const labels: Record<string, string> = {}
        if (typeof item.Labels === 'string') {
          for (const pair of item.Labels.split(',')) {
            const idx = pair.indexOf('=')
            if (idx !== -1) {
              labels[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim()
            }
          }
        } else if (item.Labels && typeof item.Labels === 'object') {
          Object.assign(labels, item.Labels)
        }
        list.push({
          Id: item.ID || item.Id || '',
          Names: names,
          Image: item.Image || '',
          State: item.State || 'running',
          Labels: labels,
        })
      } catch {}
    }
    return list
  } catch {
    return []
  }
}

async function queryDevDockerSocket(sock: string): Promise<any[]> {
  return new Promise((resolve) => {
    const dReq = http.get(
      {
        socketPath: sock,
        path: '/containers/json?all=false',
        timeout: 1500,
      },
      (dRes) => {
        let raw = ''
        dRes.on('data', chunk => raw += chunk)
        dRes.on('end', () => {
          try {
            resolve(JSON.parse(raw))
          } catch {
            resolve([])
          }
        })
      }
    )
    dReq.on('error', () => resolve([]))
    dReq.on('timeout', () => {
      dReq.destroy()
      resolve([])
    })
  })
}

async function getDevRunningContainers(): Promise<any[]> {
  const sock = getDevDockerSocket()
  if (sock) {
    try {
      const fromSocket = await queryDevDockerSocket(sock)
      if (Array.isArray(fromSocket) && fromSocket.length > 0) {
        return fromSocket
      }
    } catch {}
  }
  return queryDevDockerCli()
}

function detectDevContainerPlugin(c: any): string | null {
  const rawNames = c.Names || []
  const names: string[] = (Array.isArray(rawNames) ? rawNames : [String(rawNames)])
    .map((n: string) => n.replace(/^\//, '').toLowerCase())
  const img = (c.Image || '').toLowerCase()
  const labels = c.Labels || {}
  const svc = (labels['com.docker.compose.service'] || labels['service'] || labels['routewarden.role'] || '').toLowerCase()

  // Label opt-in
  for (const k of Object.keys(labels)) {
    const kl = k.toLowerCase()
    const vl = String(labels[k] || '').toLowerCase()
    if ((kl === 'routewarden' || kl === 'warden.enabled') && vl === 'true') {
      if (kl === 'routewarden.role' && vl) return vl
    }
  }

  if (img.includes('traefik') || names.some(n => n.includes('traefik')) || svc.includes('traefik')) return 'traefik-warden'
  if (img.includes('caddy') || names.some(n => n.includes('caddy')) || svc.includes('caddy')) return 'caddy-warden'
  if (img.includes('nginx') || names.some(n => n.includes('nginx')) || svc.includes('nginx') || img.includes('openresty')) return 'nginx-warden'
  if (img.includes('tcp-warden') || names.some(n => n.includes('tcp-warden')) || svc === 'tcp-warden' || img.includes('tcp')) return 'tcp-warden'
  if (img.includes('routewarden') || names.some(n => n.includes('routewarden') || n.includes('rwarden') || n.startsWith('rwarden-'))) {
    if (names.some(n => n.includes('caddy'))) return 'caddy-warden'
    if (names.some(n => n.includes('nginx'))) return 'nginx-warden'
    if (names.some(n => n.includes('tcp'))) return 'tcp-warden'
    return 'traefik-warden'
  }
  return null
}

async function getDevLiveSources(): Promise<any[]> {
  const containers = await getDevRunningContainers()
  const liveSources: any[] = []

  for (const c of containers) {
    const plugin = detectDevContainerPlugin(c)
    if (plugin) {
      const rawNames = c.Names || []
      const firstName = Array.isArray(rawNames) ? rawNames[0] : String(rawNames)
      const cleanName = (firstName || '').replace(/^\//, '') || (c.Id || '').slice(0, 12)
      liveSources.push({
        id: (c.Id || '').slice(0, 12),
        name: cleanName,
        kind: 'docker',
        plugin,
        status: 'live',
      })
    }
  }

  // Also probe tcp-warden direct on 9091
  try {
    const hRes = await fetch('http://127.0.0.1:9091/ping', { signal: AbortSignal.timeout(300) })
    if (hRes.ok && !liveSources.some(s => s.name === 'tcp-warden' || s.plugin === 'tcp-warden')) {
      liveSources.push({
        id: 'tcp-warden-api',
        name: 'tcp-warden',
        kind: 'api',
        plugin: 'tcp-warden',
        status: 'live',
      })
    }
  } catch {}

  return liveSources
}

function startDevLogWatcher() {
  if (isWatchingLogs) return
  isWatchingLogs = true

  const pollAndTail = async () => {
    try {
      const containers = await getDevRunningContainers()
      const currentSources = await getDevLiveSources()

      // Broadcast sources if changed
      const currentKey = currentSources.map(s => `${s.id}:${s.name}:${s.status}`).sort().join('|')
      if (currentKey !== lastSourcesKey) {
        lastSourcesKey = currentKey
        broadcastDev({ msg_type: 'sources', payload: currentSources })
      }

      const sock = getDevDockerSocket()

      for (const c of containers) {
        const plugin = detectDevContainerPlugin(c)
        if (!plugin || !c.Id) continue

        const rawNames = c.Names || []
        const firstName = Array.isArray(rawNames) ? rawNames[0] : String(rawNames)
        const cName = (firstName || '').replace(/^\//, '') || c.Id.slice(0, 12)

        if (!activeLogStreams.has(c.Id)) {
          activeLogStreams.add(c.Id)
          let streamStarted = false

          // Try socket streaming first if socket exists
          if (sock) {
            try {
              const req = http.get(
                {
                  socketPath: sock,
                  path: `/containers/${c.Id}/logs?follow=1&stdout=1&stderr=1&tail=500&timestamps=0`,
                  timeout: 0,
                },
                (res) => {
                  if (res.statusCode === 200) {
                    streamStarted = true
                    res.on('data', chunk => extractDevJsonLines(chunk.toString('utf8'), cName, plugin, c.Id))
                    res.on('end', () => activeLogStreams.delete(c.Id))
                    res.on('error', () => activeLogStreams.delete(c.Id))
                  } else {
                    activeLogStreams.delete(c.Id)
                  }
                }
              )
              req.on('error', () => {
                activeLogStreams.delete(c.Id)
              })
            } catch {
              activeLogStreams.delete(c.Id)
            }
          }

          // Fallback to docker logs CLI if socket not available or failed
          if (!streamStarted) {
            try {
              const logProcess = spawn('docker', ['logs', '--tail', '500', '-f', c.Id])
              logProcess.stdout?.on('data', chunk => extractDevJsonLines(chunk.toString('utf8'), cName, plugin, c.Id))
              logProcess.stderr?.on('data', chunk => extractDevJsonLines(chunk.toString('utf8'), cName, plugin, c.Id))
              logProcess.on('close', () => activeLogStreams.delete(c.Id))
              logProcess.on('error', () => activeLogStreams.delete(c.Id))
            } catch {
              activeLogStreams.delete(c.Id)
            }
          }
        }
      }
    } catch {}

    // Connect to tcp-warden SSE stream at 127.0.0.1:9091/api/events
    if (!activeLogStreams.has('tcp-warden-sse')) {
      try {
        const sseReq = http.get(
          {
            hostname: '127.0.0.1',
            port: 9091,
            path: '/api/events',
            headers: { Accept: 'text/event-stream' },
            timeout: 0,
          },
          (res) => {
            if (res.statusCode === 200) {
              activeLogStreams.add('tcp-warden-sse')
              res.on('data', chunk => {
                extractDevJsonLines(chunk.toString('utf8'), 'tcp-warden', 'tcp-warden', 'tcp-warden-sse')
              })
              res.on('end', () => activeLogStreams.delete('tcp-warden-sse'))
              res.on('error', () => activeLogStreams.delete('tcp-warden-sse'))
            }
          }
        )
        sseReq.on('error', () => activeLogStreams.delete('tcp-warden-sse'))
      } catch {}
    }
  }

  pollAndTail()
  setInterval(pollAndTail, 3000)
}

function devApiPlugin(): Plugin {
  return {
    name: 'dev-api-fallback',
    configureServer(server) {
      // Start background log ingestion on server start
      startDevLogWatcher()

      server.middlewares.use(async (req: any, res: any, next: any) => {
        const rawUrl = (req?.url as string) || ''
        const host = req?.headers?.host || 'localhost'
        const url = new URL(rawUrl, `http://${host}`)

        // Handle /ws/events SSE connection
        if (url.pathname === '/ws/events') {
          let handledBy9090 = false
          try {
            const probe = await fetch('http://127.0.0.1:9090/api/health', { signal: AbortSignal.timeout(200) })
            if (probe.ok) {
              const bReq = http.get('http://127.0.0.1:9090/ws/events', (bRes) => {
                if (bRes.statusCode === 200) {
                  res.writeHead(200, {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                  })
                  bRes.pipe(res)
                  handledBy9090 = true
                }
              })
              bReq.on('error', () => {})
              await new Promise(r => setTimeout(r, 80))
              if (handledBy9090) return
            }
          } catch {}

          // Dev fallback SSE endpoint
          res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
          })

          sseClients.add(res)

          // Immediately send source list
          getDevLiveSources().then(sources => {
            try {
              res.write(`data: ${JSON.stringify({ msg_type: 'sources', payload: sources })}\n\n`)
            } catch {}
          })

          // Heartbeat comment every 15 seconds
          const hb = setInterval(() => {
            try {
              res.write(': heartbeat\n\n')
            } catch {}
          }, 15000)

          req.on('close', () => {
            clearInterval(hb)
            sseClients.delete(res)
          })
          return
        }

        // Handle /api/config/:id
        if (url.pathname.startsWith('/api/config/')) {
          const id = url.pathname.replace(/^\/api\/config\/?/, '').trim()
          try {
            const hRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, { signal: AbortSignal.timeout(300) })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({
            id,
            name: id,
            kind: 'docker',
            has_config: false,
            error: 'No routewarden.json label found on container',
          }))
          return
        }

        // Handle /api/ip/:ip or /api/ip?ip=...
        if (
          url.pathname.startsWith('/api/ip/') ||
          (url.pathname === '/api/ip' && url.searchParams.has('ip'))
        ) {
          // Attempt proxying to 9090 first
          try {
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 800)
            const backendRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, {
              signal: controller.signal,
            })
            clearTimeout(timeoutId)
            if (backendRes.ok) {
              const data = await backendRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {
            // Backend offline or unreachable, serve directly in dev mode
          }

          let ip = url.pathname.replace(/^\/api\/ip\/?/, '').trim()
          if (!ip) ip = url.searchParams.get('ip') || ''

          if (!ip) {
            res.statusCode = 400
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({ error: 'Missing IP parameter' }))
            return
          }

          const specialGeo = resolveSpecialOrPrivateGeo(ip)
          let geo = specialGeo || {
            ip,
            country_code: 'XX',
            country_name: 'Public IP',
            flag_emoji: '🌐',
            region: 'Public Internet',
            city: 'Unknown Location',
            zip: '',
            lat: 0,
            lon: 0,
            timezone: 'UTC',
            isp: 'Internet Service Provider',
            org: 'Public Network',
            as: '',
            is_private: false,
          }

          if (!specialGeo) {
            try {
              const ipApiRes = await fetch(
                `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as`
              )
              if (ipApiRes.ok) {
                const d = await ipApiRes.json()
                if (d.status === 'success' && d.countryCode) {
                  const toFlag = (c: string) =>
                    String.fromCodePoint(
                      ...c.toUpperCase().split('').map(x => 0x1f1a5 + x.charCodeAt(0))
                    )
                  geo = {
                    ip,
                    country_code: d.countryCode,
                    country_name: d.country,
                    flag_emoji: toFlag(d.countryCode),
                    region: d.regionName,
                    city: d.city,
                    zip: d.zip,
                    lat: d.lat,
                    lon: d.lon,
                    timezone: d.timezone,
                    isp: d.isp,
                    org: d.org,
                    as: d.as,
                    is_private: false,
                  }
                }
              }
            } catch {
              // ignore
            }
          }

          const matchingEvents = devEvents.filter(e => e.client_ip === ip)
          const response = {
            ip,
            geo,
            total_events: matchingEvents.length || 1,
            first_seen: matchingEvents.length > 0 ? matchingEvents[matchingEvents.length - 1].timestamp : new Date(Date.now() - 3600000).toISOString(),
            last_seen: matchingEvents.length > 0 ? matchingEvents[0].timestamp : new Date().toISOString(),
            risk_score: matchingEvents.length > 5 ? 'high' : matchingEvents.length > 2 ? 'medium' : 'low',
            risk_reason: 'Security events detected for this host.',
            top_paths: [{ label: matchingEvents[0]?.path || matchingEvents[0]?.service || '/.env', count: matchingEvents.length || 1 }],
            top_methods: [{ label: matchingEvents[0]?.method || matchingEvents[0]?.protocol || 'TCP', count: matchingEvents.length || 1 }],
            top_patterns: [{ label: matchingEvents[0]?.pattern || matchingEvents[0]?.reason || 'policy_match', count: matchingEvents.length || 1 }],
            response_modes: [{ label: matchingEvents[0]?.action || 'blocked', count: matchingEvents.length || 1 }],
            target_sources: [{ label: matchingEvents[0]?.source || 'tcp-warden', count: matchingEvents.length || 1 }],
            events: matchingEvents.length > 0 ? matchingEvents : [
              {
                type: 'security_event',
                timestamp: new Date().toISOString(),
                plugin: 'tcp-warden',
                client_ip: ip,
                protocol: 'tcp',
                service: 'bastion',
                action: 'blocked',
                source: 'tcp-warden',
                country_code: geo.country_code,
                country_name: geo.country_name,
                flag_emoji: geo.flag_emoji,
              },
            ],
          }

          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(response))
          return
        }

        // Handle /api/geoip?ip=...
        if (url.pathname === '/api/geoip' && url.searchParams.has('ip')) {
          const ip = url.searchParams.get('ip') || ''
          const specialGeo = resolveSpecialOrPrivateGeo(ip)
          const geo = specialGeo || {
            ip,
            country_code: 'XX',
            country_name: 'Public IP',
            flag_emoji: '🌐',
            is_private: false,
          }
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(geo))
          return
        }

        // Handle /api/events/clear and DELETE /api/events
        if (url.pathname === '/api/events/clear' || (url.pathname === '/api/events' && req.method === 'DELETE')) {
          try {
            const hRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, {
              method: req.method || 'POST',
              signal: AbortSignal.timeout(500),
            })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}
          devEvents.length = 0
          broadcastDev({ msg_type: 'clear' })
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ status: 'cleared', count: 0 }))
          return
        }

        // Handle /api/sources/clear and DELETE /api/sources
        if (url.pathname === '/api/sources/clear' || (url.pathname === '/api/sources' && req.method === 'DELETE')) {
          try {
            const hRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, {
              method: req.method || 'POST',
              signal: AbortSignal.timeout(500),
            })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}
          const sources = await getDevLiveSources()
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(sources))
          return
        }

        // Handle /api/sources dev fallback when 9090 is offline
        if (url.pathname === '/api/sources') {
          try {
            const hRes = await fetch('http://127.0.0.1:9090/api/sources', { signal: AbortSignal.timeout(300) })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}

          const sources = await getDevLiveSources()
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(sources))
          return
        }

        // Handle /api/events dev fallback when 9090 is offline
        if (url.pathname === '/api/events') {
          try {
            const hRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, { signal: AbortSignal.timeout(300) })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}
          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(devEvents))
          return
        }

        // Handle /api/stats dev fallback when 9090 is offline
        if (url.pathname === '/api/stats') {
          try {
            const hRes = await fetch(`http://127.0.0.1:9090${rawUrl}`, { signal: AbortSignal.timeout(300) })
            if (hRes.ok) {
              const data = await hRes.text()
              res.statusCode = 200
              res.setHeader('Content-Type', 'application/json')
              res.end(data)
              return
            }
          } catch {}

          // Compute snapshot from devEvents
          const ipSet = new Set(devEvents.map(e => e.client_ip).filter(Boolean))
          const pathMap = new Map<string, number>()
          const ipMap = new Map<string, number>()
          const gatewayCounts: Record<string, number> = {
            'nginx-warden': 0,
            'traefik-warden': 0,
            'caddy-warden': 0,
            'tcp-warden': 0,
          }

          for (const ev of devEvents) {
            const p = ev.service || ev.path || 'unknown'
            pathMap.set(p, (pathMap.get(p) || 0) + 1)
            if (ev.client_ip) {
              ipMap.set(ev.client_ip, (ipMap.get(ev.client_ip) || 0) + 1)
            }
            const plugin = (ev.plugin || '').toLowerCase()
            if (plugin.includes('nginx')) gatewayCounts['nginx-warden']++
            else if (plugin.includes('traefik')) gatewayCounts['traefik-warden']++
            else if (plugin.includes('caddy')) gatewayCounts['caddy-warden']++
            else gatewayCounts['tcp-warden']++
          }

          const topPaths = Array.from(pathMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([label, count]) => ({ label, count }))

          const topIPs = Array.from(ipMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([label, count]) => ({ label, count }))

          const snapshot = {
            total_events: devEvents.length,
            unique_ips: ipSet.size,
            blocks_per_min: Math.min(devEvents.length, 12),
            top_paths: topPaths,
            top_ips: topIPs,
            response_modes: [{ label: 'blocked', count: devEvents.length }],
            rate_over_time: [],
            by_gateway: [
              { label: 'nginx-warden', count: gatewayCounts['nginx-warden'] },
              { label: 'traefik-warden', count: gatewayCounts['traefik-warden'] },
              { label: 'caddy-warden', count: gatewayCounts['caddy-warden'] },
              { label: 'tcp-warden', count: gatewayCounts['tcp-warden'] },
            ],
          }

          res.statusCode = 200
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(snapshot))
          return
        }

        next()
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), devApiPlugin()],
  build: {
    outDir: '../dashboard/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
  },
})
