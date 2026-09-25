import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

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

function devApiPlugin(): Plugin {
  return {
    name: 'dev-api-fallback',
    configureServer(server) {
      server.middlewares.use(async (req: any, res: any, next: any) => {
        const rawUrl = (req?.url as string) || ''
        const host = req?.headers?.host || 'localhost'
        const url = new URL(rawUrl, `http://${host}`)

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
                      ...[...c.toUpperCase()].map(x => 0x1f1a5 + x.charCodeAt(0))
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

          const response = {
            ip,
            geo,
            total_events: 1,
            first_seen: new Date(Date.now() - 3600000).toISOString(),
            last_seen: new Date().toISOString(),
            risk_score: 'low',
            risk_reason: 'Isolated suspicious request blocked by RouteWarden.',
            top_paths: [{ label: '/.env', count: 1 }],
            top_methods: [{ label: 'GET', count: 1 }],
            top_patterns: [{ label: 'dotfile', count: 1 }],
            response_modes: [{ label: 'tarpit', count: 1 }],
            target_sources: [{ label: 'traefik-gateway', count: 1 }],
            events: [
              {
                type: 'security_event',
                timestamp: new Date().toISOString(),
                plugin: 'traefik-warden',
                client_ip: ip,
                method: 'GET',
                path: '/.env',
                pattern: 'dotfile',
                action: 'blocked',
                response_mode: 'tarpit',
                source: 'traefik-gateway',
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
    proxy: {
      // Proxy API and WebSocket calls to the Go server during development
      '/api': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://127.0.0.1:9090',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
