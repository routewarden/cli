import { defineConfig } from 'vitepress'

// Declare process ambiently for Node build-time environment in VitePress config
declare const process: { env: Record<string, string | undefined> }

// Cloudflare Web Analytics token — only set in CI via GitHub Actions environment secret/variable.
// When absent (local dev), the beacon script is omitted to prevent CORS rejections.
const CF_ANALYTICS_TOKEN = process.env.CLOUDFLARE_ANALYTICS_TOKEN || ''

export default defineConfig({
  title: 'RouteWarden CLI',
  description: 'Developer CLI, path anti-evasion tester, config validator, and official JSON Schema for RouteWarden.',
  base: '/cli/',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/cli/icon.svg' }],
    ['meta', { name: 'theme-color', content: '#6366f1' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'RouteWarden CLI (`rwarden`)' }],
    ['meta', { property: 'og:description', content: 'Developer CLI, path anti-evasion tester, config validator, and official JSON Schema for RouteWarden.' }],
    ['meta', { property: 'og:url', content: 'https://routewarden.github.io/cli/' }],
    ...(CF_ANALYTICS_TOKEN ? [[
      'script' as const,
      {
        defer: '',
        src: 'https://static.cloudflareinsights.com/beacon.min.js',
        'data-cf-beacon': JSON.stringify({ token: CF_ANALYTICS_TOKEN })
      }
    ] as [string, Record<string, string>]] : [])
  ],
  themeConfig: {
    logo: '/icon.svg',
    siteTitle: 'rwarden CLI',
    outline: {
      level: [2, 3],
      label: 'On this page'
    },
    nav: [
      {
        text: 'Guide',
        items: [
          { text: 'Installation', link: '/#installation' },
          { text: 'Commands Reference', link: '/#commands' },
          { text: 'Security Dashboard', link: '/#dashboard' },
          { text: 'Guard TCP Proxy', link: '/#guard' },
          { text: 'JSON Schema & IDE Setup', link: '/#json-schema' },
          { text: 'Production Integration', link: '/#production' },
          { text: 'Changelog', link: '/#changelog' }
        ]
      },
      { text: 'Dashboard', link: '/#dashboard' },
      { text: 'Guard Proxy', link: '/#guard' },
      { text: 'Schema', link: '/#json-schema' },
      { text: 'Changelog', link: '/#changelog' },
      { text: 'Main Docs', link: 'https://routewarden.github.io/docs/' }
    ],
    sidebar: [
      {
        text: 'Documentation',
        items: [
          { text: 'Installation', link: '/#installation' },
          { text: 'Commands Reference', link: '/#commands' },
          { text: 'JSON Schema & IDE Setup', link: '/#json-schema' },
          { text: 'Production Integration', link: '/#production' },
          { text: 'Changelog', link: '/#changelog' }
        ]
      },
      {
        text: 'Security Dashboard',
        items: [
          { text: 'Overview & Capabilities', link: '/#dashboard' },
          { text: 'Live Event Feed', link: '/#dashboard-live-feed' },
          { text: 'Analytics & Attack Trends', link: '/#dashboard-analytics' },
          { text: 'Sources & Containers', link: '/#dashboard-sources' },
          { text: 'IP Intelligence & Threat Score', link: '/#dashboard-ip-intelligence' },
          { text: 'Tailscale & NetBird VPN', link: '/#dashboard-mesh-vpn' },
          { text: 'CLI & Docker Usage', link: '/#dashboard-usage' },
          { text: 'Command Flags', link: '/#dashboard-flags' },
          { text: 'REST & WebSocket API', link: '/#dashboard-api' }
        ]
      },
      {
        text: 'Guard TCP Proxy',
        items: [
          { text: 'Overview & Architecture', link: '/#guard' },
          { text: 'Commands & Subcommands', link: '/#guard-commands' },
          { text: 'Configuration (netguard.json)', link: '/#guard-config' },
          { text: 'Protocol Inspectors', link: '/#guard-protocols' },
          { text: 'CrowdSec Integration', link: '/#guard-crowdsec' },
          { text: 'Management REST & SSE API', link: '/#guard-api' },
          { text: 'Docker & Compose Deployment', link: '/#guard-docker' },
          { text: 'Configuration Hot-Reload', link: '/#guard-hot-reload' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/routewarden/cli' }
    ],
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © RouteWarden Contributors'
    },
    search: {
      provider: 'local'
    }
  }
})
