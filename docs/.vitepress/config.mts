import { defineConfig } from 'vitepress'

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
    ['meta', { property: 'og:url', content: 'https://routewarden.github.io/cli/' }]
  ],
  themeConfig: {
    logo: '/icon.svg',
    siteTitle: 'rwarden CLI',
    nav: [
      {
        text: 'Guide',
        items: [
          { text: 'Installation', link: '/#installation' },
          { text: 'Commands Reference', link: '/#commands' },
          { text: 'JSON Schema & IDE Setup', link: '/#json-schema' },
          { text: 'Production Integration', link: '/#production' }
        ]
      },
      { text: 'Schema', link: '/#json-schema' },
      { text: 'Main Docs ↗', link: 'https://routewarden.github.io/docs/' }
    ],
    sidebar: [
      {
        text: 'RouteWarden CLI',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Installation', link: '/#installation' },
          { text: 'Commands Reference', link: '/#commands' },
          { text: 'JSON Schema & IDE Setup', link: '/#json-schema' },
          { text: 'Production Integration', link: '/#production' }
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
