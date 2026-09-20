import DefaultTheme from 'vitepress/theme'
import type { EnhanceAppContext } from 'vitepress'
import { trackPageView, trackDownload } from './telemetry'

export default {
  extends: DefaultTheme,
  enhanceApp({ router }: EnhanceAppContext) {
    // Route tracking for SPA page transitions in VitePress
    if (router && typeof window !== 'undefined') {
      const originalAfterRouteChanged = router.onAfterRouteChanged
      router.onAfterRouteChanged = (to: string) => {
        if (originalAfterRouteChanged) {
          originalAfterRouteChanged(to)
        }
        trackPageView(to)
      }
    }

    if (typeof window !== 'undefined') {
      window.addEventListener('DOMContentLoaded', () => {
        trackPageView()

        // Global click listener to track installer and release asset downloads
        document.addEventListener('click', (e: MouseEvent) => {
          const target = (e.target as HTMLElement)?.closest('a')
          if (!target) return

          const href = target.getAttribute('href') || ''
          const text = target.innerText?.trim() || ''

          // Check if link is a download link (GitHub release, tar.gz, zip, install.sh)
          if (
            href.includes('/releases/download/') ||
            href.endsWith('.tar.gz') ||
            href.endsWith('.zip') ||
            href.includes('install.sh') ||
            href.includes('/releases/latest')
          ) {
            let platform = 'generic'
            const lowerHref = href.toLowerCase()
            if (lowerHref.includes('darwin') || lowerHref.includes('macos')) platform = 'darwin'
            else if (lowerHref.includes('linux')) platform = 'linux'
            else if (lowerHref.includes('windows')) platform = 'windows'

            trackDownload(href, platform)
          }
        }, { passive: true })
      })
    }
  }
}
