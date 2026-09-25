import DefaultTheme from 'vitepress/theme'
import type { EnhanceAppContext } from 'vitepress'
import { h, onMounted } from 'vue'
import { trackPageView, trackDownload } from './telemetry'

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {})
  },
  setup() {
    onMounted(() => {
      // 1. Initial page tracking
      trackPageView()

      // 2. Global download clicks listener
      document.addEventListener('click', (e: MouseEvent) => {
        const target = (e.target as HTMLElement)?.closest('a')
        if (!target) return

        const href = target.getAttribute('href') || ''

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

      // 3. Robust left-sidebar scroll spy and auto-scroll for single-page documentation
      const updateActiveSidebar = () => {
        const sidebarLinks = Array.from(
          document.querySelectorAll<HTMLAnchorElement>('.VPSidebar .VPSidebarItem.is-link a')
        )
        if (!sidebarLinks.length) return

        // Extract all section anchor IDs dynamically from sidebar links
        const targetIds: string[] = []
        sidebarLinks.forEach((link) => {
          const href = link.getAttribute('href') || ''
          const hashIdx = href.indexOf('#')
          if (hashIdx !== -1) {
            const id = href.slice(hashIdx + 1).trim()
            if (id && !targetIds.includes(id)) {
              targetIds.push(id)
            }
          }
        })

        // Ensure all dashboard and main sections are included
        const fallbackSectionIds = [
          'installation',
          'commands',
          'dashboard',
          'dashboard-features',
          'dashboard-views',
          'dashboard-live-feed',
          'dashboard-analytics',
          'dashboard-sources',
          'dashboard-ip-intelligence',
          'dashboard-mesh-vpn',
          'dashboard-usage',
          'dashboard-flags',
          'dashboard-api',
          'json-schema',
          'production',
          'changelog',
        ]
        fallbackSectionIds.forEach((id) => {
          if (!targetIds.includes(id)) {
            targetIds.push(id)
          }
        })

        // Sort elements by their actual top offset on the page
        const scrollPosition = window.scrollY + 180
        const elementsWithOffsets = targetIds
          .map((id) => {
            const el = document.getElementById(id)
            if (!el) return null
            const rect = el.getBoundingClientRect()
            return { id, top: rect.top + window.scrollY }
          })
          .filter((item): item is { id: string; top: number } => item !== null)
          .sort((a, b) => a.top - b.top)

        let currentSectionId = ''
        for (const item of elementsWithOffsets) {
          if (scrollPosition >= item.top) {
            currentSectionId = item.id
          }
        }

        // If at top of the page, default to first section
        if (!currentSectionId && elementsWithOffsets.length > 0 && window.scrollY < 200) {
          currentSectionId = elementsWithOffsets[0].id
        }

        let activeItemEl: HTMLElement | null = null

        sidebarLinks.forEach((link) => {
          const href = link.getAttribute('href') || ''
          const itemDiv = link.closest('.VPSidebarItem') as HTMLElement | null
          const linkText = link.querySelector('.text') as HTMLElement | null

          const hashIdx = href.indexOf('#')
          const linkAnchor = hashIdx !== -1 ? href.slice(hashIdx + 1) : ''
          const isActive = currentSectionId ? linkAnchor === currentSectionId : false

          if (itemDiv) {
            if (isActive) {
              itemDiv.classList.add('is-active')
              activeItemEl = itemDiv
              if (linkText) {
                linkText.style.color = 'var(--vp-c-brand-1)'
                linkText.style.fontWeight = '600'
              }
            } else {
              itemDiv.classList.remove('is-active')
              if (linkText) {
                linkText.style.color = ''
                linkText.style.fontWeight = ''
              }
            }
          }
        })

        // Auto-scroll the left sidebar container so the active section stays in view
        if (activeItemEl) {
          const sidebarContainer =
            (activeItemEl as HTMLElement).closest('.VPSidebar') ||
            document.querySelector('.VPSidebar')
          if (sidebarContainer) {
            const containerRect = sidebarContainer.getBoundingClientRect()
            const itemRect = (activeItemEl as HTMLElement).getBoundingClientRect()

            // If the item is near or outside the top or bottom of the sidebar container, scroll it smoothly into view
            if (
              itemRect.top < containerRect.top + 80 ||
              itemRect.bottom > containerRect.bottom - 80
            ) {
              (activeItemEl as HTMLElement).scrollIntoView({
                behavior: 'smooth',
                block: 'nearest',
                inline: 'nearest',
              })
            }
          }
        }
      }

      window.addEventListener('scroll', updateActiveSidebar, { passive: true })
      window.addEventListener('hashchange', updateActiveSidebar, { passive: true })
      window.addEventListener('resize', updateActiveSidebar, { passive: true })

      // Run immediately and after layout rendering
      updateActiveSidebar()
      setTimeout(updateActiveSidebar, 150)
      setTimeout(updateActiveSidebar, 500)
    })
  },
  enhanceApp({ router }: EnhanceAppContext) {
    if (router && typeof window !== 'undefined') {
      const originalAfterRouteChanged = router.onAfterRouteChanged
      router.onAfterRouteChanged = (to: string) => {
        if (originalAfterRouteChanged) {
          originalAfterRouteChanged(to)
        }
        trackPageView(to)
      }
    }
  }
}


