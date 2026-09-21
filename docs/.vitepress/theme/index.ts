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

      // 3. Robust left-sidebar scroll spy for single-page documentation
      const sectionIds = ['installation', 'commands', 'json-schema', 'production', 'changelog']

      const updateActiveSidebar = () => {
        const sidebarLinks = Array.from(
          document.querySelectorAll<HTMLAnchorElement>('.VPSidebar .VPSidebarItem.is-link a')
        )
        if (!sidebarLinks.length) return

        // Compute current section based on scroll position
        const scrollPosition = window.scrollY + 160
        let currentSectionId = ''

        for (const id of sectionIds) {
          const el = document.getElementById(id)
          if (el) {
            const rect = el.getBoundingClientRect()
            const absoluteTop = rect.top + window.scrollY
            if (scrollPosition >= absoluteTop) {
              currentSectionId = id
            }
          }
        }

        // If at top of the page, default to first section
        if (!currentSectionId && window.scrollY < 200) {
          currentSectionId = sectionIds[0]
        }

        sidebarLinks.forEach((link) => {
          const href = link.getAttribute('href') || ''
          const itemDiv = link.closest('.VPSidebarItem') as HTMLElement | null
          const linkText = link.querySelector('.text') as HTMLElement | null
          const isActive = currentSectionId ? href.includes(`#${currentSectionId}`) : false

          if (itemDiv) {
            if (isActive) {
              itemDiv.classList.add('is-active')
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


