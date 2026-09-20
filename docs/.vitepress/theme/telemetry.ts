/**
 * Lightweight telemetry and event logger for RouteWarden CLI Docs.
 * Compatible with Cloudflare Web Analytics and custom event tracking.
 */

declare global {
  interface Window {
    __cfBeacon?: any
  }
}

/**
 * Track page view or SPA route navigation.
 */
export function trackPageView(path?: string, title?: string) {
  if (typeof window === 'undefined') return
  const currentPath = path || window.location.pathname
  const currentTitle = title || document.title

  try {
    if (window.__cfBeacon && typeof window.__cfBeacon.send === 'function') {
      window.__cfBeacon.send()
    }
  } catch {}

  try {
    window.dispatchEvent(
      new CustomEvent('routewarden:telemetry', {
        detail: {
          event: 'pageview',
          category: 'cli_docs',
          path: currentPath,
          title: currentTitle,
          timestamp: Date.now()
        }
      })
    )
  } catch {}
}

/**
 * Track custom user actions (e.g. binary download, copy install command, schema view).
 */
export function trackEvent(category: string, action: string, metadata?: Record<string, any>) {
  if (typeof window === 'undefined') return

  try {
    window.dispatchEvent(
      new CustomEvent('routewarden:telemetry', {
        detail: {
          category,
          action,
          metadata: metadata || {},
          timestamp: Date.now()
        }
      })
    )
  } catch {}

  // Also trigger beacon ping if supported
  try {
    if (window.__cfBeacon && typeof window.__cfBeacon.send === 'function') {
      window.__cfBeacon.send()
    }
  } catch {}
}

/**
 * Specific helper to track binary downloads or installer executions.
 */
export function trackDownload(asset: string, platform?: string) {
  trackEvent('downloads', 'download_binary', {
    asset,
    platform: platform || 'unknown',
    url: window.location.href
  })
}
