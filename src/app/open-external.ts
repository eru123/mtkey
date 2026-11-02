/** Opens an external URL in the system browser.
 *
 * Inside Tauri, `window.open` is a dead button: every webview backend either
 * swallows the popup or handles it without navigating. The official opener
 * plugin does the job; its capability is scoped to the hosts the Learn panel
 * links to. In a plain browser (tests, vite preview) the fallback applies. */
export async function openExternal(url: string): Promise<void> {
  if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
    try {
      const { openUrl } = await import('@tauri-apps/plugin-opener')
      await openUrl(url)
      return
    } catch {
      // fall through to the browser path
    }
  }
  window.open(url, '_blank')
}
