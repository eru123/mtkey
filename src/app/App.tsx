/** The instrument shell: rail + workbench + learn dock + status bar, the
 * global keyboard map (DESIGN §5) and the native window title. */
import { useEffect } from 'react'

import { useAppStore } from './store-context'
import { AppStoreProvider } from './store'
import { useBench } from './bench-context'
import { BenchProvider } from './bench'
import { isEditableTarget } from './lib'
import { useViewportWidth } from './hooks'
import { TooltipProvider } from '@/components/ui/tooltip'
import { CommandPalette } from '@/components/app/CommandPalette'
import { LearnDockHost } from '@/components/app/LearnDock'
import { MethodRail } from '@/components/app/MethodRail'
import { SelfTestDialog } from '@/components/app/SelfTestDialog'
import { ShortcutsDialog } from '@/components/app/ShortcutsDialog'
import { StatusBar } from '@/components/app/StatusBar'
import { Workbench } from '@/components/app/Workbench'

export default function App() {
  return (
    <AppStoreProvider>
      <TooltipProvider delayDuration={500}>
        <BenchProvider>
          <Shell />
        </BenchProvider>
      </TooltipProvider>
    </AppStoreProvider>
  )
}

function Shell() {
  const store = useAppStore()
  const bench = useBench()
  const viewportWidth = useViewportWidth()

  // DESIGN §2: rail auto-collapses below 840px viewport width, and below
  // 960px when the learn dock is open (the dock pushes, it never covers).
  const railCollapsed =
    store.railCollapsed ||
    viewportWidth < 840 ||
    (store.dockOpen && viewportWidth < 960)

  // DESIGN §7: window title follows the selected method, native titlebar.
  useEffect(() => {
    const title = `MTKey — ${store.method.name}`
    document.title = title
    if (window.__TAURI_INTERNALS__) {
      import('@tauri-apps/api/window')
        .then((mod) => mod.getCurrentWindow().setTitle(title))
        .catch(() => {
          // not fatal: the document title already updated
        })
    }
  }, [store.method.name])

  // The global keyboard map, DESIGN §5.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const mod = event.metaKey || event.ctrlKey
      const key = event.key.toLowerCase()

      if (mod && key === 'k') {
        event.preventDefault()
        store.setPaletteOpen(true)
        return
      }
      if (mod && event.key === 'Enter') {
        event.preventDefault()
        bench.runNow()
        return
      }
      if (mod && event.shiftKey && key === 'c') {
        event.preventDefault()
        bench.copyOutput()
        return
      }
      if (mod && event.shiftKey && key === 'x') {
        event.preventDefault()
        bench.swap()
        return
      }
      if (mod && key === 'j') {
        event.preventDefault()
        store.toggleDock()
        return
      }
      if (mod && key === 'b') {
        event.preventDefault()
        store.toggleRail()
        return
      }
      if (event.key === 'Escape') {
        // Radix closes the topmost dialog/popover itself; only close the
        // dock when no overlay layer is open.
        const overlayOpen = document.querySelector(
          '[data-state="open"][role="dialog"], [data-state="open"][role="menu"]',
        )
        if (!overlayOpen && store.dockOpen) store.setDockOpen(false)
        return
      }
      if (event.key === '?' && !isEditableTarget(event.target)) {
        event.preventDefault()
        store.setShortcutsOpen(true)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [bench, store])

  return (
    <div className="flex h-full flex-col overflow-hidden bg-background text-foreground">
      <div className="flex min-h-0 flex-1">
        <MethodRail collapsed={railCollapsed} onToggleCollapsed={store.toggleRail} />
        <main className="min-w-95 flex-1 overflow-y-auto" aria-label="Workbench">
          <Workbench />
        </main>
        <LearnDockHost open={store.dockOpen} />
      </div>
      <StatusBar />
      <CommandPalette />
      <SelfTestDialog />
      <ShortcutsDialog />
    </div>
  )
}
