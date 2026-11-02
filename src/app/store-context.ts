/** The app store context: per-method session state (in memory only, per
 * DESIGN §5 "whiteboard, not vault") plus global UI state. The provider
 * lives in store.tsx. */
import { createContext, useContext } from 'react'

import type {
  CipherMethod,
  Direction,
  TestCase,
} from '@/core'

export type ThemePreference = 'light' | 'dark' | 'system'

export const THEME_STORAGE_KEY = 'mtkey.theme'

export interface MethodSession {
  input: string
  fields: Record<string, string>
  direction: Direction
  revealed: Record<string, boolean>
}

export interface SelfTestResult {
  status: 'running' | 'done'
  cases: TestCase[]
  durationMs: number
}

export interface AppStoreValue {
  method: CipherMethod
  selectMethod: (id: string) => void
  session: MethodSession
  setInput: (value: string) => void
  setDirection: (direction: Direction) => void
  setField: (name: string, value: string) => void
  mergeFields: (values: Record<string, string>) => void
  toggleReveal: (name: string) => void
  maskAllSecrets: () => void
  dockOpen: boolean
  setDockOpen: (open: boolean) => void
  toggleDock: () => void
  railCollapsed: boolean
  toggleRail: () => void
  theme: ThemePreference
  setTheme: (theme: ThemePreference) => void
  resolvedTheme: 'light' | 'dark'
  paletteOpen: boolean
  setPaletteOpen: (open: boolean) => void
  shortcutsOpen: boolean
  setShortcutsOpen: (open: boolean) => void
  selfTestOpen: boolean
  setSelfTestOpen: (open: boolean) => void
  selfTest: SelfTestResult | null
  startSelfTest: () => void
}

export const AppStoreContext = createContext<AppStoreValue | null>(null)

export function useAppStore(): AppStoreValue {
  const value = useContext(AppStoreContext)
  if (!value) throw new Error('useAppStore must be used inside AppStoreProvider')
  return value
}
