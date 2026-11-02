/** AppStoreProvider: session memory + UI state + theme persistence. */
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import {
  findMethod,
  registry,
  runSelfTest as coreRunSelfTest,
  type CipherMethod,
  type Direction,
} from '@/core'

import { defaultDirection } from './lib'
import {
  AppStoreContext,
  THEME_STORAGE_KEY,
  type AppStoreValue,
  type MethodSession,
  type SelfTestResult,
  type ThemePreference,
} from './store-context'

function defaultSession(method: CipherMethod): MethodSession {
  const fields: Record<string, string> = {}
  for (const spec of method.fields) {
    if (spec.default !== undefined) fields[spec.name] = spec.default
  }
  return { input: '', fields, direction: defaultDirection(method), revealed: {} }
}

function readStoredTheme(): ThemePreference {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      return stored
    }
  } catch {
    // storage unavailable: stay dark
  }
  return 'dark'
}

function systemPrefersLight(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: light)').matches
  )
}

export function AppStoreProvider({ children }: { children: ReactNode }) {
  const [methodId, setMethodId] = useState(() => registry[0].id)
  const [sessions, setSessions] = useState<Record<string, MethodSession>>(
    () => ({}),
  )
  const [dockOpen, setDockOpen] = useState(false)
  const [railCollapsed, setRailCollapsed] = useState(false)
  const [theme, setTheme] = useState<ThemePreference>(readStoredTheme)
  const [systemLight, setSystemLight] = useState(systemPrefersLight)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [shortcutsOpen, setShortcutsOpen] = useState(false)
  const [selfTestOpen, setSelfTestOpen] = useState(false)
  const [selfTest, setSelfTest] = useState<SelfTestResult | null>(null)

  const method = useMemo(
    () => findMethod(methodId) ?? registry[0],
    [methodId],
  )

  const session = sessions[methodId] ?? defaultSession(method)

  const updateSession = useCallback(
    (id: string, patch: (current: MethodSession) => MethodSession) => {
      setSessions((prev) => {
        const forMethod = findMethod(id) ?? registry[0]
        const current = prev[id] ?? defaultSession(forMethod)
        return { ...prev, [id]: patch(current) }
      })
    },
    [],
  )

  const selectMethod = useCallback((id: string) => {
    setMethodId(id)
  }, [])

  const setInput = useCallback(
    (value: string) =>
      updateSession(methodId, (s) => ({ ...s, input: value })),
    [methodId, updateSession],
  )

  const setDirection = useCallback(
    (direction: Direction) =>
      updateSession(methodId, (s) => ({ ...s, direction })),
    [methodId, updateSession],
  )

  const setField = useCallback(
    (name: string, value: string) =>
      updateSession(methodId, (s) => ({
        ...s,
        fields: { ...s.fields, [name]: value },
      })),
    [methodId, updateSession],
  )

  const mergeFields = useCallback(
    (values: Record<string, string>) =>
      updateSession(methodId, (s) => ({
        ...s,
        fields: { ...s.fields, ...values },
        revealed: {},
      })),
    [methodId, updateSession],
  )

  const toggleReveal = useCallback(
    (name: string) =>
      updateSession(methodId, (s) => ({
        ...s,
        revealed: { ...s.revealed, [name]: !(s.revealed[name] ?? false) },
      })),
    [methodId, updateSession],
  )

  const maskAllSecrets = useCallback(
    () => updateSession(methodId, (s) => ({ ...s, revealed: {} })),
    [methodId, updateSession],
  )

  const toggleDock = useCallback(() => setDockOpen((open) => !open), [])
  const toggleRail = useCallback(
    () => setRailCollapsed((collapsed) => !collapsed),
    [],
  )

  // Theme: persisted in localStorage, 'system' follows the OS setting.
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const onChange = () => setSystemLight(media.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const resolvedTheme: 'light' | 'dark' =
    theme === 'system' ? (systemLight ? 'light' : 'dark') : theme

  useEffect(() => {
    document.documentElement.classList.toggle('light', resolvedTheme === 'light')
  }, [resolvedTheme])

  useEffect(() => {
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme)
    } catch {
      // storage unavailable: theme lives for this session only
    }
  }, [theme])

  const startSelfTest = useCallback(() => {
    setSelfTest((prev) =>
      prev?.status === 'running'
        ? prev
        : { status: 'running', cases: [], durationMs: 0 },
    )
    const startedAt = performance.now()
    coreRunSelfTest()
      .then((cases) => {
        setSelfTest({
          status: 'done',
          cases,
          durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
        })
      })
      .catch(() => {
        setSelfTest({
          status: 'done',
          cases: [
            {
              name: 'self-test runner',
              pass: false,
              detail: 'The self-test itself crashed.',
            },
          ],
          durationMs: 0,
        })
      })
  }, [])

  const value = useMemo<AppStoreValue>(
    () => ({
      method,
      selectMethod,
      session,
      setInput,
      setDirection,
      setField,
      mergeFields,
      toggleReveal,
      maskAllSecrets,
      dockOpen,
      setDockOpen,
      toggleDock,
      railCollapsed,
      toggleRail,
      theme,
      setTheme,
      resolvedTheme,
      paletteOpen,
      setPaletteOpen,
      shortcutsOpen,
      setShortcutsOpen,
      selfTestOpen,
      setSelfTestOpen,
      selfTest,
      startSelfTest,
    }),
    [
      method,
      selectMethod,
      session,
      setInput,
      setDirection,
      setField,
      mergeFields,
      toggleReveal,
      maskAllSecrets,
      dockOpen,
      toggleDock,
      railCollapsed,
      toggleRail,
      theme,
      resolvedTheme,
      paletteOpen,
      shortcutsOpen,
      selfTestOpen,
      selfTest,
      startSelfTest,
    ],
  )

  return (
    <AppStoreContext.Provider value={value}>
      {children}
    </AppStoreContext.Provider>
  )
}
