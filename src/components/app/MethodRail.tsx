/** The method rail (DESIGN §2/§8): wordmark, filter, six category groups
 * with count badges, 28px items, listbox semantics with roving keyboard
 * focus and type-ahead, collapse to a 48px icon column, and the settings
 * popover in the footer. */
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react'
import {
  FlaskConical,
  Keyboard,
  Monitor,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Settings2,
  Sun,
} from 'lucide-react'
import { cn } from 'cn'

import { registry, searchMethods, type CipherMethod } from '@/core'

import { useAppStore } from '@/app/store-context'
import { CATEGORY_ICONS } from '@/app/lib'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Kbd } from '@/components/app/Kbd'

const RAIL_VERSION = 'MTKey 2.1.0'

export function MethodRail({
  collapsed,
  onToggleCollapsed,
}: {
  collapsed: boolean
  onToggleCollapsed: () => void
}) {
  if (collapsed) {
    return <CollapsedRail onExpand={onToggleCollapsed} />
  }
  return <ExpandedRail onCollapse={onToggleCollapsed} />
}

// ------------------------------------------------------------- expanded

function ExpandedRail({ onCollapse }: { onCollapse: () => void }) {
  const { method, selectMethod } = useAppStore()
  const [filter, setFilter] = useState('')
  const [activeId, setActiveId] = useState(method.id)
  const listRef = useRef<HTMLDivElement | null>(null)

  const filtering = filter.trim().length > 0
  const flat = useMemo(
    () => (filtering ? searchMethods(filter) : registry),
    [filter, filtering],
  )

  useEffect(() => {
    if (flat.some((m) => m.id === activeId)) return
    setActiveId(flat[0]?.id ?? method.id)
  }, [flat, activeId, method.id])

  const select = (id: string) => {
    setActiveId(id)
    selectMethod(id)
  }

  const moveActive = (delta: 1 | -1) => {
    const index = flat.findIndex((m) => m.id === activeId)
    const next = flat[Math.min(flat.length - 1, Math.max(0, index + delta))]
    if (next) setActiveId(next.id)
    document.getElementById(`rail-opt-${next?.id}`)?.scrollIntoView?.({
      block: 'nearest',
    })
  }

  const typeAhead = (char: string) => {
    const index = flat.findIndex((m) => m.id === activeId)
    const pool = flat.slice(index + 1).concat(flat.slice(0, index + 1))
    const match = pool.find((m) =>
      m.name.toLowerCase().startsWith(char.toLowerCase()),
    )
    if (match) {
      setActiveId(match.id)
      document.getElementById(`rail-opt-${match.id}`)?.scrollIntoView?.({
        block: 'nearest',
      })
    }
  }

  const onListKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        moveActive(1)
        break
      case 'ArrowUp':
        event.preventDefault()
        moveActive(-1)
        break
      case 'Home':
        event.preventDefault()
        if (flat[0]) setActiveId(flat[0].id)
        break
      case 'End':
        event.preventDefault()
        if (flat.length > 0) setActiveId(flat[flat.length - 1].id)
        break
      case 'Enter':
        event.preventDefault()
        if (activeId) select(activeId)
        break
      default:
        if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          typeAhead(event.key)
        }
    }
  }

  const groups = useMemo(() => {
    if (filtering) return null
    return Object.entries(
      registry.reduce<Record<string, CipherMethod[]>>((acc, m) => {
        ;(acc[m.category] ??= []).push(m)
        return acc
      }, {}),
    )
  }, [filtering])

  return (
    <aside
      className="flex h-full w-50 shrink-0 flex-col border-r bg-background"
      aria-label="Method rail"
    >
      <div className="flex h-8 shrink-0 items-center px-3">
        <span className="text-sm font-semibold tracking-widest uppercase">
          MTKey
        </span>
      </div>

      <div className="px-3 pb-2">
        <div className="relative">
          <Search
            className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowDown') {
                event.preventDefault()
                listRef.current?.focus()
              }
            }}
            placeholder="Filter…"
            aria-label="Filter methods"
            aria-controls="method-rail-listbox"
            className="h-7 rounded-md pr-2 pl-7 text-sm"
          />
        </div>
      </div>

      <div className="min-h-0 flex-1 px-1.5 pb-1.5">
        <ScrollArea className="h-full">
          <div
            id="method-rail-listbox"
            ref={listRef}
            role="listbox"
            aria-label="Methods"
            tabIndex={0}
            aria-activedescendant={
              activeId ? `rail-opt-${activeId}` : undefined
            }
            onKeyDown={onListKeyDown}
            className="flex flex-col gap-2 outline-none"
          >
            {groups
              ? groups.map(([category, methods]) => (
                  <div
                    key={category}
                    role="group"
                    aria-labelledby={`rail-cat-${category.replace(/\s+/g, '-')}`}
                  >
                    <div
                      id={`rail-cat-${category.replace(/\s+/g, '-')}`}
                      className="flex h-6 items-center justify-between gap-2 px-2"
                    >
                      <span className="text-engraved text-muted-foreground">
                        {category}
                      </span>
                      <Badge
                        variant="secondary"
                        className="h-5 rounded-sm px-1.5 text-2xs tabular-nums"
                      >
                        {methods.length}
                      </Badge>
                    </div>
                    <div className="flex flex-col gap-px">
                      {methods.map((m) => (
                        <RailItem
                          key={m.id}
                          method={m}
                          selected={m.id === method.id}
                          active={m.id === activeId}
                          onSelect={select}
                        />
                      ))}
                    </div>
                  </div>
                ))
              : flat.map((m) => (
                  <RailItem
                    key={m.id}
                    method={m}
                    selected={m.id === method.id}
                    active={m.id === activeId}
                    onSelect={select}
                    showCategory
                  />
                ))}
          </div>
        </ScrollArea>
      </div>

      <div className="flex h-8 shrink-0 items-center gap-0.5 border-t px-1.5">
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          onClick={onCollapse}
          aria-label="Collapse method rail"
          aria-keyshortcuts="Control+B Meta+B"
        >
          <PanelLeftClose className="size-3.5" />
        </Button>
        <SettingsPopover />
        <span
          className="ml-auto pr-1 text-2xs text-muted-foreground"
          title={RAIL_VERSION}
        >
          {RAIL_VERSION}
        </span>
      </div>
    </aside>
  )
}

function RailItem({
  method,
  selected,
  active,
  onSelect,
  showCategory = false,
}: {
  method: CipherMethod
  selected: boolean
  active: boolean
  onSelect: (id: string) => void
  showCategory?: boolean
}) {
  return (
    <button
      type="button"
      id={`rail-opt-${method.id}`}
      role="option"
      aria-selected={selected}
      onClick={() => onSelect(method.id)}
      className={cn(
        'relative flex h-7 w-full items-center gap-1.5 overflow-hidden rounded-sm px-2 text-left text-base whitespace-nowrap transition-colors',
        selected
          ? 'bg-accent text-foreground'
          : 'text-muted-foreground hover:bg-accent hover:text-foreground',
        active && 'ring-1 ring-ring',
      )}
    >
      {selected ? (
        <span
          className="absolute top-1 bottom-1 left-0 w-0.5 rounded-full bg-primary"
          aria-hidden
        />
      ) : null}
      <span className="truncate">{method.name}</span>
      {showCategory ? (
        <span className="ml-auto shrink-0 text-2xs text-muted-foreground">
          {method.category}
        </span>
      ) : null}
    </button>
  )
}

// ------------------------------------------------------------- collapsed

function CollapsedRail({ onExpand }: { onExpand: () => void }) {
  const { method, selectMethod } = useAppStore()
  const [openCategory, setOpenCategory] = useState<string | null>(null)

  const categories = Object.entries(
    registry.reduce<Record<string, CipherMethod[]>>((acc, m) => {
      ;(acc[m.category] ??= []).push(m)
      return acc
    }, {}),
  )

  return (
    <aside
      className="flex h-full w-12 shrink-0 flex-col items-center border-r bg-background py-2"
      aria-label="Method rail (collapsed)"
    >
      <Button
        variant="ghost"
        size="icon-sm"
        className="size-7"
        onClick={onExpand}
        aria-label="Expand method rail"
        aria-keyshortcuts="Control+B Meta+B"
      >
        <PanelLeftOpen className="size-3.5" />
      </Button>

      <div className="mt-2 flex min-h-0 flex-1 flex-col items-center gap-1">
        {categories.map(([category, methods]) => {
          const Icon = CATEGORY_ICONS[category as CipherMethod['category']]
          const containsSelected = method.category === category
          return (
            <Popover
              key={category}
              open={openCategory === category}
              onOpenChange={(open) => setOpenCategory(open ? category : null)}
            >
              <PopoverTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className={cn(
                    'size-7',
                    containsSelected && 'bg-accent text-accent-foreground',
                  )}
                  aria-label={`${category} methods`}
                  aria-expanded={openCategory === category}
                >
                  <Icon className="size-3.5" />
                </Button>
              </PopoverTrigger>
              <PopoverContent side="right" align="start" className="w-44 p-1">
                <p className="text-engraved px-2 py-1 text-muted-foreground">
                  {category}
                </p>
                <div className="flex flex-col">
                  {methods.map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      onClick={() => {
                        selectMethod(m.id)
                        setOpenCategory(null)
                      }}
                      aria-current={m.id === method.id ? 'true' : undefined}
                      className={cn(
                        'flex h-7 items-center rounded-sm px-2 text-left text-base',
                        m.id === method.id
                          ? 'bg-accent text-foreground'
                          : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                      )}
                    >
                      <span className="truncate">{m.name}</span>
                    </button>
                  ))}
                </div>
              </PopoverContent>
            </Popover>
          )
        })}
      </div>

      <SettingsPopover />
    </aside>
  )
}

// ------------------------------------------------------ settings popover

const THEME_ROWS = [
  { key: 'light', label: 'Light', icon: Sun },
  { key: 'dark', label: 'Dark', icon: Moon },
  { key: 'system', label: 'System', icon: Monitor },
] as const

function SettingsPopover() {
  const { theme, setTheme, setSelfTestOpen, setShortcutsOpen } = useAppStore()
  const [open, setOpen] = useState(false)

  const closeAnd = (action: () => void) => () => {
    setOpen(false)
    action()
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          aria-label="Settings"
        >
          <Settings2 className="size-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent side="top" align="start" className="w-64 p-1.5">
        <p className="text-engraved px-2 py-1 text-muted-foreground">Theme</p>
        <div className="flex flex-col">
          {THEME_ROWS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => setTheme(key)}
              aria-pressed={theme === key}
              className={cn(
                'flex h-8 items-center gap-2 rounded-md px-2 text-base hover:bg-accent',
                theme === key
                  ? 'text-foreground'
                  : 'text-muted-foreground',
              )}
            >
              <Icon className="size-3.5" />
              {label}
              {theme === key ? (
                <span
                  className="ml-auto size-1.5 rounded-full bg-primary"
                  aria-hidden
                />
              ) : null}
            </button>
          ))}
        </div>
        <Separator className="my-1.5" />
        <div className="flex flex-col">
          <button
            type="button"
            onClick={closeAnd(() => {
              setSelfTestOpen(true)
            })}
            className="flex h-8 items-center gap-2 rounded-md px-2 text-base text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <FlaskConical className="size-3.5" />
            Run self-test
          </button>
          <button
            type="button"
            onClick={closeAnd(() => {
              setShortcutsOpen(true)
            })}
            className="flex h-8 items-center gap-2 rounded-md px-2 text-base text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <Keyboard className="size-3.5" />
            Keyboard shortcuts
            <span className="ml-auto">
              <Kbd>?</Kbd>
            </span>
          </button>
        </div>
        <Separator className="my-1.5" />
        <p className="px-2 py-1 text-2xs text-muted-foreground">
          {RAIL_VERSION}
        </p>
      </PopoverContent>
    </Popover>
  )
}
