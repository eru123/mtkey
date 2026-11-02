/** Ctrl/Cmd+K palette (DESIGN §8): methods grouped by category with
 * aliases as muted secondary text, then an Actions group, kbd footer with
 * the tagline. */
import { useEffect, useState } from 'react'
import {
  BookOpen,
  FlaskConical,
  Moon,
  PanelLeftClose,
  Sun,
} from 'lucide-react'

import { CATEGORY_ORDER, registry, type CipherMethod } from '@/core'

import { useAppStore } from '@/app/store-context'
import { CATEGORY_ICONS } from '@/app/lib'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { Kbd } from '@/components/app/Kbd'

export function CommandPalette() {
  const store = useAppStore()
  const [query, setQuery] = useState('')

  useEffect(() => {
    if (store.paletteOpen) setQuery('')
  }, [store.paletteOpen])

  const close = () => store.setPaletteOpen(false)

  const chooseMethod = (method: CipherMethod) => {
    store.selectMethod(method.id)
    close()
  }

  return (
    <CommandDialog
      open={store.paletteOpen}
      onOpenChange={store.setPaletteOpen}
      className="rounded-xl shadow-overlay sm:max-w-lg"
      title="Command palette"
      description="Search methods and actions"
      showCloseButton={false}
    >
      <CommandInput
        value={query}
        onValueChange={setQuery}
        placeholder="Search methods by name, alias or category…"
      />
      <CommandList>
        <CommandEmpty>
          No method matches “{query.trim()}”.
        </CommandEmpty>
        {CATEGORY_ORDER.map((category) => {
          const Icon = CATEGORY_ICONS[category as CipherMethod['category']]
          return (
            <CommandGroup key={category} heading={category}>
              {registry
                .filter((m) => m.category === category)
                .map((m) => (
                  <CommandItem
                    key={m.id}
                    value={`${m.name} ${m.id} ${m.aliases.join(' ')} ${m.category}`}
                    onSelect={() => chooseMethod(m)}
                  >
                    <Icon className="size-3.5" />
                    <span className="text-base">{m.name}</span>
                    {m.aliases.length > 0 ? (
                      <span className="ml-auto max-w-40 truncate text-xs text-muted-foreground">
                        {m.aliases.join(', ')}
                      </span>
                    ) : null}
                  </CommandItem>
                ))}
            </CommandGroup>
          )
        })}
        <CommandSeparator />
        <CommandGroup heading="Actions">
          <CommandItem
            onSelect={() => {
              store.setTheme(store.resolvedTheme === 'dark' ? 'light' : 'dark')
              close()
            }}
          >
            {store.resolvedTheme === 'dark' ? (
              <Sun className="size-3.5" />
            ) : (
              <Moon className="size-3.5" />
            )}
            Toggle theme
          </CommandItem>
          <CommandItem
            onSelect={() => {
              close()
              store.setSelfTestOpen(true)
            }}
          >
            <FlaskConical className="size-3.5" />
            Run self-test
          </CommandItem>
          <CommandItem
            onSelect={() => {
              store.toggleDock()
              close()
            }}
          >
            <BookOpen className="size-3.5" />
            Toggle learn panel
          </CommandItem>
          <CommandItem
            onSelect={() => {
              store.toggleRail()
              close()
            }}
          >
            <PanelLeftClose className="size-3.5" />
            Collapse method rail
          </CommandItem>
        </CommandGroup>
      </CommandList>
      <div className="flex items-center justify-between gap-3 border-t px-3 py-2">
        <p className="text-2xs text-muted-foreground">
          A quiet workbench for ciphers, hashes and tokens.
        </p>
        <p className="flex shrink-0 items-center gap-1 text-2xs text-muted-foreground">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd>
          navigate
          <Kbd>↵</Kbd>
          open
          <Kbd>esc</Kbd>
          close
        </p>
      </div>
    </CommandDialog>
  )
}
