import type { ReactNode } from 'react'

/** Keyboard hint chip, DESIGN §4: text-2xs mono, radius-sm, hairline
 * border on the secondary surface. */
export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded-sm border bg-secondary px-1 font-mono text-2xs font-medium text-muted-foreground">
      {children}
    </kbd>
  )
}
