import type { ReactNode } from 'react'
import { cn } from 'cn'

/** A faceplate card: hairline border, engraved uppercase label, card
 * surface, radius-lg, no shadow (DESIGN §4 Card). */
export function Panel({
  label,
  headerRight,
  className,
  contentClassName,
  children,
}: {
  label: string
  headerRight?: ReactNode
  className?: string
  contentClassName?: string
  children: ReactNode
}) {
  return (
    <section
      className={cn(
        'flex flex-col rounded-lg border bg-card text-card-foreground',
        className,
      )}
    >
      <header className="flex h-7 shrink-0 items-center gap-2 px-3">
        <h2 className="text-engraved text-muted-foreground">{label}</h2>
        {headerRight ? (
          <div className="ml-auto flex min-w-0 items-center gap-1.5">
            {headerRight}
          </div>
        ) : null}
      </header>
      <div className={cn('flex min-h-0 flex-col px-3 pb-3', contentClassName)}>
        {children}
      </div>
    </section>
  )
}
