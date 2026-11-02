import type { ReactNode } from 'react'
import {
  CircleCheck,
  CircleX,
  Info,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import { cn } from 'cn'

/** The instrument's message strips, DESIGN §5: note, warning, error and
 * success. Full sentences from the core, never raw exception text. */
export type BenchVariant = 'note' | 'warning' | 'error' | 'success'

const VARIANTS: Record<BenchVariant, { box: string; icon: string }> = {
  note: {
    box: 'bg-muted text-muted-foreground',
    icon: 'text-muted-foreground',
  },
  warning: {
    box: 'bg-warning-soft text-warning-soft-foreground border-l-2 border-l-warning',
    icon: 'text-warning',
  },
  error: {
    box: 'bg-destructive-soft text-destructive-soft-foreground',
    icon: 'text-destructive',
  },
  success: {
    box: 'bg-success-soft text-success-soft-foreground',
    icon: 'text-success',
  },
}

const ICONS: Record<BenchVariant, LucideIcon> = {
  note: Info,
  warning: TriangleAlert,
  error: CircleX,
  success: CircleCheck,
}

export function BenchMessage({
  variant = 'note',
  className,
  children,
}: {
  variant?: BenchVariant
  className?: string
  children: ReactNode
}) {
  const Icon = ICONS[variant]
  return (
    <div
      role={variant === 'error' ? 'alert' : undefined}
      className={cn(
        'flex items-start gap-2 rounded-md px-3 py-2 text-sm leading-snug',
        VARIANTS[variant].box,
        className,
      )}
    >
      <Icon
        className={cn('mt-0.5 size-3.5 shrink-0', VARIANTS[variant].icon)}
        aria-hidden
      />
      <span className="min-w-0">{children}</span>
    </div>
  )
}
