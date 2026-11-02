/** The 24px status bar (DESIGN §2/§8): method slug with a state dot on
 * the left, the operation lamp in the center, self-test pill and theme
 * toggle on the right. */
import { FlaskConical, Moon, Sun } from 'lucide-react'
import { cn } from 'cn'

import { useAppStore } from '@/app/store-context'
import { useBench } from '@/app/bench-context'

function lampFor(phase: string | undefined): string {
  switch (phase) {
    case 'computing':
      return 'bg-primary animate-pulse'
    case 'ready':
      return 'bg-success'
    case 'error':
      return 'bg-destructive'
    case 'generating':
      return 'bg-warning'
    default:
      return 'bg-muted-foreground'
  }
}

export function StatusBar() {
  const { method, selfTest, setSelfTestOpen, resolvedTheme, setTheme } =
    useAppStore()
  const bench = useBench()

  const center = bench.generating
    ? bench.generating.label || 'Computing…'
    : (bench.statusNote ??
      (bench.run.phase === 'computing'
        ? 'Computing…'
        : bench.run.phase === 'error'
          ? `Failed (${bench.run.durationMs ?? 0} ms)`
          : bench.run.phase === 'ready'
            ? `Ready (${bench.run.durationMs ?? 0} ms)`
            : 'Ready'))

  const lampPhase = bench.generating
    ? 'generating'
    : bench.statusNote
      ? 'ready'
      : bench.run.phase

  const done = selfTest?.status === 'done'
  const passCount = done ? selfTest.cases.filter((c) => c.pass).length : 0
  const allPass = done && passCount === selfTest.cases.length
  const pillLabel = done
    ? `${passCount}/${selfTest.cases.length} self-test`
    : 'self-test: not run'

  return (
    <footer className="flex h-6 shrink-0 items-center gap-3 border-t bg-background px-3 text-xs">
      <div className="flex min-w-0 items-center gap-2">
        <span
          className={cn('size-1.5 shrink-0 rounded-full', lampFor(lampPhase))}
          aria-hidden
        />
        <span className="text-mono text-muted-foreground">{method.id}</span>
      </div>

      <div className="flex min-w-0 flex-1 items-center justify-center gap-2">
        <span
          className={cn('size-1.5 shrink-0 rounded-full', lampFor(lampPhase))}
          aria-hidden
        />
        <span className="truncate text-muted-foreground" role="status">
          {center}
        </span>
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <button
          type="button"
          onClick={() => setSelfTestOpen(true)}
          className="flex h-5 items-center gap-1.5 rounded-sm px-1.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          aria-label={`Diagnostics: ${pillLabel}. Open the self-test dialog.`}
        >
          <FlaskConical className="size-3" aria-hidden />
          <span
            className={cn(
              'size-1.5 rounded-full',
              !done
                ? 'bg-muted-foreground'
                : allPass
                  ? 'bg-success'
                  : 'bg-destructive',
            )}
            aria-hidden
          />
          <span className="tabular-nums">{pillLabel}</span>
        </button>
        <button
          type="button"
          onClick={() => setTheme(resolvedTheme === 'dark' ? 'light' : 'dark')}
          className="flex size-5 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground"
          aria-label={
            resolvedTheme === 'dark'
              ? 'Switch to light theme'
              : 'Switch to dark theme'
          }
        >
          {resolvedTheme === 'dark' ? (
            <Sun className="size-3" aria-hidden />
          ) : (
            <Moon className="size-3" aria-hidden />
          )}
        </button>
      </div>
    </footer>
  )
}
