/** The output card (DESIGN §4/§5): fills the remaining workbench height,
 * note lamp + length badge + copy in the header, warning and truncation
 * banners above the output, error replaces the content, internal scroll
 * with wrapping only for newline-containing output, 512 KB display cap,
 * throttled polite announcements that never read the content. */
import { useEffect, useState } from 'react'
import {
  BookOpen,
  Check,
  Copy,
  Info,
  LoaderCircle,
} from 'lucide-react'
import { ScrollArea as ScrollAreaPrimitive } from 'radix-ui'
import { cn } from 'cn'

import { useAppStore } from '@/app/store-context'
import { useBench } from '@/app/bench-context'
import { usePrefersReducedMotion } from '@/app/hooks'
import { DISPLAY_CAP, formatOutputLength } from '@/app/lib'
import { BenchMessage } from '@/components/app/BenchMessage'
import { Panel } from '@/components/app/Panel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollBar } from '@/components/ui/scroll-area'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

export function OutputCard() {
  const { run, copiedAt, copyOutput, announcement } = useBench()
  const { session } = useAppStore()
  const reduced = usePrefersReducedMotion()
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (copiedAt === 0) return
    setCopied(true)
    const timer = setTimeout(() => setCopied(false), 1200)
    return () => clearTimeout(timer)
  }, [copiedAt])

  const hasOutput = run.output.length > 0
  const computing = run.phase === 'computing'
  // With nothing typed, parameter errors ("needs a key") stay in the
  // status bar instead of shouting over the empty state.
  const failed = run.phase === 'error' && session.input.length > 0
  const truncated = run.output.length > DISPLAY_CAP
  const display = truncated ? run.output.slice(0, DISPLAY_CAP) : run.output
  const wrap = display.includes('\n')

  return (
    <Panel
      label="Output"
      className="min-h-40 flex-1"
      contentClassName="gap-1.5"
      headerRight={
        <>
          {computing ? (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              {!reduced ? (
                <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
              ) : null}
              Computing…
            </span>
          ) : null}
          {run.note && !computing ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex min-w-0 items-center gap-1 text-xs text-muted-foreground">
                  <Info className="size-3.5 shrink-0" aria-hidden />
                  <span className="max-w-48 truncate">{run.note}</span>
                </span>
              </TooltipTrigger>
              <TooltipContent className="max-w-80">{run.note}</TooltipContent>
            </Tooltip>
          ) : null}
          {hasOutput ? (
            <Badge
              variant="outline"
              className="h-5 rounded-sm px-1.5 text-xs font-medium tabular-nums"
            >
              {formatOutputLength(run.output)}
            </Badge>
          ) : null}
          <Button
            variant="ghost"
            size="sm"
            className="h-7 gap-1.5 px-2 text-base"
            onClick={copyOutput}
            disabled={!hasOutput}
            aria-label="Copy the full output to the clipboard"
            aria-keyshortcuts="Control+Shift+C Meta+Shift+C"
          >
            {copied ? (
              <Check className="size-3.5 text-success-soft-foreground" />
            ) : (
              <Copy className="size-3.5" />
            )}
            <span
              className={
                copied ? 'text-success-soft-foreground' : undefined
              }
            >
              {copied ? 'Copied' : 'Copy'}
            </span>
          </Button>
        </>
      }
    >
      {run.warning ? (
        <BenchMessage variant="warning">{run.warning}</BenchMessage>
      ) : null}
      {truncated ? (
        <BenchMessage variant="note">
          Display truncated at 512 KB. Copy copies the full result.
        </BenchMessage>
      ) : null}

      {failed ? (
        <BenchMessage variant="error" className="flex-1">
          {run.error}
        </BenchMessage>
      ) : hasOutput ? (
        <ScrollAreaPrimitive.Root className="min-h-0 flex-1 overflow-hidden">
          <ScrollAreaPrimitive.Viewport className="size-full">
            <pre
              aria-label="Output"
              className={cn(
                'text-mono',
                wrap ? 'whitespace-pre-wrap break-words' : 'w-max whitespace-pre',
              )}
            >
              {display}
            </pre>
          </ScrollAreaPrimitive.Viewport>
          <ScrollBar orientation="vertical" />
          {wrap ? null : <ScrollBar orientation="horizontal" />}
        </ScrollAreaPrimitive.Root>
      ) : (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 py-6 text-muted-foreground">
          <BookOpen className="size-5" aria-hidden />
          <p className="text-sm">
            Type or paste something. Output appears here as you type.
          </p>
        </div>
      )}

      <span role="status" aria-live="polite" className="sr-only">
        {announcement}
      </span>
    </Panel>
  )
}
