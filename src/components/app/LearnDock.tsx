/** The learn dock (DESIGN §2c): 320px third column that pushes the
 * workbench, hairline left border, 200ms slide in/out (skipped under
 * reduced motion). */
import { useEffect, useState } from 'react'
import { ExternalLink, X } from 'lucide-react'
import { cn } from 'cn'

import { useAppStore } from '@/app/store-context'
import { usePrefersReducedMotion } from '@/app/hooks'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'

const SLIDE_MS = 200

/** Keeps the dock mounted during its slide-out so the animation can play,
 * unmounting immediately under reduced motion. */
export function LearnDockHost({ open }: { open: boolean }) {
  const reduced = usePrefersReducedMotion()
  const [mounted, setMounted] = useState(open)
  const [closing, setClosing] = useState(false)

  useEffect(() => {
    if (open) {
      setMounted(true)
      setClosing(false)
      return
    }
    if (!mounted) return
    if (reduced) {
      setMounted(false)
      return
    }
    setClosing(true)
    const timer = setTimeout(() => {
      setMounted(false)
      setClosing(false)
    }, SLIDE_MS)
    return () => clearTimeout(timer)
  }, [open, mounted, reduced])

  if (!mounted) return null
  return <LearnDock closing={closing} />
}

function LearnDock({ closing }: { closing: boolean }) {
  const { method, setDockOpen } = useAppStore()

  return (
    <aside
      aria-label={`Learn: ${method.name}`}
      className={cn(
        'flex h-full w-80 shrink-0 flex-col border-l bg-background',
        closing
          ? 'animate-out slide-out-to-right-2 fade-out-0 duration-200'
          : 'animate-in slide-in-from-right-2 fade-in-0 duration-200',
      )}
    >
      <div className="flex h-8 shrink-0 items-center justify-between pl-3 pr-1.5">
        <span className="text-engraved text-muted-foreground">Learn</span>
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          onClick={() => setDockOpen(false)}
          aria-label="Close learn dock"
        >
          <X className="size-3.5" />
        </Button>
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="px-4 pt-2 pb-4">
          <h1 className="text-2xl font-semibold text-foreground">
            {method.name}
          </h1>
          <Separator className="my-3" />
          <p className="text-base leading-[1.6] text-foreground">
            {method.learn}
          </p>
        </div>
      </ScrollArea>

      <div className="shrink-0 border-t p-3">
        <Button
          variant="ghost"
          className="h-7 gap-1.5 px-2 text-base"
          onClick={() => window.open(method.wikiUrl, '_blank')}
        >
          Read on Wikipedia
          <ExternalLink className="size-3.5" />
        </Button>
      </div>
    </aside>
  )
}
