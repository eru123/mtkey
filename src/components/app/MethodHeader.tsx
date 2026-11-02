/** The 48px method header (DESIGN §8): category icon chip, name, blurb
 * with tooltip, direction segmented control (labels always come from the
 * method; one-way methods get a single locked segment), Learn button,
 * Wikipedia link. */
import { BookOpen, ExternalLink } from 'lucide-react'
import { cn } from 'cn'

import type { Direction } from '@/core'

import { useAppStore } from '@/app/store-context'
import { openExternal } from '@/app/open-external'
import { CATEGORY_ICONS, lockedDirection } from '@/app/lib'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

export function MethodHeader() {
  const { method, session, setDirection, dockOpen, toggleDock } = useAppStore()
  const Icon = CATEGORY_ICONS[method.category]
  const oneWay = !method.twoWay

  return (
    <header className="-mx-3 -mt-3 flex h-12 shrink-0 items-center gap-2 border-b px-3">
      <span className="flex size-6 shrink-0 items-center justify-center rounded-sm bg-muted text-muted-foreground">
        <Icon className="size-3.5" />
      </span>
      <h1 className="shrink-0 text-xl font-semibold text-foreground">
        {method.name}
      </h1>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="min-w-0 flex-1 cursor-default truncate text-sm text-muted-foreground">
            {method.blurb}
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-72">{method.blurb}</TooltipContent>
      </Tooltip>

      <div className="ml-auto flex shrink-0 items-center gap-1.5">
        {oneWay ? (
          <LockedDirection />
        ) : (
          <Tabs
            value={session.direction}
            onValueChange={(value) => setDirection(value as Direction)}
          >
            <TabsList className="h-7 gap-0.5 rounded-sm bg-muted p-0.5">
              <TabsTrigger
                value="encode"
                className="h-6 rounded-sm px-2.5 text-sm font-medium text-muted-foreground hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-none dark:text-muted-foreground dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground"
              >
                {method.encodeLabel}
              </TabsTrigger>
              <TabsTrigger
                value="decode"
                className="h-6 rounded-sm px-2.5 text-sm font-medium text-muted-foreground hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-none dark:text-muted-foreground dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground"
              >
                {method.decodeLabel}
              </TabsTrigger>
            </TabsList>
          </Tabs>
        )}

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className={cn('h-7 gap-1.5 px-2 text-base', dockOpen && 'bg-accent')}
              onClick={toggleDock}
              aria-label="Toggle the learn dock"
              aria-pressed={dockOpen}
              aria-keyshortcuts="Control+J Meta+J"
            >
              <BookOpen className="size-3.5" />
              Learn
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Open the learn dock <span className="text-2xs">Ctrl+J</span>
          </TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon-sm"
              className="size-7"
              onClick={() => void openExternal(method.wikiUrl)}
              aria-label={`Read about ${method.name} on Wikipedia (opens in your browser)`}
            >
              <ExternalLink className="size-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Read on Wikipedia</TooltipContent>
        </Tooltip>
      </div>
    </header>
  )
}

function LockedDirection() {
  const { method } = useAppStore()
  const { label, direction } = lockedDirection(method)
  return (
    <Tabs value={direction}>
      <TabsList
        className="h-7 rounded-sm bg-muted p-0.5"
        aria-disabled="true"
      >
        <Tooltip>
          <TooltipTrigger asChild>
            <TabsTrigger
              value={direction}
              aria-disabled="true"
              className="h-6 cursor-not-allowed rounded-sm px-2.5 text-sm font-medium text-muted-foreground data-[state=active]:bg-secondary data-[state=active]:text-muted-foreground data-[state=active]:shadow-none dark:text-muted-foreground dark:data-[state=active]:bg-secondary dark:data-[state=active]:text-muted-foreground"
              tabIndex={-1}
            >
              {label}
            </TabsTrigger>
          </TooltipTrigger>
          <TooltipContent>
            One-way function: there is no un-hashing.
          </TooltipContent>
        </Tooltip>
      </TabsList>
    </Tabs>
  )
}
