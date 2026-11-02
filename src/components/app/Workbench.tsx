/** The workbench column (DESIGN §2): method header, parameters card,
 * input card, the swap button in the seam, output card filling the rest.
 * It is a container query context so the parameter grid and input minimum
 * height respond to workbench width, not viewport width. */
import { ArrowUpDown } from 'lucide-react'

import { useAppStore } from '@/app/store-context'
import { useBench } from '@/app/bench-context'
import { InputCard } from '@/components/app/InputCard'
import { MethodHeader } from '@/components/app/MethodHeader'
import { OutputCard } from '@/components/app/OutputCard'
import { ParametersCard } from '@/components/app/ParametersCard'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

export function Workbench() {
  const { method } = useAppStore()
  const { swap } = useBench()

  return (
    <div className="@container flex min-h-full flex-col gap-3 p-3">
      <MethodHeader />
      {method.fields.length > 0 ? <ParametersCard /> : null}
      <InputCard />
      {method.twoWay ? (
        <div className="-my-1 flex h-7 shrink-0 items-center justify-end">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                className="size-7"
                onClick={swap}
                aria-label="Move the output into the input and flip the direction"
                aria-keyshortcuts="Control+Shift+X Meta+Shift+X"
              >
                <ArrowUpDown className="size-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              Swap output into input <span className="text-2xs">Ctrl+Shift+X</span>
            </TooltipContent>
          </Tooltip>
        </div>
      ) : null}
      <OutputCard />
    </div>
  )
}
