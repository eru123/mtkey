/** The self-test dialog (DESIGN §8): runs the core's known-answer suite on
 * open, dense mono rows, pass/fail lamps, Re-run. Also the target of the
 * status bar pill — the instrument's diagnostics switch. */
import { useEffect } from 'react'
import { CircleCheck, CircleX, LoaderCircle } from 'lucide-react'
import { cn } from 'cn'

import { selfTestDetail } from '@/core'

import { useAppStore } from '@/app/store-context'
import { BenchMessage } from '@/components/app/BenchMessage'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ScrollArea } from '@/components/ui/scroll-area'

export function SelfTestDialog() {
  const { selfTestOpen, setSelfTestOpen, selfTest, startSelfTest } =
    useAppStore()

  useEffect(() => {
    if (selfTestOpen) startSelfTest()
  }, [selfTestOpen, startSelfTest])

  const running = selfTest?.status !== 'done'
  const cases = selfTest?.status === 'done' ? selfTest.cases : []
  const passed = cases.filter((c) => c.pass).length
  const failed = cases.length - passed
  const summary =
    selfTest?.status === 'done'
      ? failed === 0
        ? `${passed}/${cases.length} passed in ${selfTest.durationMs} ms`
        : `${passed}/${cases.length} — ${failed} failed`
      : 'The self-test hasn’t run this session. It checks known-answer vectors, including PHP cross-language ones.'

  return (
    <Dialog open={selfTestOpen} onOpenChange={setSelfTestOpen}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-xl">Self-test</DialogTitle>
          <DialogDescription className="tabular-nums">
            {summary}
          </DialogDescription>
        </DialogHeader>

        {running ? (
          <div className="flex h-40 flex-col items-center justify-center gap-2 text-muted-foreground">
            <LoaderCircle className="size-5 animate-spin" aria-hidden />
            <p className="text-sm">
              The self-test hasn’t run this session. It checks known-answer
              vectors, including PHP cross-language ones.
            </p>
          </div>
        ) : (
          <ScrollArea className="h-72 rounded-md border">
            <div className="flex flex-col p-1">
              {cases.map((testCase) => (
                <div
                  key={testCase.name}
                  className="flex h-7 items-center gap-2 px-1.5"
                  title={testCase.detail}
                >
                  {testCase.pass ? (
                    <CircleCheck
                      className="size-3.5 shrink-0 text-success"
                      aria-hidden
                    />
                  ) : (
                    <CircleX
                      className="size-3.5 shrink-0 text-destructive"
                      aria-hidden
                    />
                  )}
                  <span
                    className={cn(
                      'truncate text-mono',
                      testCase.pass
                        ? 'text-foreground'
                        : 'text-destructive-soft-foreground',
                    )}
                  >
                    {testCase.name}
                  </span>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}

        {failed > 0 ? (
          <BenchMessage variant="error">{selfTestDetail(cases)}</BenchMessage>
        ) : null}

        <DialogFooter>
          <Button
            variant="secondary"
            className="h-7 px-2 text-base"
            onClick={startSelfTest}
            disabled={running}
          >
            Re-run
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
