/** The input card (DESIGN §4): mono textarea, 96px minimum (72px in a
 * narrow workbench), auto-grows to 40vh then scrolls inside. */
import { useAppStore } from '@/app/store-context'
import { useAutoGrowTextarea } from '@/app/hooks'
import { Panel } from '@/components/app/Panel'
import { Textarea } from '@/components/ui/textarea'

export function InputCard() {
  const { session, setInput } = useAppStore()
  const ref = useAutoGrowTextarea(session.input)

  return (
    <Panel label="Input">
      <Textarea
        ref={ref}
        value={session.input}
        onChange={(event) => setInput(event.target.value)}
        placeholder="Input"
        aria-label="Input"
        spellCheck={false}
        className="max-h-[40vh] min-h-18 w-full resize-none rounded-md p-2.5 text-mono @min-[560px]:min-h-24"
      />
    </Panel>
  )
}
