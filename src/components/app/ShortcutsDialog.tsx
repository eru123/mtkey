/** The "?" keyboard map dialog (DESIGN §5) with the app tagline. */
import { useAppStore } from '@/app/store-context'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Kbd } from '@/components/app/Kbd'

const SHORTCUTS: { keys: string[]; action: string }[] = [
  { keys: ['Ctrl', 'K'], action: 'Open command palette' },
  { keys: ['Esc'], action: 'Close topmost layer: palette, dialog, learn dock' },
  { keys: ['Ctrl', '↵'], action: 'Run now (bypass debounce)' },
  { keys: ['Ctrl', '⇧', 'C'], action: 'Copy output' },
  { keys: ['Ctrl', '⇧', 'X'], action: 'Swap output into input' },
  { keys: ['Ctrl', 'J'], action: 'Toggle learn dock' },
  { keys: ['Ctrl', 'B'], action: 'Collapse / expand method rail' },
  { keys: ['↑', '↓'], action: 'Move selection in rail or palette' },
  { keys: ['Home', 'End'], action: 'First / last method in rail' },
  { keys: ['?'], action: 'This dialog' },
]

export function ShortcutsDialog() {
  const { shortcutsOpen, setShortcutsOpen } = useAppStore()
  return (
    <Dialog open={shortcutsOpen} onOpenChange={setShortcutsOpen}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl">Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            A quiet workbench for ciphers, hashes and tokens.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col">
          {SHORTCUTS.map(({ keys, action }) => (
            <div
              key={action}
              className="flex h-7 items-center justify-between gap-4"
            >
              <span className="min-w-0 truncate text-base">{action}</span>
              <span className="flex shrink-0 items-center gap-1">
                {keys.map((key) => (
                  <Kbd key={key}>{key}</Kbd>
                ))}
              </span>
            </div>
          ))}
        </div>
        <p className="text-2xs text-muted-foreground">
          Ctrl/Cmd means the platform modifier (Ctrl on Windows and Linux,
          Cmd on macOS).
        </p>
      </DialogContent>
    </Dialog>
  )
}
