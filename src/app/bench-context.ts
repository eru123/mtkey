/** The bench context: the live crypto run pipeline (debounce, sequence
 * token, stale-result discard), field validation, dice rolls, copy and
 * swap. The provider lives in bench.tsx. */
import { createContext, useContext } from 'react'

import type { FieldValidation } from '@/core'

export type BenchPhase = 'idle' | 'computing' | 'ready' | 'error'

export interface BenchRunState {
  phase: BenchPhase
  output: string
  note: string
  warning: string
  error: string
  durationMs: number | null
}

export interface BenchGenerating {
  fields: string[]
  label: string
}

export interface BenchValue {
  run: BenchRunState
  /** Bypass the debounce and process right now (Ctrl/Cmd+Enter). */
  runNow: () => void
  /** Copy the full output; flashes the Copied lamp. */
  copyOutput: () => void
  /** Move output into input, flip direction, re-run (two-way only). */
  swap: () => void
  /** Roll the dice for one field; RSA pairs fill both key fields. */
  rollDice: (fieldName: string) => void
  generating: BenchGenerating | null
  copiedAt: number
  validation: FieldValidation
  /** Transient success line under the parameters card (RSA pair minted). */
  diceNote: string
  /** Throttled screen-reader announcement, 1/s, never content. */
  announcement: string
  /** Temporary center-lamp override, e.g. "Copied to clipboard". */
  statusNote: string | null
}

export const BenchContext = createContext<BenchValue | null>(null)

export function useBench(): BenchValue {
  const value = useContext(BenchContext)
  if (!value) throw new Error('useBench must be used inside BenchProvider')
  return value
}
