/** BenchProvider: wires the store's session state into the crypto core.
 * Runs are debounced (120ms / 500ms heavy) with a run-sequence token so
 * stale results are discarded, last-write-wins, per DESIGN §5. */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import {
  CipherError,
  emptyValidation,
  generateForField,
  type FieldValidation,
} from '@/core'

import { BenchContext, type BenchRunState, type BenchValue } from './bench-context'
import { useAppStore } from './store-context'
import { diceAnnouncement, isHeavyMethod } from './lib'

const IDLE_RUN: BenchRunState = {
  phase: 'idle',
  output: '',
  note: '',
  warning: '',
  error: '',
  durationMs: null,
}

const EMPTY_VALIDATION = emptyValidation()

export function BenchProvider({ children }: { children: ReactNode }) {
  const { method, session, setInput, setDirection, mergeFields } = useAppStore()
  const { input, direction, fields } = session

  const [run, setRun] = useState<BenchRunState>(IDLE_RUN)
  const [generating, setGenerating] = useState<BenchValue['generating']>(null)
  const [copiedAt, setCopiedAt] = useState(0)
  const [validation, setValidation] = useState<FieldValidation>(EMPTY_VALIDATION)
  const [diceNote, setDiceNote] = useState('')
  const [announcement, setAnnouncement] = useState('')
  const [statusNote, setStatusNote] = useState<string | null>(null)

  const runSeq = useRef(0)
  const validationSeq = useRef(0)
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const announceState = useRef({ last: 0, timer: undefined as ReturnType<typeof setTimeout> | undefined })
  const statusNoteTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const runRef = useRef(run)
  runRef.current = run
  const methodIdRef = useRef(method.id)
  methodIdRef.current = method.id

  const announce = useCallback((text: string) => {
    const state = announceState.current
    if (state.timer) {
      clearTimeout(state.timer)
      state.timer = undefined
    }
    const wait = Math.max(0, state.last + 1000 - Date.now())
    if (wait === 0) {
      state.last = Date.now()
      setAnnouncement(text)
    } else {
      state.timer = setTimeout(() => {
        state.last = Date.now()
        setAnnouncement(text)
      }, wait)
    }
  }, [])

  const flashStatusNote = useCallback((text: string) => {
    if (statusNoteTimer.current) clearTimeout(statusNoteTimer.current)
    setStatusNote(text)
    statusNoteTimer.current = setTimeout(() => setStatusNote(null), 2000)
  }, [])

  // ------------------------------------------------------- the pipeline
  const heavy = isHeavyMethod(method, fields)

  const execute = useCallback(async () => {
    const seq = ++runSeq.current
    setRun((prev) => ({ ...prev, phase: 'computing' }))
    if (heavy) announce('Computing')
    const startedAt = performance.now()
    try {
      const result = await method.process({ direction, input, fields })
      if (seq !== runSeq.current) return
      setRun({
        phase: 'ready',
        output: result.output,
        note: result.note ?? '',
        warning: result.warning ?? '',
        error: '',
        durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
      })
      if (result.output.length > 0) announce('Output updated')
    } catch (error) {
      if (seq !== runSeq.current) return
      const message =
        error instanceof CipherError
          ? error.message
          : error instanceof Error
            ? error.message
            : 'The operation failed.'
      setRun({
        phase: 'error',
        output: '',
        note: '',
        warning: '',
        error: message,
        durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
      })
      announce(message)
    }
  }, [announce, direction, fields, heavy, input, method])

  useEffect(() => {
    if (generating) return
    const delay = heavy ? 500 : 120
    debounceTimer.current = setTimeout(() => void execute(), delay)
    return () => clearTimeout(debounceTimer.current)
  }, [execute, generating, heavy])

  const runNow = useCallback(() => {
    if (generating) return
    // Bypass the debounce: cancel the pending run, then run immediately.
    clearTimeout(debounceTimer.current)
    runSeq.current += 1 // invalidate any in-flight run from the old state
    void execute()
  }, [execute, generating])

  // Reset the bench when the method changes; the debounced run refills it.
  useEffect(() => {
    runSeq.current += 1
    validationSeq.current += 1
    setRun(IDLE_RUN)
    setValidation(EMPTY_VALIDATION)
    setDiceNote('')
    setGenerating(null)
  }, [method.id])

  // ------------------------------------------- live field validation
  useEffect(() => {
    if (!method.validateFields) {
      setValidation(EMPTY_VALIDATION)
      return
    }
    const seq = ++validationSeq.current
    const timer = setTimeout(() => {
      method
        .validateFields!(fields)
        .then((result) => {
          if (seq === validationSeq.current) setValidation(result)
        })
        .catch(() => {
          if (seq === validationSeq.current) setValidation(EMPTY_VALIDATION)
        })
    }, 300)
    return () => clearTimeout(timer)
  }, [fields, method])

  // Once live validation reports a pair verdict it supersedes the dice note.
  useEffect(() => {
    if (validation.overall) setDiceNote('')
  }, [validation.overall])

  // ------------------------------------------------------------- copy
  const copyOutput = useCallback(() => {
    const value = runRef.current.output
    if (value.length === 0) return
    const write = async () => {
      try {
        await navigator.clipboard.writeText(value)
      } catch {
        // Clipboard API unavailable: legacy fallback.
        const helper = document.createElement('textarea')
        helper.value = value
        helper.setAttribute('readonly', '')
        helper.style.position = 'fixed'
        helper.style.opacity = '0'
        document.body.appendChild(helper)
        helper.select()
        try {
          document.execCommand('copy')
        } finally {
          helper.remove()
        }
      }
      setCopiedAt(Date.now())
      flashStatusNote('Copied to clipboard')
      announce('Output copied to clipboard')
    }
    void write()
  }, [announce, flashStatusNote])

  // ------------------------------------------------------------- swap
  const swap = useCallback(() => {
    const current = runRef.current
    if (!method.twoWay || current.phase !== 'ready' || current.output.length === 0) {
      return
    }
    const nextDirection = direction === 'encode' ? 'decode' : 'encode'
    runSeq.current += 1
    setRun(IDLE_RUN)
    setInput(current.output)
    setDirection(nextDirection)
    announce(
      `Direction switched to ${nextDirection === 'encode' ? method.encodeLabel : method.decodeLabel}`,
    )
  }, [announce, direction, method, setDirection, setInput])

  // ------------------------------------------------------------- dice
  const rollDice = useCallback(
    (fieldName: string) => {
      const spec = method.fields.find((f) => f.name === fieldName)
      if (!spec?.generator) return
      const isPair = spec.generator === 'rsaKeyPair'
      const targetFields = isPair
        ? method.fields.filter((f) => f.generator === 'rsaKeyPair').map((f) => f.name)
        : [fieldName]
      const capturedMethodId = method.id
      setGenerating({
        fields: targetFields,
        label: isPair ? `Generating RSA-${(fields['bits'] ?? '2048')} pair…` : '',
      })
      const fill = async () => {
        try {
          const values = await generateForField(method, fieldName, fields)
          if (methodIdRef.current !== capturedMethodId) return
          mergeFields(values)
          if (isPair) setDiceNote('Key pair generated and verified.')
          announce(diceAnnouncement(spec))
        } catch (error) {
          if (methodIdRef.current !== capturedMethodId) return
          announce(error instanceof Error ? error.message : 'Generation failed.')
        } finally {
          if (methodIdRef.current === capturedMethodId) setGenerating(null)
        }
      }
      void fill()
    },
    [announce, fields, mergeFields, method],
  )

  const value = useMemo<BenchValue>(
    () => ({
      run,
      runNow,
      copyOutput,
      swap,
      rollDice,
      generating,
      copiedAt,
      validation,
      diceNote,
      announcement,
      statusNote,
    }),
    [
      run,
      runNow,
      copyOutput,
      swap,
      rollDice,
      generating,
      copiedAt,
      validation,
      diceNote,
      announcement,
      statusNote,
    ],
  )

  return <BenchContext.Provider value={value}>{children}</BenchContext.Provider>
}
