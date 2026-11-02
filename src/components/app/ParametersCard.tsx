/** The parameters card (DESIGN §4/§5): ParamGrid (2 columns at 560px+
 * workbench width), FieldRow per FieldSpec with dice, secret masking and
 * live debounced validation, plus the overall verdict BenchMessage under
 * the card. */
import type { ReactNode } from 'react'
import {
  CircleCheck,
  CircleX,
  Dices,
  Eye,
  EyeOff,
  LoaderCircle,
} from 'lucide-react'
import { cn } from 'cn'

import type { FieldSpec } from '@/core'

import { useAppStore } from '@/app/store-context'
import { useBench } from '@/app/bench-context'
import { BenchMessage } from '@/components/app/BenchMessage'
import { Panel } from '@/components/app/Panel'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'

export function ParametersCard() {
  const { method } = useAppStore()
  const { validation, diceNote } = useBench()

  const overall = validation.overall || diceNote
  const overallOk =
    Object.values(validation.fields).every((v) => v.ok) && !!validation.overall

  return (
    <Panel label="Parameters">
      <div className="grid grid-cols-1 gap-3 @min-[560px]:grid-cols-2">
        {method.fields.map((spec) => (
          <FieldRow key={spec.name} spec={spec} />
        ))}
      </div>
      {overall ? (
        <BenchMessage
          variant={overallOk || !validation.overall ? 'success' : 'error'}
          className="mt-3"
        >
          {overall}
        </BenchMessage>
      ) : null}
    </Panel>
  )
}

function FieldRow({ spec }: { spec: FieldSpec }) {
  const { session, setField, toggleReveal } = useAppStore()
  const { generating, rollDice, validation } = useBench()

  const value = session.fields[spec.name] ?? ''
  const revealed = session.revealed[spec.name] ?? false
  const isGenerating = generating?.fields.includes(spec.name) ?? false
  const verdict = validation.fields[spec.name]
  const isMultiline = spec.kind === 'multiline'
  const maskedSecret = spec.secret && !revealed
  // Slot buttons live inside single-line inputs (DESIGN §5) and in the
  // label row for textareas, where there is no inside-right slot.
  const slotsInline = !isMultiline || maskedSecret

  const eyeButton = spec.secret ? (
    <Button
      variant="ghost"
      size="icon-sm"
      className="size-6"
      onClick={() => toggleReveal(spec.name)}
      aria-label={revealed ? `Hide ${spec.label}` : `Show ${spec.label}`}
      aria-pressed={revealed}
    >
      {revealed ? (
        <EyeOff className="size-3.5" />
      ) : (
        <Eye className="size-3.5" />
      )}
    </Button>
  ) : null

  const diceButton = spec.generator ? (
    <Button
      variant="ghost"
      size="icon-sm"
      className="size-6"
      onClick={() => rollDice(spec.name)}
      disabled={isGenerating}
      aria-label={`Generate ${spec.label.toLowerCase()}`}
    >
      {isGenerating ? (
        <LoaderCircle className="size-3.5 animate-spin" />
      ) : (
        <Dices className="size-3.5" />
      )}
    </Button>
  ) : null

  const slotButtons =
    eyeButton || diceButton ? (
      <div className="flex items-center gap-0.5">
        {eyeButton}
        {diceButton}
      </div>
    ) : null

  const controlId = `param-${spec.name}`

  let control: ReactNode
  if (spec.kind === 'dropdown' && spec.options) {
    control = (
      <Select
        value={value || spec.default}
        onValueChange={(next) => setField(spec.name, next)}
      >
        <SelectTrigger
          id={controlId}
          disabled={isGenerating}
          className="h-8 w-full rounded-md text-base"
        >
          <SelectValue placeholder={spec.placeholder} />
        </SelectTrigger>
        <SelectContent className="rounded-lg">
          {spec.options.map((option) => (
            <SelectItem key={option} value={option} className="h-7 text-sm">
              {option}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    )
  } else if (isMultiline && !maskedSecret) {
    control = (
      <Textarea
        id={controlId}
        value={value}
        onChange={(event) => setField(spec.name, event.target.value)}
        placeholder={spec.placeholder}
        disabled={isGenerating}
        aria-label={spec.label}
        className="min-h-20 w-full resize-y rounded-md p-2.5 text-mono"
        rows={3}
      />
    )
  } else {
    const inputType = maskedSecret
      ? 'password'
      : spec.kind === 'number'
        ? 'number'
        : 'text'
    control = (
      <div className="relative">
        <Input
          id={controlId}
          type={inputType}
          value={value}
          onChange={(event) => setField(spec.name, event.target.value)}
          placeholder={spec.placeholder}
          min={spec.min}
          max={spec.max}
          disabled={isGenerating}
          autoComplete="off"
          spellCheck={false}
          className={cn(
            'h-8 rounded-md px-2.5 text-mono',
            slotsInline && slotButtons && 'pr-14',
          )}
        />
        {slotsInline && slotButtons ? (
          <div className="absolute top-1/2 right-1 flex -translate-y-1/2 items-center gap-0.5">
            {slotButtons}
          </div>
        ) : null}
      </div>
    )
  }

  return (
    <div
      className={cn(
        'flex flex-col gap-1',
        isMultiline && '@min-[560px]:col-span-2',
      )}
    >
      <div className="flex h-5 items-center justify-between gap-2">
        <Label
          htmlFor={controlId}
          className="text-engraved text-muted-foreground"
        >
          {spec.label}
        </Label>
        {!slotsInline && slotButtons ? slotButtons : null}
      </div>
      {control}
      {spec.hint ? (
        <p className="text-2xs leading-snug text-muted-foreground">
          {spec.hint}
        </p>
      ) : null}
      {verdict?.certain && verdict.message ? (
        <p
          className={cn(
            'flex items-center gap-1 text-2xs leading-snug',
            verdict.ok
              ? 'text-success-soft-foreground'
              : 'text-destructive-soft-foreground',
          )}
        >
          {verdict.ok ? (
            <CircleCheck className="size-3 shrink-0" aria-hidden />
          ) : (
            <CircleX className="size-3 shrink-0" aria-hidden />
          )}
          {verdict.message}
        </p>
      ) : null}
    </div>
  )
}
