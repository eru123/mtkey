/** UI wiring tests: CipherError paths surface as error banners through the
 * real app shell, the debounced pipeline only commits the latest run, and
 * copy copies the full output even when the display is capped. */
import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { findMethod, type CipherResult } from '@/core'
import { newKey, saveKeyAscii } from '@/core/defuse'
import { DISPLAY_CAP } from '@/app/lib'

const KEY32 = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
const NONCE12 = '0f0e0d0c0b0a090807060504'

const outputText = () =>
  document.querySelector('pre[aria-label="Output"]')?.textContent ?? ''

/** Radix TabsTrigger activates on mousedown; a bare fireEvent.click is
 * not a real browser click, so send both. */
function clickTab(name: string | RegExp) {
  const tab = screen.getByRole('tab', { name })
  fireEvent.mouseDown(tab)
  fireEvent.click(tab)
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

describe('error paths surface as banners', () => {
  it('invalid base64 decode shows the error, not a crash', async () => {
    render(<App />)
    clickTab('Decode')
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: '###' } })

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toBe('Base64 input contains invalid characters.')
    // The empty-state / banner layout is still standing.
    expect(screen.getByText('Output')).toBeDefined()
  })

  it('wrong AES key size names the wanted sizes', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('option', { name: 'AES-256-GCM' }))
    fireEvent.change(screen.getByLabelText('Key'), { target: { value: 'abcd' } })
    fireEvent.change(screen.getByLabelText('Nonce'), { target: { value: NONCE12 } })
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: 'hello' } })

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/128 or 192 or 256-bit key/)
    expect(alert.textContent).toContain('Got 2')
  })

  it('tampered GCM ciphertext fails authentication through the UI', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('option', { name: 'AES-256-GCM' }))
    fireEvent.change(screen.getByLabelText('Key'), { target: { value: KEY32 } })
    fireEvent.change(screen.getByLabelText('Nonce'), { target: { value: NONCE12 } })
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: 'gcm ui roundtrip' } })

    const ciphertext = await vi.waitFor(() => {
      const text = outputText()
      expect(text.length).toBeGreaterThan(0)
      return text
    })

    // Flip one ciphertext byte, keep valid base64.
    const bytes = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0))
    bytes[0] ^= 0x01
    const tampered = btoa(String.fromCharCode(...bytes))

    clickTab('Decode')
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: tampered } })

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Authentication failed/)
  })

  it('defuse tampered ciphertext reports the integrity failure', async () => {
    const keyAscii = saveKeyAscii(newKey())
    render(<App />)
    fireEvent.click(screen.getByRole('option', { name: 'Defuse Authenticated (key)' }))
    fireEvent.change(screen.getByLabelText('Defuse key'), { target: { value: keyAscii } })
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: 'do not touch' } })

    const ciphertext = await vi.waitFor(() => {
      const text = outputText()
      expect(text).toMatch(/^def50200/)
      return text
    })

    const flipped =
      ciphertext.slice(0, -1) + (ciphertext.endsWith('0') ? '1' : '0')
    clickTab('Decode')
    fireEvent.change(screen.getByLabelText('Input'), { target: { value: flipped } })

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Integrity check failed/)
  })

  it('JWT wrong secret warns but still renders header and payload', async () => {
    render(<App />)
    fireEvent.click(screen.getByRole('option', { name: 'JWT' }))
    fireEvent.change(screen.getByLabelText('HMAC secret'), { target: { value: 'wrong-secret' } })
    clickTab('Decode & verify')
    fireEvent.change(screen.getByLabelText('Input'), {
      target: {
        value:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' +
          'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      },
    })

    expect(
      await screen.findByText('Signature verification failed.')
    ).toBeDefined()
    expect(outputText()).toContain('"sub": "1234567890"')
    expect(outputText()).toContain('"name": "John Doe"')
  })
})

describe('debounce and run sequence', () => {
  it('rapid input changes produce only the final result', async () => {
    vi.useFakeTimers()
    const base64 = findMethod('base64')!
    const original = base64.process
    const spy = vi.fn(async (request: { input: string }) => {
      void request
      return { output: 'final' } as CipherResult
    })
    base64.process = spy

    render(<App />)
    const input = screen.getByLabelText('Input')
    for (const value of ['a', 'ab', 'abc', 'abcd']) {
      fireEvent.change(input, { target: { value } })
    }

    await act(async () => {
      vi.advanceTimersByTime(130)
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy.mock.calls[0]?.[0]?.input).toBe('abcd')
    expect(outputText()).toBe('final')

    base64.process = original
  })

  it('Ctrl+Enter bypasses the debounce without double-running', async () => {
    vi.useFakeTimers()
    const base64 = findMethod('base64')!
    const original = base64.process
    const spy = vi.fn(async (request: { input: string }) => {
      void request
      return { output: `ran:${request.input}` } as CipherResult
    })
    base64.process = spy

    render(<App />)
    fireEvent.change(screen.getByLabelText('Input'), {
      target: { value: 'force me' },
    })
    // Run now, while the 120ms debounce is still pending.
    fireEvent.keyDown(window, { key: 'Enter', ctrlKey: true })
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(outputText()).toBe('ran:force me')

    // The superseded debounce timer must not fire a second run.
    await act(async () => {
      vi.advanceTimersByTime(500)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(spy).toHaveBeenCalledTimes(1)
    expect(outputText()).toBe('ran:force me')

    base64.process = original
  })

  it('a stale slow run cannot overwrite a newer fast result', async () => {
    vi.useFakeTimers()
    const base64 = findMethod('base64')!
    const original = base64.process
    let resolveSlow: (result: CipherResult) => void = () => undefined
    base64.process = (request) => {
      if (request.input === 'slow-input') {
        return new Promise<CipherResult>((resolve) => {
          resolveSlow = resolve
        })
      }
      return Promise.resolve({ output: `fast:${request.input}` })
    }

    render(<App />)
    const input = screen.getByLabelText('Input')

    fireEvent.change(input, { target: { value: 'slow-input' } })
    await act(async () => {
      vi.advanceTimersByTime(130)
    })
    // The slow run is now in flight (phase computing, no output yet).

    fireEvent.change(input, { target: { value: 'quick' } })
    await act(async () => {
      vi.advanceTimersByTime(130)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(outputText()).toBe('fast:quick')

    // The slow run finally lands; its sequence token is stale, so the
    // newer fast result must survive.
    await act(async () => {
      resolveSlow({ output: 'STALE OVERWRITE' })
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(outputText()).toBe('fast:quick')
    expect(screen.queryByText('STALE OVERWRITE')).toBeNull()

    base64.process = original
  })
})

describe('copy and the 512 KB display cap', () => {
  it('copies the full output while the display is truncated', async () => {
    const writeText = vi.fn((text: string) => {
      void text
      return Promise.resolve()
    })
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })

    render(<App />)
    // 400,000 chars of input base64-encode past the 512 KB display cap.
    fireEvent.change(screen.getByLabelText('Input'), {
      target: { value: 'a'.repeat(400_000) },
    })

    await vi.waitFor(() => {
      expect(outputText().length).toBe(DISPLAY_CAP)
    })
    expect(
      screen.getByText('Display truncated at 512 KB. Copy copies the full result.')
    ).toBeDefined()

    fireEvent.click(
      screen.getByRole('button', { name: 'Copy the full output to the clipboard' })
    )
    await vi.waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))

    const copied = writeText.mock.calls[0][0]
    expect(copied.length).toBeGreaterThan(DISPLAY_CAP)
    expect(copied.length % 4).toBe(0) // complete base64, no mid-stream cut
    expect(await screen.findByText('Copied')).toBeDefined()
  })
})
