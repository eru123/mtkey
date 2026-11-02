import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import App from '@/App'

describe('app shell', () => {
  it('starts on Base64 and computes output live while typing', async () => {
    render(<App />)

    // Base64 is selected in the rail and shown as the method name.
    expect(screen.getAllByText('Base64').length).toBeGreaterThan(0)

    // Typing runs through the debounced pipeline and lands in the output.
    const input = screen.getByLabelText('Input')
    fireEvent.change(input, { target: { value: 'foobar' } })

    expect(await screen.findByText('Zm9vYmFy')).toBeDefined()
  })

  it('switches methods from the rail and keeps one-way methods locked', async () => {
    render(<App />)

    fireEvent.click(screen.getByRole('option', { name: 'SHA-256' }))
    expect((await screen.findAllByText('SHA-256')).length).toBeGreaterThan(0)

    // One-way method: exactly one, locked direction segment.
    expect(screen.getAllByRole('tab')).toHaveLength(1)
    fireEvent.change(screen.getByLabelText('Input'), {
      target: { value: 'abc' },
    })
    expect(
      await screen.findByText(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      ),
    ).toBeDefined()
  })
})
