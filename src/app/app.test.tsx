import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import App from '@/App'

describe('app shell', () => {
  it('renders the scaffolding placeholder', () => {
    render(<App />)
    expect(screen.getByText('MTKey')).toBeDefined()
    expect(screen.getByText(/workbench scaffolding ready/i)).toBeDefined()
  })
})
