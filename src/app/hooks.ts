/** Small DOM-facing hooks: viewport tracking, reduced motion and the
 * auto-growing input textarea. */
import { useCallback, useEffect, useRef, useState } from 'react'

/** Viewport width, kept live via a resize listener. Drives the rail
 * auto-collapse rules in DESIGN §2. */
export function useViewportWidth(): number {
  const [width, setWidth] = useState(() => window.innerWidth)
  useEffect(() => {
    const onResize = () => setWidth(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return width
}

export function usePrefersReducedMotion(): boolean {
  const query = '(prefers-reduced-motion: reduce)'
  const [reduced, setReduced] = useState(() =>
    typeof window.matchMedia === 'function'
      ? window.matchMedia(query).matches
      : false,
  )
  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return
    const media = window.matchMedia(query)
    const onChange = () => setReduced(media.matches)
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])
  return reduced
}

/** Auto-grows a textarea with the current value up to a fraction of the
 * viewport height (40vh per DESIGN §4); beyond that it scrolls inside. */
export function useAutoGrowTextarea(value: string, maxVh = 0.4) {
  const ref = useRef<HTMLTextAreaElement | null>(null)

  const resize = useCallback(() => {
    const el = ref.current
    if (!el) return
    el.style.height = 'auto'
    const max = Math.round(window.innerHeight * maxVh)
    el.style.height = `${Math.min(el.scrollHeight, max)}px`
  }, [maxVh])

  useEffect(() => {
    resize()
  }, [value, resize])

  useEffect(() => {
    window.addEventListener('resize', resize)
    return () => window.removeEventListener('resize', resize)
  }, [resize])

  return ref
}
