import { useEffect, useRef, useState } from 'react'

// usePoll runs fn now and then every ms while enabled. The latest fn is always
// used, so callers don't need to memoize it; changing deps re-runs it at once.
export function usePoll(fn: () => void, ms: number, enabled = true, deps: unknown[] = []) {
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    if (!enabled) return
    ref.current()
    const id = setInterval(() => ref.current(), ms)
    return () => clearInterval(id)
  }, [ms, enabled, ...deps])
}

// useDebounced returns value once it has stopped changing for ms.
export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

// useStored is useState persisted to localStorage (per-viewer conveniences
// like a remembered range). Storage failures fall back to plain state.
export function useStored<T extends string>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      return (localStorage.getItem(key) as T) ?? initial
    } catch {
      return initial
    }
  })
  const set = (nv: T) => {
    setV(nv)
    try {
      localStorage.setItem(key, nv)
    } catch {
      // ignore
    }
  }
  return [v, set]
}
