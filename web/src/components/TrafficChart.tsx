import { MouseEvent, useMemo, useState } from 'react'
import { Bucket } from '../types'

// A lightweight responsive area chart (requests + blocked per bucket) drawn with
// SVG. The plot uses a 0..100 viewBox with non-scaling strokes so lines stay
// crisp at any width; axis labels, the hover guide and tooltip are HTML
// overlaid on top to avoid the non-uniform scale.

// niceMax rounds up to 1, 2 or 5 × 10^k so gridlines land on round numbers.
function niceMax(v: number): number {
  if (v <= 4) return 4
  const pow = 10 ** Math.floor(Math.log10(v))
  for (const m of [1, 2, 5, 10]) {
    if (m * pow >= v) return m * pow
  }
  return 10 * pow
}

export default function TrafficChart({
  series,
  unit,
  tick,
  full,
}: {
  series: Bucket[]
  unit: string // "min" or "hour", for the y label and tooltip
  tick: (t: number) => string // short x-axis label for a bucket start
  full: (t: number) => string // tooltip label for a bucket
}) {
  const [hover, setHover] = useState<number | null>(null)

  const { reqArea, reqLine, blkArea, blkLine, max } = useMemo(() => {
    const max = niceMax(Math.max(0, ...series.map((b) => b.requests)))
    const x = (i: number) => (series.length === 1 ? 50 : (i / (series.length - 1)) * 100)
    const y = (v: number) => 100 - (v / max) * 100
    const line = (key: 'requests' | 'blocked') =>
      series.map((b, i) => `${x(i).toFixed(2)},${y(b[key]).toFixed(2)}`).join(' ')
    const area = (pts: string) => (series.length ? `M0,100 L${pts.split(' ').join(' L')} L100,100 Z` : '')
    const rl = line('requests')
    const bl = line('blocked')
    return { reqLine: rl, reqArea: area(rl), blkLine: bl, blkArea: area(bl), max }
  }, [series])

  if (!series.length) {
    return <div className="h-52 flex items-center justify-center text-sm text-slate-400">no traffic yet</div>
  }

  const pick = (e: MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect()
    const f = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width))
    setHover(Math.round(f * (series.length - 1)))
  }
  const h = hover !== null ? series[hover] : null
  const hx = hover !== null ? (series.length === 1 ? 50 : (hover / (series.length - 1)) * 100) : 0
  const mid = Math.floor((series.length - 1) / 2)

  return (
    <div className="flex gap-2">
      {/* y axis */}
      <div className="relative w-10 h-52 shrink-0 text-[11px] text-slate-400 text-right">
        <span className="absolute right-0 -top-1.5">{max.toLocaleString()}</span>
        <span className="absolute right-0 top-1/2 -translate-y-1/2">{(max / 2).toLocaleString()}</span>
        <span className="absolute right-0 -bottom-1.5">0</span>
      </div>

      <div className="flex-1 min-w-0">
        <div className="relative h-52 cursor-crosshair" onMouseMove={pick} onMouseLeave={() => setHover(null)}>
          <svg className="absolute inset-0 w-full h-full overflow-visible" viewBox="0 0 100 100" preserveAspectRatio="none">
            {[0, 50, 100].map((gy) => (
              <line
                key={gy}
                x1="0"
                x2="100"
                y1={gy}
                y2={gy}
                className="stroke-slate-200 dark:stroke-slate-800"
                strokeWidth="1"
                vectorEffect="non-scaling-stroke"
              />
            ))}
            <path d={reqArea} className="fill-blue-500/10" />
            <path d={blkArea} className="fill-rose-500/20" />
            <polyline points={reqLine} fill="none" className="stroke-blue-500" strokeWidth="1.75" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
            <polyline points={blkLine} fill="none" className="stroke-rose-500" strokeWidth="1.75" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
          </svg>

          {h && (
            <>
              <div className="absolute top-0 bottom-0 w-px bg-slate-400/60 pointer-events-none" style={{ left: `${hx}%` }} />
              <div
                className="absolute top-2 z-10 pointer-events-none rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-lg px-2.5 py-1.5 text-xs whitespace-nowrap"
                style={hx > 60 ? { right: `${100 - hx}%`, marginRight: 8 } : { left: `${hx}%`, marginLeft: 8 }}
              >
                <div className="text-slate-500 mb-0.5">{full(h.t)}</div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-500" />
                  {h.requests.toLocaleString()} requests
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  {h.blocked.toLocaleString()} blocked
                </div>
              </div>
            </>
          )}
        </div>

        {/* x axis */}
        <div className="relative h-5 mt-1 text-[11px] text-slate-400">
          <span className="absolute left-0">{tick(series[0].t)}</span>
          {series.length > 2 && (
            <span className="absolute -translate-x-1/2" style={{ left: `${(mid / (series.length - 1)) * 100}%` }}>
              {tick(series[mid].t)}
            </span>
          )}
          <span className="absolute right-0">{tick(series[series.length - 1].t)}</span>
        </div>
        <div className="sr-only">requests per {unit}</div>
      </div>
    </div>
  )
}
