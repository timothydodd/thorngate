import { useMemo } from 'react'
import { Bucket } from '../types'

// A lightweight responsive line chart (requests + blocked per minute) drawn with
// SVG. Uses a 0..100 viewBox with non-scaling strokes so lines stay crisp at any
// width; axis labels are overlaid as HTML to avoid the non-uniform scale.
export default function TrafficChart({ series }: { series: Bucket[] }) {
  const { reqPoints, blkPoints, max } = useMemo(() => {
    if (!series.length) return { reqPoints: '', blkPoints: '', max: 0 }
    const m = Math.max(1, ...series.map((b) => b.requests))
    const x = (i: number) => (series.length === 1 ? 50 : (i / (series.length - 1)) * 100)
    const y = (v: number) => 100 - (v / m) * 92 - 4
    const pts = (key: 'requests' | 'blocked') =>
      series.map((b, i) => `${x(i).toFixed(2)},${y(b[key]).toFixed(2)}`).join(' ')
    return { reqPoints: pts('requests'), blkPoints: pts('blocked'), max: m }
  }, [series])

  const fmt = (t: number) =>
    new Date(t * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  return (
    <div className="relative h-44">
      {series.length > 0 ? (
        <>
          <svg
            className="absolute inset-0 w-full h-full"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
          >
            {/* top gridline at max */}
            <line x1="0" y1="4" x2="100" y2="4" className="stroke-slate-300/40 dark:stroke-slate-600/40" strokeWidth="1" vectorEffect="non-scaling-stroke" />
            <polyline
              points={reqPoints}
              fill="none"
              stroke="#3b82f6"
              strokeWidth="2"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
            <polyline
              points={blkPoints}
              fill="none"
              stroke="#f43f5e"
              strokeWidth="2"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
          </svg>
          <span className="absolute left-0 top-0 text-[11px] text-slate-400">{max}/min</span>
          <span className="absolute left-0 bottom-0 text-[11px] text-slate-400">{fmt(series[0].t)}</span>
          <span className="absolute right-0 bottom-0 text-[11px] text-slate-400">
            {fmt(series[series.length - 1].t)}
          </span>
        </>
      ) : (
        <div className="h-full flex items-center justify-center text-sm text-slate-400">
          no traffic yet
        </div>
      )}
    </div>
  )
}
