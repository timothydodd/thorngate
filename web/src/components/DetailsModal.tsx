import { ReactNode, useEffect } from 'react'
import { RequestEvent } from '../types'
import { OutcomeBadge, statusColor } from './badges'

function Row({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <dt className="w-24 shrink-0 text-slate-400">{label}</dt>
      <dd className={'break-all ' + (mono ? 'font-mono' : '')}>{value}</dd>
    </div>
  )
}

export default function DetailsModal({ event, onClose }: { event: RequestEvent; onClose: () => void }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl max-h-[85vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-200 dark:border-slate-800">
          <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-300">Request details</h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-xl leading-none"
          >
            &times;
          </button>
        </div>
        <dl className="px-5 py-4 space-y-2 text-sm">
          <Row label="Time" value={new Date(event.time).toLocaleString()} />
          <Row label="IP" value={event.ip} mono />
          <Row label="Method" value={event.method} />
          <Row label="Host" value={event.host} mono />
          <Row label="Path" value={event.path} mono />
          {event.query && <Row label="Query" value={event.query} mono />}
          <Row label="Upstream" value={event.upstream || '—'} mono />
          <Row
            label="Status"
            value={<span className={'font-mono ' + statusColor(event.status)}>{event.status}</span>}
          />
          <Row label="Outcome" value={<OutcomeBadge outcome={event.outcome} />} />
        </dl>
      </div>
    </div>
  )
}
