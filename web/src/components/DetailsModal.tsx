import { ReactNode } from 'react'
import { formatBytes, fullTime } from '../format'
import { useNav } from '../nav'
import { RequestEvent } from '../types'
import { Button, IPLink, Modal, OutcomeBadge, StatusText } from './ui'

function Row({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <dt className="w-24 shrink-0 text-slate-400">{label}</dt>
      <dd className={'min-w-0 break-all ' + (mono ? 'font-mono' : '')}>{value}</dd>
    </div>
  )
}

export default function DetailsModal({ event, onClose }: { event: RequestEvent; onClose: () => void }) {
  const nav = useNav()
  const open = (ip: string) => {
    onClose()
    nav.openIP(ip)
  }
  return (
    <Modal
      title="Request details"
      onClose={onClose}
      footer={
        <Button onClick={() => open(event.ip)}>
          Inspect {event.ip}
        </Button>
      }
    >
      <dl className="space-y-2 text-sm">
        <Row label="Time" value={fullTime(event.time)} />
        <Row label="IP" value={<IPLink ip={event.ip} onOpen={open} />} />
        {event.country && <Row label="Country" value={event.country} />}
        <Row label="Method" value={event.method} />
        <Row label="Host" value={event.host} mono />
        <Row label="Path" value={event.path} mono />
        {event.query && <Row label="Query" value={event.query} mono />}
        {event.ua && <Row label="User agent" value={event.ua} mono />}
        <Row label="Upstream" value={event.upstream || '—'} mono />
        <Row label="Status" value={<StatusText code={event.status} deny={event.deny} />} />
        <Row label="Sent" value={event.outcome === 'proxied' ? formatBytes(event.bytes) : '—'} />
        <Row label="Outcome" value={<OutcomeBadge outcome={event.outcome} />} />
      </dl>
    </Modal>
  )
}
