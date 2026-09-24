import { FormEvent, useState } from 'react'
import { api } from '../api'
import { isIPv6, isRange } from '../format'
import { Button, ErrorText, Field, Modal, Segmented, inputClass, cx } from './ui'

export const DURATIONS = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'permanent', label: 'Permanent' },
]

// BanDialog confirms a manual ban with a duration and reason. For a single
// IPv6 address it offers the whole /64 — scanners rotate through theirs — which
// is what automatic bans do too.
export default function BanDialog({ ip, onClose, onDone }: { ip: string; onClose: () => void; onDone: () => void }) {
  const v6 = isIPv6(ip) && !isRange(ip)
  const [range64, setRange64] = useState(v6)
  const [duration, setDuration] = useState('permanent')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const target = range64 ? ip + '/64' : ip

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.ban(target, reason.trim() || 'manual (portal)', duration)
      onDone()
      onClose()
    } catch (err: any) {
      setError(err?.message || 'ban failed')
      setBusy(false)
    }
  }

  return (
    <Modal title="Ban client" onClose={onClose} width="max-w-md">
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm">
          Block <span className="font-mono font-medium break-all">{ip}</span> from reaching any upstream.
        </p>
        {v6 && (
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={range64} onChange={(e) => setRange64(e.target.checked)} className="mt-0.5 accent-emerald-600" />
            <span>
              Ban the whole <span className="font-mono">/64</span>
              <span className="block text-xs text-slate-400">
                An IPv6 client usually holds its entire /64 and can rotate to any address in it.
              </span>
            </span>
          </label>
        )}
        <Field label="Duration">
          <Segmented value={duration} onChange={setDuration} options={DURATIONS.map((d) => ({ ...d, label: d.value === 'permanent' ? 'Permanent' : d.value }))} />
        </Field>
        <Field label="Reason (optional)">
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="manual (portal)" className={cx(inputClass, 'w-full')} />
        </Field>
        <ErrorText>{error}</ErrorText>
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={busy}>
            {busy ? 'Banning…' : duration === 'permanent' ? 'Ban permanently' : `Ban for ${duration}`}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
