// Shared presentational building blocks. Every screen composes these so the
// portal keeps one look: slate surfaces, emerald for primary actions, rose for
// destructive ones, amber for warnings.

import { ButtonHTMLAttributes, ReactNode, useEffect } from 'react'
import { formatStatus, statusColor } from '../format'

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

// ---- Surfaces ----

export const surface = 'rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900'

export function Card({
  title,
  actions,
  children,
  className,
  bodyClassName = 'p-4',
}: {
  title?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cx(surface, 'overflow-hidden', className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 border-b border-slate-200 dark:border-slate-800">
          {title && <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{title}</h2>}
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}

// ---- Controls ----

type Variant = 'default' | 'primary' | 'danger' | 'danger-outline' | 'ghost'

const variants: Record<Variant, string> = {
  default:
    'border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800',
  primary: 'bg-emerald-600 hover:bg-emerald-500 text-white',
  danger: 'bg-rose-600 hover:bg-rose-500 text-white',
  'danger-outline': 'border border-rose-300 dark:border-rose-900 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-900/30',
  ghost: 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800',
}

export function Button({
  variant = 'default',
  size = 'md',
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: 'sm' | 'md' }) {
  return (
    <button
      type="button"
      {...props}
      className={cx(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap disabled:opacity-50 disabled:pointer-events-none',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1.5 text-sm',
        variants[variant],
        className,
      )}
    />
  )
}

export const inputClass =
  'px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40 placeholder:text-slate-400'

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-slate-500 mb-1">{label}</span>
      {children}
    </label>
  )
}

// Segmented is a compact single-choice toggle (ranges, outcome filters).
export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string; disabled?: boolean; title?: string }[]
  value: T
  onChange: (v: T) => void
}) {
  return (
    <div className="inline-flex rounded-md border border-slate-300 dark:border-slate-700 p-0.5 bg-slate-50 dark:bg-slate-950">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          disabled={o.disabled}
          title={o.title}
          onClick={() => onChange(o.value)}
          className={cx(
            'px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap disabled:opacity-40 disabled:cursor-not-allowed',
            o.value === value
              ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-100 shadow-sm'
              : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

// ---- Badges ----

type Tone = 'slate' | 'rose' | 'amber' | 'emerald' | 'sky' | 'violet'

const tones: Record<Tone, string> = {
  slate: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  rose: 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300',
  amber: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  emerald: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300',
  sky: 'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300',
  violet: 'bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300',
}

export function Badge({ tone = 'slate', children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cx('inline-block text-xs font-sans px-1.5 py-0.5 rounded whitespace-nowrap', tones[tone])}>
      {children}
    </span>
  )
}

const outcomeTone: Record<string, Tone> = { blocked: 'rose', honeypot: 'amber', proxied: 'slate' }

export function OutcomeBadge({ outcome }: { outcome: string }) {
  return <Badge tone={outcomeTone[outcome] ?? 'slate'}>{outcome}</Badge>
}

export function StatusText({ code, deny }: { code: number; deny?: string }) {
  return <span className={cx('font-mono', statusColor(code))}>{formatStatus(code, deny)}</span>
}

// ---- Feedback ----

export function Muted({ children }: { children: ReactNode }) {
  return <p className="text-sm text-slate-400">{children}</p>
}

export function ErrorText({ children }: { children: ReactNode }) {
  return children ? <p className="text-sm text-rose-500">{children}</p> : null
}

// ---- Overlays ----

// Modal is a centred dialog; Escape or a backdrop click closes it.
export function Modal({
  title,
  onClose,
  children,
  footer,
  width = 'max-w-lg',
}: {
  title: ReactNode
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  width?: string
}) {
  useEscape(onClose)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className={cx('relative w-full shadow-xl max-h-[85vh] flex flex-col', surface, width)}>
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-200 dark:border-slate-800">
          <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-300">{title}</h3>
          <CloseButton onClick={onClose} />
        </div>
        <div className="px-5 py-4 overflow-auto">{children}</div>
        {footer && (
          <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-800 flex justify-end gap-2">{footer}</div>
        )}
      </div>
    </div>
  )
}

// Drawer slides in from the right, for detail views that sit beside a list.
export function Drawer({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEscape(onClose)
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <aside className="relative w-full max-w-xl h-full overflow-auto bg-slate-50 dark:bg-slate-950 border-l border-slate-200 dark:border-slate-800 shadow-2xl">
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 px-5 h-14 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800">
          <div className="min-w-0">{title}</div>
          <CloseButton onClick={onClose} />
        </div>
        <div className="p-5 space-y-4">{children}</div>
      </aside>
    </div>
  )
}

function CloseButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Close"
      className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 text-xl leading-none px-1"
    >
      &times;
    </button>
  )
}

function useEscape(fn: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && fn()
    document.addEventListener('keydown', h)
    return () => document.removeEventListener('keydown', h)
  }, [fn])
}

// ---- Tables ----

// Opaque sticky header: a translucent one lets scrolled rows show through.
export const theadClass =
  'sticky top-0 z-[1] bg-slate-50 dark:bg-slate-900 text-slate-500 text-xs uppercase tracking-wide shadow-[0_1px_0_0_var(--color-slate-200)] dark:shadow-[0_1px_0_0_var(--color-slate-800)]'
export const thClass = 'text-left font-medium px-3 py-2 whitespace-nowrap'
export const tdClass = 'px-3 py-1.5'
export const rowClass = 'hover:bg-slate-50 dark:hover:bg-slate-800/40'

// IPLink opens the IP panel for an address.
export function IPLink({ ip, onOpen, className }: { ip: string; onOpen: (ip: string) => void; className?: string }) {
  return (
    <button
      type="button"
      onClick={() => onOpen(ip)}
      title={`Inspect ${ip}`}
      className={cx('font-mono text-left hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline underline-offset-2', className)}
    >
      {ip}
    </button>
  )
}

// Pager is the prev/next footer for paginated tables.
export function Pager({
  page,
  pages,
  onPage,
  note,
}: {
  page: number
  pages: number
  onPage: (p: number) => void
  note?: ReactNode
}) {
  return (
    <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 text-xs text-slate-500">
      <div className="flex gap-1">
        <Button size="sm" onClick={() => onPage(1)} disabled={page <= 1} title="Newest">
          «
        </Button>
        <Button size="sm" onClick={() => onPage(page - 1)} disabled={page <= 1}>
          ‹ Prev
        </Button>
      </div>
      <span className="text-center">
        Page {page} of {pages}
        {note && <span className="block sm:inline sm:ml-2">{note}</span>}
      </span>
      <Button size="sm" onClick={() => onPage(page + 1)} disabled={page >= pages}>
        Next ›
      </Button>
    </div>
  )
}
