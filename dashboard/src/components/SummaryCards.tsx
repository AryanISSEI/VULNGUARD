import { AlertOctagon, AlertTriangle, AlertCircle, CheckCircle2, Wrench } from 'lucide-react'
import { ScanSummary } from '../types'

interface Props {
  summary: ScanSummary
}

export function SummaryCards({ summary }: Props) {
  const cards = [
    {
      title: 'Critical',
      count: summary.critical,
      icon: AlertOctagon,
      color: 'var(--color-critical)',
      bg: 'rgba(239, 68, 68, 0.1)',
      border: 'rgba(239, 68, 68, 0.2)',
      glow: 'glow-critical'
    },
    {
      title: 'High',
      count: summary.high,
      icon: AlertTriangle,
      color: 'var(--color-high)',
      bg: 'rgba(249, 115, 22, 0.1)',
      border: 'rgba(249, 115, 22, 0.2)',
      glow: 'glow-high'
    },
    {
      title: 'Medium',
      count: summary.medium,
      icon: AlertCircle,
      color: 'var(--color-medium)',
      bg: 'rgba(234, 179, 8, 0.1)',
      border: 'rgba(234, 179, 8, 0.2)',
      glow: 'glow-medium'
    },
    {
      title: 'Low',
      count: summary.low,
      icon: CheckCircle2,
      color: 'var(--color-low)',
      bg: 'rgba(59, 130, 246, 0.1)',
      border: 'rgba(59, 130, 246, 0.2)',
      glow: 'glow-low'
    },
    {
      title: 'Fixes',
      count: summary.patches_available,
      icon: Wrench,
      color: 'var(--color-success)',
      bg: 'rgba(16, 185, 129, 0.1)',
      border: 'rgba(16, 185, 129, 0.2)',
      glow: 'glow-success'
    }
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map((card) => (
        <div
          key={card.title}
          className={`glass-card hover-lift p-6 ${card.glow}`}
          style={{ borderColor: card.border }}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-medium text-muted mb-1">{card.title}</p>
              <p className="text-4xl font-bold" style={{ color: card.color }}>
                {card.count.toLocaleString()}
              </p>
            </div>
            <div style={{ background: card.bg, padding: '0.75rem', borderRadius: '12px', color: card.color }}>
              <card.icon style={{ width: '20px', height: '20px' }} />
            </div>
          </div>
          {card.count > 0 && card.title !== 'Fixes' && (
            <div className="mt-4">
              <div style={{ height: '4px', width: '100%', background: 'rgba(255,255,255,0.05)', borderRadius: '9999px', overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    background: card.color,
                    borderRadius: '9999px',
                    width: `${Math.min((card.count / (summary.total_findings || 1)) * 100, 100)}%`
                  }}
                />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
