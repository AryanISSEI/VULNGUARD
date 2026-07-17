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
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
      glow: 'glow-critical'
    },
    {
      title: 'High',
      count: summary.high,
      icon: AlertTriangle,
      color: 'text-orange-400',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/20',
      glow: 'glow-high'
    },
    {
      title: 'Medium',
      count: summary.medium,
      icon: AlertCircle,
      color: 'text-yellow-400',
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/20',
      glow: 'glow-medium'
    },
    {
      title: 'Low',
      count: summary.low,
      icon: CheckCircle2,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/20',
      glow: 'glow-low'
    },
    {
      title: 'Fixes',
      count: summary.patches_available,
      icon: Wrench,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
      border: 'border-green-500/20',
      glow: 'glow-success'
    }
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map((card) => (
        <div
          key={card.title}
          className={`glass-card ${card.glow} ${card.border} border p-5 hover-lift transition-all duration-300`}
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-sm font-medium text-gray-400 mb-1">{card.title}</p>
              <p className={`text-3xl font-bold ${card.color}`}>
                {card.count.toLocaleString()}
              </p>
            </div>
            <div className={`${card.bg} p-2.5 rounded-xl ${card.color}`}>
              <card.icon className="w-5 h-5" />
            </div>
          </div>
          {card.count > 0 && card.title !== 'Fixes' && (
            <div className="mt-3">
              <div className="h-1 w-full bg-dark-700 rounded-full overflow-hidden">
                <div
                  className={`h-full ${card.color.replace('text-', 'bg-')} rounded-full`}
                  style={{
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
