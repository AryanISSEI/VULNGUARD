import { useMemo } from 'react'
import { Finding, FilterOptions, Severity } from '../types'
import { Filter, X } from 'lucide-react'

interface Props {
  findings: Finding[]
  filters: FilterOptions
  onFilterChange: (filters: FilterOptions) => void
}

const severityConfig: Record<Severity, { label: string; badge: string }> = {
  critical: { label: 'Critical', badge: 'badge-critical' },
  high: { label: 'High', badge: 'badge-high' },
  medium: { label: 'Medium', badge: 'badge-medium' },
  low: { label: 'Low', badge: 'badge-low' }
}

export function FilterBar({ findings, filters, onFilterChange }: Props) {
  const rules = useMemo(() => {
    const ruleSet = new Set(findings.map(f => f.rule))
    return Array.from(ruleSet).sort()
  }, [findings])

  const toggleSeverity = (severity: Severity) => {
    const current = filters.severity || []
    const updated = current.includes(severity)
      ? current.filter(s => s !== severity)
      : [...current, severity]
    onFilterChange({ ...filters, severity: updated })
  }

  const setHasPatch = (value: boolean | null) => {
    onFilterChange({ ...filters, hasPatch: value })
  }

  const clearFilters = () => {
    onFilterChange({ severity: [], rule: [], hasPatch: null })
  }

  const hasActiveFilters = (filters.severity?.length ?? 0) > 0 || (filters.rule?.length ?? 0) > 0 || filters.hasPatch !== null

  return (
    <div className="px-6 py-6 border-b" style={{ background: 'rgba(255,255,255,0.02)' }}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div style={{ background: 'rgba(59, 130, 246, 0.2)', padding: '0.5rem', borderRadius: '8px' }}>
            <Filter style={{ width: '16px', height: '16px', color: '#60a5fa' }} />
          </div>
          <span className="text-sm font-medium text-main">Filters</span>
        </div>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-2 text-xs text-muted hover-lift"
          >
            <X style={{ width: '12px', height: '12px' }} />
            Clear all
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-8">
        {/* Severity Filter */}
        <div className="flex items-center gap-4">
          <span className="text-xs text-muted font-medium" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>Severity:</span>
          <div className="flex gap-2">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`badge ${severityConfig[sev].badge} hover-lift`}
                style={{
                  opacity: filters.severity?.includes(sev) ? 1 : 0.6,
                  transform: filters.severity?.includes(sev) ? 'scale(1.05)' : 'none',
                  boxShadow: filters.severity?.includes(sev) ? '0 0 0 2px var(--bg-dark), 0 0 0 4px rgba(59,130,246,0.3)' : 'none'
                }}
              >
                {severityConfig[sev].label}
              </button>
            ))}
          </div>
        </div>

        {/* Rule Filter */}
        {rules.length > 0 && (
          <div className="flex items-center gap-4">
            <span className="text-xs text-muted font-medium" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>Rule:</span>
            <select
              value={filters.rule?.[0] || ''}
              onChange={(e) => {
                const value = e.target.value
                onFilterChange({
                  ...filters,
                  rule: value ? [value] : []
                })
              }}
              className="input-glass"
              style={{ padding: '4px 8px', minWidth: '140px', fontSize: '0.75rem' }}
            >
              <option value="" style={{ background: 'var(--bg-dark)' }}>All rules</option>
              {rules.map((rule) => (
                <option key={rule} value={rule} style={{ background: 'var(--bg-dark)' }}>{rule}</option>
              ))}
            </select>
          </div>
        )}

        {/* Patch Filter */}
        <div className="flex items-center gap-4">
          <span className="text-xs text-muted font-medium" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>Fixes:</span>
          <div className="flex gap-2">
            {[
              { label: 'All', value: null },
              { label: 'Available', value: true },
              { label: 'None', value: false }
            ].map((option) => (
              <button
                key={String(option.value)}
                onClick={() => setHasPatch(option.value as boolean | null)}
                className="btn-glass hover-lift"
                style={
                  filters.hasPatch === option.value
                    ? { background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa', borderColor: 'rgba(59, 130, 246, 0.4)' }
                    : { background: 'rgba(255,255,255,0.03)', color: 'var(--text-muted)' }
                }
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
