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
    <div className="px-6 py-5 border-b border-border bg-surface-hover/30">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="bg-blue-500/20 p-2 rounded-lg">
            <Filter className="w-4 h-4 text-blue-400" />
          </div>
          <span className="text-sm font-medium text-gray-300">Filters</span>
        </div>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-3 h-3" />
            Clear all
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-6">
        {/* Severity Filter */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 uppercase tracking-wider font-medium">Severity:</span>
          <div className="flex gap-2">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => (
              <button
                key={sev}
                onClick={() => toggleSeverity(sev)}
                className={`pro-badge ${severityConfig[sev].badge} transition-all duration-200 hover:opacity-100 ${
                  filters.severity?.includes(sev) ? 'ring-1 ring-offset-1 ring-offset-bg ring-blue-500/50 opacity-100' : 'opacity-50'
                }`}
              >
                {severityConfig[sev].label}
              </button>
            ))}
          </div>
        </div>

        {/* Rule Filter */}
        {rules.length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-500 uppercase tracking-wider font-medium">Rule:</span>
            <select
              value={filters.rule?.[0] || ''}
              onChange={(e) => {
                const value = e.target.value
                onFilterChange({
                  ...filters,
                  rule: value ? [value] : []
                })
              }}
              className="bg-surface border border-border text-gray-300 rounded-md py-1.5 px-2 text-xs min-w-[140px] focus:outline-none focus:border-gray-500"
            >
              <option value="" className="bg-surface">All rules</option>
              {rules.map((rule) => (
                <option key={rule} value={rule} className="bg-surface">{rule}</option>
              ))}
            </select>
          </div>
        )}

        {/* Patch Filter */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 uppercase tracking-wider font-medium">Fixes:</span>
          <div className="flex gap-2">
            {[
              { label: 'All', value: null },
              { label: 'Available', value: true },
              { label: 'None', value: false }
            ].map((option) => (
              <button
                key={String(option.value)}
                onClick={() => setHasPatch(option.value as boolean | null)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 ${
                  filters.hasPatch === option.value
                    ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                    : 'bg-surface text-gray-400 border border-border hover:bg-surface-hover'
                }`}
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
