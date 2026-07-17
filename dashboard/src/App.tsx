import { useState, useEffect } from 'react'
import { ScanResults, Finding, FilterOptions } from './types'
import { SummaryCards } from './components/SummaryCards'
import { FindingList } from './components/FindingList'
import { FilterBar } from './components/FilterBar'
import { FileUpload } from './components/FileUpload'
import { UrlScanner } from './components/UrlScanner'
import { ReportDecryptor } from './components/ReportDecryptor'
import { Shield, AlertTriangle, Sparkles, Scan, FileSearch } from 'lucide-react'

function App() {
  const [results, setResults] = useState<ScanResults | null>(null)
  const [filteredFindings, setFilteredFindings] = useState<Finding[]>([])
  const [filters, setFilters] = useState<FilterOptions>({
    severity: [],
    rule: [],
    hasPatch: null
  })
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    // Simulate loading for glass effect reveal
    const timer = setTimeout(() => setIsLoading(false), 500)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const resultsUrl = urlParams.get('results')

    if (resultsUrl) {
      fetch(resultsUrl)
        .then(r => r.json())
        .then(data => setResults(data))
        .catch(err => console.error('Failed to load results:', err))
    } else {
      const saved = localStorage.getItem('scanResults')
      if (saved) {
        setResults(JSON.parse(saved))
      }
    }
  }, [])

  useEffect(() => {
    if (!results) return

    let filtered = results.findings

    const severityFilters = filters.severity
    if (severityFilters && severityFilters.length > 0) {
      filtered = filtered.filter(f => severityFilters.includes(f.severity))
    }

    const ruleFilters = filters.rule
    if (ruleFilters && ruleFilters.length > 0) {
      filtered = filtered.filter(f => ruleFilters.includes(f.rule))
    }

    if (filters.hasPatch !== null) {
      filtered = filtered.filter(f => (f.patch !== null) === filters.hasPatch)
    }

    setFilteredFindings(filtered)
  }, [results, filters])

  const handleFileUpload = (data: ScanResults) => {
    setResults(data)
    localStorage.setItem('scanResults', JSON.stringify(data))
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="glass-card p-8">
          <Shield style={{ width: '48px', height: '48px', color: 'var(--color-primary)' }} />
        </div>
      </div>
    )
  }

  if (!results) {
    return (
      <div className="min-h-screen relative">
        <header className="fixed top-0 left-0 right-0 z-50 glass-panel border-b-0">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Shield style={{ width: '32px', height: '32px', color: 'var(--color-primary)' }} />
              <div>
                <h1 className="text-xl font-bold text-gradient">VulnGuard</h1>
                <p className="text-xs text-muted">Security Scanner Dashboard</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Sparkles style={{ width: '16px', height: '16px', color: 'var(--color-primary)' }} />
              <span className="text-sm text-muted">AI-Powered Analysis</span>
            </div>
          </div>
        </header>

        <main className="min-h-screen flex items-center justify-center px-6 pt-24">
          <div className="max-w-2xl w-full animate-fade-in">
            <div className="text-center mb-10">
              <div className="inline-flex items-center gap-2 px-4 py-2 glass-card mb-6" style={{ borderRadius: '9999px' }}>
                <Scan style={{ width: '16px', height: '16px', color: 'var(--color-secondary)' }} />
                <span className="text-sm text-muted font-medium">Static Analysis Tool</span>
              </div>
              <h2 className="text-4xl font-bold mb-4">
                <span>Scan Your Code for</span>
                <br />
                <span className="text-gradient">Security Vulnerabilities</span>
              </h2>
              <p className="text-muted text-lg max-w-2xl mx-auto mt-4">
                Upload your scan results to visualize, filter, and fix security issues with AI-suggested patches.
              </p>
            </div>

            <div className="glass-card p-1 mt-8">
              <div className="hero-upload-card">
                <UrlScanner onUpload={handleFileUpload} />
                <div className="divider">
                  <div className="divider-line"></div>
                  <span className="divider-text">OR</span>
                  <div className="divider-line"></div>
                </div>
                <FileUpload onUpload={handleFileUpload} />
                <div className="divider">
                  <div className="divider-line"></div>
                  <span className="divider-text">OR</span>
                  <div className="divider-line"></div>
                </div>
                <ReportDecryptor />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-6 mt-8">
              {[
                { icon: Shield, label: 'Vulnerability Detection' },
                { icon: Sparkles, label: 'AI-Powered Fixes' },
                { icon: FileSearch, label: 'Multi-Language Support' },
              ].map((feature, i) => (
                <div key={i} className="glass-card p-4 text-center hover-lift">
                  <feature.icon style={{ width: '24px', height: '24px', color: 'var(--color-primary)', margin: '0 auto 8px auto' }} />
                  <span className="text-sm text-muted font-medium">{feature.label}</span>
                </div>
              ))}
            </div>
          </div>
        </main>
      </div>
    )
  }

  const hasFailures = results.summary.critical > 0 || results.summary.high > 0

  return (
    <div className="min-h-screen relative">
      <header className="fixed top-0 left-0 right-0 z-50 glass-panel border-b">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Shield style={{ width: '32px', height: '32px', color: 'var(--color-primary)' }} />
            <div>
              <h1 className="text-xl font-bold text-gradient">VulnGuard</h1>
              <p className="text-xs text-muted">
                {results.summary.files_scanned} files • {(results.summary.duration_ms / 1000).toFixed(1)}s
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            {hasFailures ? (
              <div className="badge badge-critical glow-critical">
                <AlertTriangle style={{ width: '16px', height: '16px' }} />
                <span>Issues Found</span>
              </div>
            ) : (
              <div className="badge badge-success glow-safe">
                <Shield style={{ width: '16px', height: '16px' }} />
                <span>All Clear</span>
              </div>
            )}
            <button
              onClick={() => {
                setResults(null)
                localStorage.removeItem('scanResults')
              }}
              className="btn-glass"
            >
              New Scan
            </button>
          </div>
        </div>
      </header>

      <main className="pt-24 pb-8 px-6 max-w-7xl mx-auto animate-fade-in">
        <SummaryCards summary={results.summary} />

        <div className="mt-8 glass-card overflow-hidden">
          <FilterBar
            findings={results.findings}
            filters={filters}
            onFilterChange={setFilters}
          />
          <FindingList
            findings={filteredFindings}
            totalCount={results.findings.length}
          />
        </div>
      </main>
    </div>
  )
}

export default App
