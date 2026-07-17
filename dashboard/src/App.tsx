import { useState, useEffect } from 'react'
import { ScanResults, Finding, FilterOptions } from './types'
import { SummaryCards } from './components/SummaryCards'
import { FindingList } from './components/FindingList'
import { FilterBar } from './components/FilterBar'
import { FileUpload } from './components/FileUpload'
import { UrlScanner } from './components/UrlScanner'
import { Shield, AlertTriangle, Sparkles, Scan, FileSearch } from 'lucide-react'

// ... standard component logic remains unmodified below, except for the render output


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
        <div className="glass-card p-8 animate-pulse">
          <Shield className="w-12 h-12 text-blue-400 mx-auto" />
        </div>
      </div>
    )
  }

  if (!results) {
    return (
      <div className="min-h-screen relative">
        <div className="gradient-mesh" />

        {/* Header */}
        <header className="fixed top-0 left-0 right-0 z-50 glass-panel border-b-0">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="absolute inset-0 bg-blue-500/30 blur-xl rounded-full" />
                <Shield className="w-8 h-8 text-blue-400 relative z-10" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gradient">VulnGuard</h1>
                <p className="text-xs text-gray-400">Security Scanner Dashboard</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span className="text-sm text-gray-400">AI-Powered Analysis</span>
            </div>
          </div>
        </header>

        {/* Hero Upload Section */}
        <main className="min-h-screen flex items-center justify-center px-6 pt-20">
          <div className="max-w-2xl w-full">
            {/* Hero Text */}
            <div className="text-center mb-10">
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass-card mb-6">
                <Scan className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-gray-300">Static Analysis Tool</span>
              </div>
              <h2 className="text-4xl md:text-5xl font-bold mb-4">
                <span className="text-white">Scan Your Code for</span>
                <br />
                <span className="text-gradient">Security Vulnerabilities</span>
              </h2>
              <p className="text-gray-400 text-lg max-w-lg mx-auto">
                Upload your scan results to visualize, filter, and fix security issues with AI-suggested patches.
              </p>
            </div>

            {/* Upload Card */}
            <div className="glass-card p-1">
              <div className="bg-dark-800/50 rounded-xl p-8">
                <UrlScanner onUpload={handleFileUpload} />
                <div className="flex items-center gap-4 my-6">
                  <div className="h-px bg-glass-border flex-1"></div>
                  <span className="text-gray-500 text-sm font-medium uppercase tracking-wider">OR</span>
                  <div className="h-px bg-glass-border flex-1"></div>
                </div>
                <FileUpload onUpload={handleFileUpload} />
              </div>
            </div>

            {/* Features */}
            <div className="grid grid-cols-3 gap-4 mt-8">
              {[
                { icon: Shield, label: 'Vulnerability Detection' },
                { icon: Sparkles, label: 'AI-Powered Fixes' },
                { icon: FileSearch, label: 'Multi-Language Support' },
              ].map((feature, i) => (
                <div key={i} className="glass-card p-4 text-center hover-lift">
                  <feature.icon className="w-6 h-6 text-blue-400 mx-auto mb-2" />
                  <span className="text-sm text-gray-300">{feature.label}</span>
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
      <div className="gradient-mesh" />

      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 glass-panel border-b border-white/[0.08]">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-blue-500/30 blur-xl rounded-full" />
              <Shield className="w-8 h-8 text-blue-400 relative z-10" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gradient">VulnGuard</h1>
              <p className="text-xs text-gray-400">
                {results.summary.files_scanned} files • {(results.summary.duration_ms / 1000).toFixed(1)}s
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {hasFailures ? (
              <div className="badge badge-critical glow-critical flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                <span>Issues Found</span>
              </div>
            ) : (
              <div className="badge badge-success glow-success flex items-center gap-2">
                <Shield className="w-4 h-4" />
                <span>All Clear</span>
              </div>
            )}
            <button
              onClick={() => {
                setResults(null)
                localStorage.removeItem('scanResults')
              }}
              className="glass-button"
            >
              New Scan
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="pt-24 pb-8 px-6 max-w-7xl mx-auto">
        <SummaryCards summary={results.summary} />

        <div className="mt-6 glass-card overflow-hidden">
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
