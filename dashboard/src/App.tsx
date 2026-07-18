import { useState, useEffect } from 'react'
import { ScanResults, Finding, FilterOptions } from './types'
import { SummaryCards } from './components/SummaryCards'
import { FindingList } from './components/FindingList'
import { FilterBar } from './components/FilterBar'
import { FileUpload } from './components/FileUpload'
import { UrlScanner } from './components/UrlScanner'
import { MetricsDashboard } from './components/MetricsDashboard'
import { Shield, AlertTriangle, Sparkles, FileSearch, Palette, LayoutDashboard, List } from 'lucide-react'

// ... standard component logic remains unmodified below, except for the render output


function App() {
  const [results, setResults] = useState<ScanResults | null>(null)
  const [filteredFindings, setFilteredFindings] = useState<Finding[]>([])
  const [filters, setFilters] = useState<FilterOptions>({
    severity: [],
    rule: [],
    hasPatch: null
  })
  const [viewMode, setViewMode] = useState<'list' | 'metrics'>('list')
  const [isLoading, setIsLoading] = useState(true)

  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'obsidian')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  useEffect(() => {
    // Simulate loading
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

    const severityMap: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    filtered.sort((a, b) => (severityMap[a.severity] ?? 99) - (severityMap[b.severity] ?? 99))

    setFilteredFindings(filtered)
  }, [results, filters])

  const handleFileUpload = (data: ScanResults) => {
    setResults(data)
    localStorage.setItem('scanResults', JSON.stringify(data))
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="pro-card p-8 animate-pulse">
          <Shield className="w-12 h-12 text-primary mx-auto" />
        </div>
      </div>
    )
  }

  const ThemeSwitcher = () => (
    <div className="flex items-center gap-2">
      <Palette className="w-4 h-4 text-gray-400" />
      <select 
        value={theme} 
        onChange={(e) => setTheme(e.target.value)}
        className="bg-surface border border-border rounded-md text-sm px-2 py-1 text-gray-300 focus:outline-none focus:border-gray-500 transition-colors"
      >
        <option value="obsidian">Obsidian</option>
        <option value="midnight">Midnight</option>
        <option value="slate">Slate</option>
        <option value="forest">Forest</option>
        <option value="ocean">Ocean</option>
        <option value="nebula">Nebula</option>
      </select>
    </div>
  )

  if (!results) {
    return (
      <div className="min-h-screen relative bg-background">
        {/* Header */}
        <header className="fixed top-0 left-0 right-0 z-50 bg-surface/80 backdrop-blur-md border-b border-border">
          <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-gray-100" />
              <div>
                <h1 className="text-xl font-semibold text-gray-100">VulnGuard</h1>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <ThemeSwitcher />
            </div>
          </div>
        </header>

        {/* Ambient Flowing Gradient Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-900/20 via-purple-900/10 to-slate-900/20 bg-[length:200%_200%] animate-flow pointer-events-none -z-10" />
        <div className="absolute top-[20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-500/10 blur-[120px] pointer-events-none -z-10 animate-pulse-slow" />
        <div className="absolute top-[50%] right-[-10%] w-[40%] h-[60%] rounded-full bg-purple-500/10 blur-[120px] pointer-events-none -z-10 animate-pulse-slow" style={{ animationDelay: '1s' }} />

        {/* Hero Section */}
        <main className="min-h-screen flex items-center justify-center px-6 pt-20 pb-12 relative z-10">
          <div className="max-w-7xl w-full grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            
            {/* Left Column: Text & Dynamic Elements */}
            <div className="space-y-8">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-primary/20 bg-primary/5">
                <span className="flex w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-xs font-mono font-medium text-gray-300 tracking-wide uppercase">AI-Powered Engine Active</span>
              </div>
              
              <h2 className="text-5xl lg:text-7xl font-bold tracking-tight text-gray-100 leading-tight">
                Secure your <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-400 to-indigo-400 animate-pulse-slow">
                  entire codebase.
                </span>
              </h2>
              
              <p className="text-gray-400 text-lg md:text-xl max-w-lg leading-relaxed font-light">
                Enterprise-grade vulnerability detection powered by neural analysis. Upload your SARIF scans to automatically identify, prioritize, and remediate critical security threats.
              </p>

              <div className="flex flex-wrap gap-4 pt-4">
                <div className="flex items-center gap-2 text-sm text-gray-300 font-medium">
                  <Shield className="w-5 h-5 text-gray-500" />
                  Real-time Scanning
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-300 font-medium">
                  <Sparkles className="w-5 h-5 text-gray-500" />
                  Auto-Remediation
                </div>
                <div className="flex items-center gap-2 text-sm text-gray-300 font-medium">
                  <FileSearch className="w-5 h-5 text-gray-500" />
                  CI/CD Ready
                </div>
              </div>
            </div>

            {/* Right Column: Upload Card */}
            <div className="relative">
              {/* Dynamic decorative background elements */}
              <div className="absolute -inset-4 bg-gradient-to-r from-gray-800 to-gray-900 rounded-3xl opacity-50 blur-2xl transform -rotate-3 animate-pulse-slow pointer-events-none"></div>
              
              <div className="pro-card p-8 lg:p-10 relative z-10 shadow-2xl backdrop-blur-xl border-gray-700/50">
                <div className="mb-6 text-center">
                  <h3 className="text-xl font-semibold text-gray-100 mb-2">Initialize Scan</h3>
                  <p className="text-sm text-gray-400">Connect to your backend or upload a SARIF report.</p>
                </div>

                <UrlScanner onUpload={handleFileUpload} />
                
                <div className="flex items-center gap-4 my-8">
                  <div className="h-px bg-border flex-1"></div>
                  <span className="text-gray-500 text-xs font-semibold uppercase tracking-widest">or</span>
                  <div className="h-px bg-border flex-1"></div>
                </div>
                
                <FileUpload onUpload={handleFileUpload} />
              </div>
            </div>
          </div>
        </main>
      </div>
    )
  }

  const hasFailures = results.summary.critical > 0 || results.summary.high > 0

  return (
    <div className="min-h-screen relative bg-background overflow-hidden">
      {/* Ambient Flowing Gradient Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-900/20 via-purple-900/10 to-slate-900/20 bg-[length:200%_200%] animate-flow pointer-events-none -z-10" />
      
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-surface/80 backdrop-blur-md border-b border-border">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Shield className="w-8 h-8 text-gray-100" />
            <div>
              <h1 className="text-xl font-semibold text-gray-100 leading-tight">VulnGuard</h1>
              <p className="text-xs text-gray-400 font-medium">
                {results.summary.files_scanned} files scanned in {(results.summary.duration_ms / 1000).toFixed(1)}s
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <ThemeSwitcher />
            <div className="h-6 w-px bg-border"></div>
            {hasFailures ? (
              <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                <AlertTriangle className="w-4 h-4" />
                <span className="text-sm font-medium">Issues Detected</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Shield className="w-4 h-4" />
                <span className="text-sm font-medium">System Secure</span>
              </div>
            )}
            <button
              onClick={() => {
                setResults(null)
                localStorage.removeItem('scanResults')
              }}
              className="btn-outline text-sm"
            >
              New Scan
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="pt-24 pb-8 px-6 max-w-7xl mx-auto">
        <SummaryCards summary={results.summary} />

        <div className="mt-6 pro-card overflow-hidden">
          <div className="border-b border-border p-4 flex items-center justify-between">
            <h2 className="text-lg font-medium text-gray-200">Scan Results</h2>
            <div className="flex bg-surface border border-border rounded-lg p-1">
              <button
                onClick={() => setViewMode('list')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  viewMode === 'list' 
                    ? 'bg-primary/20 text-primary' 
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <List className="w-4 h-4" />
                List
              </button>
              <button
                onClick={() => setViewMode('metrics')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  viewMode === 'metrics' 
                    ? 'bg-primary/20 text-primary' 
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <LayoutDashboard className="w-4 h-4" />
                Metrics
              </button>
            </div>
          </div>

          {viewMode === 'list' ? (
            <>
              <FilterBar
                findings={results.findings}
                filters={filters}
                onFilterChange={setFilters}
              />
              <FindingList
                findings={filteredFindings}
                totalCount={results.findings.length}
              />
            </>
          ) : (
            <MetricsDashboard findings={results.findings} />
          )}
        </div>
      </main>
    </div>
  )
}

export default App
