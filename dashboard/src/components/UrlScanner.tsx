import { useState } from 'react'
import { Globe, Loader2, ArrowRight, GitBranch } from 'lucide-react'
import { ScanResults } from '../types'

interface Props {
  onUpload: (data: ScanResults) => void
}

export function UrlScanner({ onUpload }: Props) {
  const [url, setUrl] = useState('')
  const [scanType, setScanType] = useState<'web' | 'repo'>('web')
  const [isScanning, setIsScanning] = useState(false)

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) return

    setIsScanning(true)
    try {
      const endpoint = scanType === 'web' ? 'scan-url' : 'scan-repo'
      const response = await fetch(`http://localhost:8000/${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      })

      if (!response.ok) {
        throw new Error(`${scanType === 'web' ? 'Web' : 'Repository'} scan failed on the server`)
      }

      const data = await response.json()
      onUpload(data)
    } catch (err: any) {
      alert(`Failed to scan. Make sure the API server is running. Error: ${err.message}`)
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="w-full">
      {/* Tabs */}
      <div className="flex gap-2 mb-4 p-1 rounded-xl" style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border-glass)' }}>
        <button
          type="button"
          onClick={() => {
            setScanType('web')
            setUrl('')
          }}
          className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-sm text-sm font-medium hover-lift ${
            scanType === 'web'
              ? 'btn-glass'
              : 'text-muted'
          }`}
          style={scanType === 'web' ? { background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa', borderColor: 'rgba(59, 130, 246, 0.3)' } : { border: 'none', background: 'transparent' }}
        >
          <Globe style={{ width: '16px', height: '16px' }} />
          Scan Website
        </button>
        <button
          type="button"
          onClick={() => {
            setScanType('repo')
            setUrl('')
          }}
          className={`flex-1 flex items-center justify-center gap-2 py-2 px-4 rounded-sm text-sm font-medium hover-lift ${
            scanType === 'repo'
              ? 'btn-glass'
              : 'text-muted'
          }`}
          style={scanType === 'repo' ? { background: 'rgba(168, 85, 247, 0.2)', color: '#c084fc', borderColor: 'rgba(168, 85, 247, 0.3)' } : { border: 'none', background: 'transparent' }}
        >
          <GitBranch style={{ width: '16px', height: '16px' }} />
          Scan Git Repo
        </button>
      </div>

      <form onSubmit={handleScan} className="relative">
        <div className="relative flex items-center p-1 rounded-sm overflow-hidden" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-glass)', borderRadius: '12px' }}>
          <div style={{ paddingLeft: '12px' }}>
            {scanType === 'web' ? (
              <Globe style={{ width: '20px', height: '20px', color: 'var(--text-muted)' }} />
            ) : (
              <GitBranch style={{ width: '20px', height: '20px', color: 'var(--text-muted)' }} />
            )}
          </div>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={scanType === 'web' ? "https://example.com" : "https://github.com/owner/repo.git"}
            className="w-full font-mono text-sm"
            style={{ background: 'transparent', border: 'none', outline: 'none', color: 'white', padding: '12px 16px' }}
            disabled={isScanning}
            required
          />
          <button
            type="submit"
            disabled={isScanning || !url}
            className="btn-primary"
            style={scanType === 'web' ? { background: 'linear-gradient(135deg, #3b82f6, #2563eb)' } : {}}
          >
            {isScanning ? (
              <>
                <Loader2 style={{ width: '16px', height: '16px' }} className="animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                {scanType === 'web' ? 'Scan Site' : 'Scan Repo'}
                <ArrowRight style={{ width: '16px', height: '16px' }} />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}
