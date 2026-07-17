import { useState } from 'react'
import { Unlock, Loader2, X, FileText, AlertCircle } from 'lucide-react'

export function ReportDecryptor() {
  const [filename, setFilename] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [decryptedContent, setDecryptedContent] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [isOpen, setIsOpen] = useState(false)

  const handleDecrypt = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!filename.trim()) return

    setIsLoading(true)
    setError(null)
    setDecryptedContent(null)

    try {
      const response = await fetch(`http://localhost:8000/api/reports/decrypt/${encodeURIComponent(filename.trim())}`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.detail || 'Failed to decrypt report')
      }
      const data = await response.json()
      setDecryptedContent(data)
      setIsOpen(true)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="w-full">
      <form onSubmit={handleDecrypt} className="relative">
        <div className="relative flex items-center p-1 rounded-sm overflow-hidden" style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-glass)', borderRadius: '12px' }}>
          <div style={{ paddingLeft: '12px' }}>
            <Unlock style={{ width: '20px', height: '20px', color: 'var(--text-muted)' }} />
          </div>
          <input
            type="text"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="Enter encrypted file name (e.g. scan-results.enc)"
            className="w-full font-mono text-sm"
            style={{ background: 'transparent', border: 'none', outline: 'none', color: 'white', padding: '12px 16px' }}
            disabled={isLoading}
            required
          />
          <button
            type="submit"
            disabled={isLoading || !filename.trim()}
            className="btn-primary"
            style={{ background: 'linear-gradient(135deg, #a855f7, #6366f1)' }}
          >
            {isLoading ? (
              <>
                <Loader2 style={{ width: '16px', height: '16px' }} className="animate-spin" />
                Decrypting...
              </>
            ) : (
              <>
                View Decrypted Report
              </>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="mt-4 flex items-center gap-2 p-4 rounded-xl" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#f87171' }}>
          <AlertCircle style={{ width: '16px', height: '16px', flexShrink: 0 }} />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Decrypted Report Modal */}
      {isOpen && decryptedContent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 animate-fade-in" style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}>
          <div className="relative w-full max-w-4xl flex flex-col glass-card" style={{ maxHeight: '85vh', background: 'var(--bg-dark)' }}>
            <div className="flex items-center justify-between p-4 border-b" style={{ background: 'rgba(255,255,255,0.02)' }}>
              <div className="flex items-center gap-2 text-gradient-alt">
                <FileText style={{ width: '20px', height: '20px' }} />
                <span className="font-bold">Decrypted Report: {filename}</span>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="btn-glass p-1"
              >
                <X style={{ width: '20px', height: '20px' }} />
              </button>
            </div>
            <div className="flex-1 p-6 overflow-y-auto font-mono text-sm" style={{ background: 'rgba(0,0,0,0.4)' }}>
              <pre className="whitespace-pre-wrap break-word text-muted">
                {JSON.stringify(decryptedContent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
