import { useState } from 'react'
import { Globe, Loader2, ArrowRight } from 'lucide-react'
import { ScanResults } from '../types'

interface Props {
  onUpload: (data: ScanResults) => void
}

export function UrlScanner({ onUpload }: Props) {
  const [url, setUrl] = useState('')
  const [isScanning, setIsScanning] = useState(false)

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) return

    setIsScanning(true)
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
      const response = await fetch(`${apiUrl}/scan-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      })

      if (!response.ok) {
        throw new Error('Web scan failed on the server')
      }

      const data = await response.json()
      onUpload(data)
    } catch (err: any) {
      alert('Failed to scan URL. Make sure the API server is running. Error: ' + err.message)
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <form onSubmit={handleScan} className="relative group mb-6">
      <div className="absolute -inset-1 bg-gradient-to-r from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-2xl blur opacity-30 group-hover:opacity-75 transition duration-1000 group-hover:duration-200"></div>
      <div className="relative flex items-center bg-dark-900 border border-white/[0.08] rounded-xl px-4 py-3 shadow-2xl overflow-hidden focus-within:border-blue-500/50 transition-colors">
        <Globe className="w-5 h-5 text-gray-400 mr-3 shrink-0" />
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="w-full bg-transparent border-none outline-none text-white placeholder-gray-500 font-mono"
          disabled={isScanning}
          required
        />
        <button
          type="submit"
          disabled={isScanning || !url}
          className="ml-3 px-4 py-1.5 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors flex items-center gap-2 shrink-0"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              Scan Site
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </div>
    </form>
  )
}
