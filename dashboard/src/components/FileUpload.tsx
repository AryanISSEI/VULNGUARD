import { useState, useCallback, ChangeEvent, DragEvent } from 'react'
import { Upload, FileJson, Sparkles } from 'lucide-react'
import { ScanResults } from '../types'
import { isSarifFile, parseSarif } from '../utils/sarif'

interface Props {
  onUpload: (data: ScanResults) => void
}

export function FileUpload({ onUpload }: Props) {
  const [isDragActive, setIsDragActive] = useState(false)

  const processFile = useCallback((file: File) => {
    const isReportFormat = file.name.endsWith('.json') || file.name.endsWith('.sarif') || file.type === 'application/json';

    if (isReportFormat) {
      const reader = new FileReader()
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target?.result as string)
          if (isSarifFile(json)) {
            onUpload(parseSarif(json))
          } else {
            onUpload(json)
          }
        } catch (err) {
          alert('Invalid file format. Please upload a valid scan results file.')
        }
      }
      reader.readAsText(file)
    } else {
      // It's a raw source code file, send to FastAPI for scanning
      const formData = new FormData()
      formData.append('file', file)
      
      fetch('http://localhost:8000/scan', {
        method: 'POST',
        body: formData,
      })
      .then(res => {
        if (!res.ok) throw new Error('API scan failed')
        return res.json()
      })
      .then(data => {
        onUpload(data)
      })
      .catch(err => {
        alert('Scan failed. Is the API server running? ' + err.message)
      })
    }
  }, [onUpload])

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragActive(true)
  }

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragActive(false)
  }

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragActive(false)

    const files = e.dataTransfer.files
    if (files.length > 0) {
      processFile(files[0])
    }
  }

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (files && files.length > 0) {
      processFile(files[0])
    }
  }

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className="relative"
      style={{ cursor: 'pointer', transition: 'transform 0.5s ease', transform: isDragActive ? 'scale(1.02)' : 'none' }}
    >
      <div
        className="text-center hover-lift"
        style={{
          border: '2px dashed',
          borderColor: isDragActive ? 'var(--color-primary)' : 'var(--border-glass)',
          background: isDragActive ? 'rgba(139, 92, 246, 0.1)' : 'rgba(255, 255, 255, 0.02)',
          borderRadius: '16px',
          padding: '2.5rem',
          transition: 'all 0.3s ease'
        }}
      >
        <input
          type="file"
          accept=".json,.sarif,application/json,.py,.js,.jsx,.ts,.tsx,.html,.css,.java,.go"
          onChange={handleChange}
          className="hidden"
          id="file-upload"
        />
        <label htmlFor="file-upload" style={{ cursor: 'pointer', display: 'block' }}>
          <div>
            {isDragActive ? (
              <>
                <div style={{ width: '64px', height: '64px', margin: '0 auto 1rem auto', borderRadius: '16px', background: 'rgba(139, 92, 246, 0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Upload style={{ width: '32px', height: '32px', color: 'var(--color-primary)' }} />
                </div>
                <p style={{ color: 'var(--color-primary)', fontWeight: 500, fontSize: '1.125rem' }}>Drop the file here</p>
              </>
            ) : (
              <>
                <div style={{ width: '64px', height: '64px', margin: '0 auto 1rem auto', borderRadius: '16px', background: 'rgba(255, 255, 255, 0.08)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <FileJson style={{ width: '32px', height: '32px', color: 'var(--text-muted)' }} />
                </div>
                <p style={{ color: '#e2e8f0', fontWeight: 500, fontSize: '1.125rem', marginBottom: '0.25rem' }}>
                  Drop a codebase or scan result
                </p>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1.5rem' }}>
                  Supports JSON, SARIF, and raw source code (.py, .js, .java, etc)
                </p>
                <div className="flex items-center justify-center gap-2">
                  <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}>
                    Any Code File
                  </span>
                  <span className="badge badge-success">
                    <Sparkles style={{ width: '12px', height: '12px' }} />
                    AI Analysis
                  </span>
                </div>
              </>
            )}
          </div>
        </label>
      </div>
    </div>
  )
}
