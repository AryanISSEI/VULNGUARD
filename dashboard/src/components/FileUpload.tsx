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
      className={`relative group cursor-pointer transition-all duration-500 ${
        isDragActive ? 'scale-105' : ''
      }`}
    >
      {/* Glow Effect */}
      <div
        className={`absolute -inset-1 bg-gradient-to-r from-blue-500/20 via-purple-500/20 to-pink-500/20 rounded-2xl blur-xl transition-opacity duration-500 ${
          isDragActive ? 'opacity-100' : 'opacity-0 group-hover:opacity-50'
        }`}
      />

      <div
        className={`relative border-2 border-dashed rounded-2xl p-10 transition-all duration-300 ${
          isDragActive
            ? 'border-blue-400 bg-blue-500/10'
            : 'border-white/[0.08] bg-white/[0.02] group-hover:border-white/[0.15] group-hover:bg-white/[0.04]'
        }`}
      >
        <input
          type="file"
          accept=".json,.sarif,application/json,.py,.js,.jsx,.ts,.tsx,.html,.css,.java,.go"
          onChange={handleChange}
          className="hidden"
          id="file-upload"
        />
        <label htmlFor="file-upload" className="cursor-pointer block">
          <div className="text-center">
            {isDragActive ? (
              <>
                <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-blue-500/20 flex items-center justify-center">
                  <Upload className="w-8 h-8 text-blue-400" />
                </div>
                <p className="text-blue-400 font-medium text-lg">Drop the file here</p>
              </>
            ) : (
              <>
                <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-white/[0.08] flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <FileJson className="w-8 h-8 text-gray-400 group-hover:text-blue-400 transition-colors" />
                </div>
                <p className="text-gray-300 font-medium text-lg mb-1">
                  Drop a codebase or scan result
                </p>
                <p className="text-gray-500 text-sm mb-6">
                  Supports JSON, SARIF, and raw source code (.py, .js, .java, etc)
                </p>
                <div className="flex items-center justify-center gap-2">
                  <span className="px-3 py-1.5 rounded-lg bg-white/[0.05] text-xs text-gray-400 border border-white/[0.08]">
                    Any Code File
                  </span>
                  <span className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-green-500/10 text-xs text-green-400 border border-green-500/20">
                    <Sparkles className="w-3 h-3" />
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
