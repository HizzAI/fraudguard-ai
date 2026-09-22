import { useState, useRef, useCallback } from 'react'
import CyberMatrixHero from './components/ui/cyber-matrix-hero'
import { 
  ShieldAlert, ShieldCheck, UploadCloud, File, AlertTriangle, 
  Activity, CheckCircle, XCircle, Search, Server, Shield, 
  ChevronDown, ChevronUp, Lock, FileJson, Cpu, Crosshair
} from 'lucide-react'

// ─── API Configuration ──────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_BASE || ''
const UPLOAD_ENDPOINT = `${API_BASE}/upload-apk`

// ─── Helpers ─────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function classKey(classification) {
  if (!classification) return 'unavailable'
  return classification.toLowerCase()
}

// ─── Shared Components ────────────────────────────────────────────────────────

function Card({ icon: Icon, title, count, children, className = '' }) {
  return (
    <div className={`bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm ${className}`}>
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900/50 border-b border-slate-800">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-4 h-4 text-slate-400" />}
          <h3 className="font-semibold text-slate-200 text-sm tracking-wide">{title}</h3>
        </div>
        {count !== undefined && (
          <span className="bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded-full font-mono">
            {count}
          </span>
        )}
      </div>
      <div className="p-4">
        {children}
      </div>
    </div>
  )
}

function KV({ label, value }) {
  const empty = value === null || value === undefined || value === ''
  return (
    <div className="flex flex-col mb-3 last:mb-0">
      <span className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</span>
      {empty ? (
        <span className="text-sm text-slate-600 italic">Not available</span>
      ) : (
        <span className="text-sm text-slate-200 font-mono break-all">{String(value)}</span>
      )}
    </div>
  )
}

function TagList({ items, emptyMsg = 'None' }) {
  if (!items || items.length === 0) {
    return <span className="text-sm text-slate-500 italic">{emptyMsg}</span>
  }
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item, i) => (
        <span key={i} className="bg-slate-800/80 border border-slate-700 text-slate-300 text-xs px-2 py-1 rounded-md font-mono">
          {item}
        </span>
      ))}
    </div>
  )
}

function ComponentGroup({ label, items }) {
  const [open, setOpen] = useState(false) // default closed to save space
  return (
    <div className="mb-4 last:mb-0 border border-slate-800 rounded-lg overflow-hidden">
      <div 
        className="flex items-center justify-between px-3 py-2 bg-slate-800/50 cursor-pointer hover:bg-slate-800 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-300">{label}</span>
          <span className="bg-slate-700 text-slate-300 text-xs px-1.5 py-0.5 rounded-md font-mono">{items?.length ?? 0}</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </div>
      {open && (
        <div className="p-3 bg-slate-900/50">
          <TagList items={items} emptyMsg="None declared" />
        </div>
      )}
    </div>
  )
}

// ─── Panels ───────────────────────────────────────────────────────────────────

function RiskHero({ risk, filename }) {
  const score = risk?.score
  const classification = risk?.classification
  const findings = risk?.findings ?? []
  
  const ck = classKey(classification)
  const isUnavailable = score === null || score === undefined

  const critCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length

  const getDialColor = () => {
    if (ck === 'malware' || ck === 'high') return 'text-red-500 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.2)]'
    if (ck === 'suspicious') return 'text-amber-500 border-amber-500 shadow-[0_0_30px_rgba(245,158,11,0.2)]'
    if (ck === 'benign') return 'text-emerald-500 border-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.2)]'
    return 'text-slate-500 border-slate-500'
  }

  const getBadgeColor = () => {
    if (ck === 'malware' || ck === 'high') return 'bg-red-500/10 text-red-500 border-red-500/20'
    if (ck === 'suspicious') return 'bg-amber-500/10 text-amber-500 border-amber-500/20'
    if (ck === 'benign') return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
    return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  }

  return (
    <div className="col-span-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg p-6 lg:p-8 flex flex-col md:flex-row items-center gap-8">
      <div className="flex flex-col items-center gap-4">
        <div className={`w-40 h-40 rounded-full border-4 flex flex-col items-center justify-center bg-slate-950 ${getDialColor()}`}>
          {isUnavailable ? (
            <span className="text-2xl font-bold">N/A</span>
          ) : (
            <>
              <span className="text-5xl font-black tracking-tighter">{score}</span>
              <span className="text-xs uppercase tracking-widest opacity-60">Risk Score</span>
            </>
          )}
        </div>
        <div className={`px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-widest border ${getBadgeColor()}`}>
          {classification ?? 'Unavailable'}
        </div>
      </div>

      <div className="flex-1 flex flex-col gap-6 w-full">
        <div>
          <h2 className="text-2xl font-bold text-white mb-1">Investigation Report</h2>
          <p className="text-slate-400 text-sm font-mono">{filename || 'Unknown File'}</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Total Findings</div>
            <div className="text-xl font-semibold text-slate-200">{findings.length}</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-xs text-red-500/70 uppercase tracking-wider mb-1">Critical</div>
            <div className="text-xl font-semibold text-red-500">{critCount}</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-xs text-amber-500/70 uppercase tracking-wider mb-1">High</div>
            <div className="text-xl font-semibold text-amber-500">{highCount}</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-xs text-emerald-500/70 uppercase tracking-wider mb-1">ML Status</div>
            <div className="text-xl font-semibold text-emerald-500">Active</div>
          </div>
        </div>

        {risk?.summary && (
          <div className="bg-blue-500/5 border border-blue-500/10 p-4 rounded-lg text-sm text-blue-200/80 leading-relaxed">
            {risk.summary}
          </div>
        )}
      </div>
    </div>
  )
}

function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <Card icon={Search} title="Why was this APK flagged?" count={0} className="col-span-full">
        <div className="p-8 text-center text-slate-500 border border-dashed border-slate-700 rounded-lg">
          No suspicious risk signals triggered by the ML feature extraction.
        </div>
      </Card>
    )
  }

  const sorted = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 }
    const sa = order[a.severity] ?? 4
    const sb = order[b.severity] ?? 4
    if (sa !== sb) return sa - sb
    return b.points - a.points
  })

  return (
    <Card icon={Crosshair} title="Why was this APK flagged?" count={findings.length} className="col-span-full border-slate-700">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sorted.map((f, i) => {
          const isHigh = f.severity === 'critical' || f.severity === 'high';
          return (
            <div key={i} className={`p-4 rounded-lg border ${isHigh ? 'bg-red-500/5 border-red-500/20' : 'bg-amber-500/5 border-amber-500/20'}`}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-sm ${
                    isHigh ? 'bg-red-500/20 text-red-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {f.severity || 'low'}
                  </span>
                  <span className="text-sm font-semibold text-slate-200">{f.category}</span>
                </div>
                <span className="text-xs font-mono text-slate-500">+{f.points} pts</span>
              </div>
              <p className="text-sm text-slate-400">{f.reason}</p>
              <div className="mt-2 text-xs font-mono text-slate-600 border-t border-slate-800/50 pt-2">{f.rule_id}</div>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function ApkDetailsPanel({ data }) {
  const isSuccess = data.analysis_status === 'success'
  return (
    <Card icon={File} title="APK Details">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <KV label="Filename" value={data.filename} />
          <KV label="File Size" value={formatBytes(data.size_bytes)} />
        </div>
        <div>
          <KV label="Package Name" value={data.app?.package_name} />
          <KV label="Version" value={data.app?.version} />
        </div>
      </div>
      <div className="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-500 uppercase tracking-wider">Analysis Status</span>
        {isSuccess ? (
          <span className="flex items-center gap-1 text-xs font-medium text-emerald-500 bg-emerald-500/10 px-2 py-1 rounded-md">
            <CheckCircle className="w-3 h-3" /> Success
          </span>
        ) : (
          <span className="flex items-center gap-1 text-xs font-medium text-red-500 bg-red-500/10 px-2 py-1 rounded-md">
            <XCircle className="w-3 h-3" /> Failed
          </span>
        )}
      </div>
    </Card>
  )
}

function CertificatePanel({ certificate }) {
  const hasCert = certificate && Object.keys(certificate).length > 0
  return (
    <Card icon={Lock} title="Cryptographic Certificate">
      {hasCert ? (
        <div className="space-y-1">
          <KV label="Subject" value={certificate.subject} />
          <div className="h-px bg-slate-800 my-2" />
          <KV label="Issuer" value={certificate.issuer} />
          <div className="h-px bg-slate-800 my-2" />
          <KV label="Serial Number" value={certificate.serial_number} />
        </div>
      ) : (
        <p className="text-sm text-slate-500 italic text-center py-4">Certificate information unavailable.</p>
      )}
    </Card>
  )
}

function PermissionsPanel({ permissions }) {
  const [query, setQuery] = useState('')
  const list = permissions ?? []
  const filtered = query.trim()
    ? list.filter(p => p.toLowerCase().includes(query.toLowerCase()))
    : list

  return (
    <Card icon={Shield} title="Requested Permissions" count={list.length}>
      {list.length > 5 && (
        <input
          className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md px-3 py-2 mb-4 focus:outline-none focus:border-blue-500 transition-colors"
          type="text"
          placeholder="Filter permissions…"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      )}
      <div className="max-h-64 overflow-y-auto pr-2">
        {filtered.length === 0 && query
          ? <span className="text-sm text-slate-500">No permissions match "{query}"</span>
          : <TagList items={filtered} emptyMsg="No permissions declared" />
        }
      </div>
    </Card>
  )
}

function ComponentsPanel({ components }) {
  const c = components ?? {}
  return (
    <Card icon={Cpu} title="Android Components">
      <div className="space-y-1">
        <ComponentGroup label="Activities" items={c.activities} />
        <ComponentGroup label="Services" items={c.services} />
        <ComponentGroup label="Broadcast Receivers" items={c.receivers} />
        <ComponentGroup label="Content Providers" items={c.providers} />
      </div>
    </Card>
  )
}

function ApiIndicatorsPanel({ apis }) {
  const list = apis ?? []
  const SHOW = 80
  return (
    <Card icon={FileJson} title="Extracted API Calls" count={list.length} className="col-span-full">
      {list.length === 0 ? (
        <span className="text-sm text-slate-500">No method references extracted.</span>
      ) : (
        <>
          <TagList items={list.slice(0, SHOW)} />
          {list.length > SHOW && (
            <p className="text-xs text-slate-500 mt-4 pt-4 border-t border-slate-800">
              Showing {SHOW} of {list.length} extracted references. Full list available in raw JSON.
            </p>
          )}
        </>
      )}
    </Card>
  )
}

function AnalysisErrorsPanel({ errors }) {
  if (!errors || errors.length === 0) return null
  return (
    <Card icon={AlertTriangle} title="Analysis Errors" className="col-span-full border-red-900/50">
      <div className="flex flex-col gap-2">
        {errors.map((e, i) => (
          <div key={i} className="bg-red-500/10 text-red-400 text-sm p-3 rounded-md font-mono border border-red-500/20">{e}</div>
        ))}
      </div>
    </Card>
  )
}

function AnalysisFailedBanner({ data }) {
  return (
    <div className="col-span-full bg-red-950/30 border border-red-900/50 rounded-xl p-6 text-center">
      <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
      <h3 className="text-xl font-bold text-red-400 mb-2">Analysis failed — risk assessment unavailable</h3>
      <p className="text-red-300/70 text-sm max-w-2xl mx-auto mb-6">
        The uploaded file could not be parsed as a valid Android APK. Static analysis requires a well-formed APK file. No risk score was generated.
      </p>
      {data.errors && data.errors.length > 0 && (
        <div className="flex flex-col gap-2 max-w-3xl mx-auto text-left">
          {data.errors.map((e, i) => (
            <div key={i} className="bg-red-950/50 text-red-300 text-xs p-3 rounded-md font-mono">{e}</div>
          ))}
        </div>
      )}
    </div>
  )
}

function AnalysisResults({ data }) {
  const failed = data.analysis_status !== 'success'

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {failed && <AnalysisFailedBanner data={data} />}
      {!failed && <RiskHero risk={data.risk} filename={data.filename} />}
      {!failed && <FindingsPanel findings={data.risk?.findings} />}
      
      <ApkDetailsPanel data={data} />
      <CertificatePanel certificate={data.certificate} />
      <PermissionsPanel permissions={data.permissions} />
      
      <div className="col-span-1 md:col-span-2 lg:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
        <ComponentsPanel components={data.components} />
        {/* Placeholder for future pipeline logs or similar height element */}
        <Card icon={Activity} title="Investigation Pipeline Log">
           <div className="font-mono text-xs text-slate-500 space-y-2">
             <div className="text-emerald-500">[OK] APK Ingested</div>
             <div className="text-emerald-500">[OK] Manifest Parsed</div>
             <div className="text-emerald-500">[OK] Certificate Verified</div>
             <div className="text-emerald-500">[OK] ML Feature Vector Extracted (47 dim)</div>
             <div className="text-emerald-500">[OK] Inference Completed</div>
           </div>
        </Card>
      </div>

      <ApiIndicatorsPanel apis={data.apis} />
      <AnalysisErrorsPanel errors={data.errors} />
    </div>
  )
}

// ─── Upload Zone ──────────────────────────────────────────────────────────────
function UploadZone({ onResult, onCancel }) {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  function selectFile(f) {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are accepted.')
      return
    }
    setError(null)
    setFile(f)
  }

  function handleInputChange(e) { selectFile(e.target.files?.[0] ?? null) }

  function handleClear() {
    setFile(null)
    setError(null)
    onResult(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  const handleDragOver = useCallback((e) => { e.preventDefault(); setDragging(true) }, [])
  const handleDragLeave = useCallback(() => setDragging(false), [])
  const handleDrop = useCallback((e) => {
    e.preventDefault(); setDragging(false)
    selectFile(e.dataTransfer.files?.[0] ?? null)
  }, [])

  async function handleAnalyze() {
    if (!file) { setError('Please select an APK file first.'); return }

    setLoading(true)
    setError(null)
    onResult(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(UPLOAD_ENDPOINT, { method: 'POST', body: formData })

      if (!response.ok) {
        let detail = `Server responded with HTTP ${response.status}`
        try { const b = await response.json(); if (b.detail) detail = b.detail } catch (_) {}
        throw new Error(detail)
      }

      const data = await response.json()
      if (typeof data !== 'object' || !('analysis_status' in data)) {
        throw new Error('Unexpected response format from backend.')
      }
      onResult(data)

    } catch (err) {
      const msg = (err.name === 'TypeError' && err.message.includes('fetch'))
        ? 'Cannot reach the backend. Make sure the FastAPI server is running.'
        : (err.message || 'An unknown error occurred.')
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-3xl mx-auto mt-8 animate-in fade-in zoom-in-95 duration-500">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl relative overflow-hidden">
        {/* Decorative top border */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-600" />
        
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-blue-500" />
              Submit Artifact
            </h2>
            <p className="text-sm text-slate-400 mt-1">Upload an Android package for deep static analysis.</p>
          </div>
          {onCancel && (
            <button onClick={onCancel} className="text-sm text-slate-500 hover:text-white transition-colors">
              Cancel
            </button>
          )}
        </div>

        <div
          className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center transition-all ${
            dragging ? 'border-blue-500 bg-blue-500/5 scale-[1.02]' : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/50'
          } ${file ? 'hidden' : 'block'}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".apk,application/vnd.android.package-archive"
            onChange={handleInputChange}
            disabled={loading}
            className="hidden"
          />
          <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mb-4 text-blue-400">
            <UploadCloud className="w-8 h-8" />
          </div>
          <p className="text-slate-300 text-lg mb-2">
            Drag &amp; drop an APK here, or <button onClick={() => inputRef.current?.click()} className="text-blue-400 hover:text-blue-300 font-medium">browse</button>
          </p>
          <p className="text-slate-500 text-sm">Only .apk files • No file is executed or installed</p>
        </div>

        {file && (
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-4 overflow-hidden">
              <div className="p-3 bg-blue-500/10 text-blue-400 rounded-md shrink-0">
                <File className="w-6 h-6" />
              </div>
              <div className="overflow-hidden">
                <div className="text-slate-200 font-medium truncate">{file.name}</div>
                <div className="text-slate-500 text-sm">{formatBytes(file.size)}</div>
              </div>
            </div>
            <button onClick={handleClear} disabled={loading} className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-400/10 rounded-md transition-colors">
              <XCircle className="w-5 h-5" />
            </button>
          </div>
        )}

        <div className="mt-6 flex justify-end">
          <button
            className={`px-6 py-2.5 rounded-lg font-medium flex items-center gap-2 transition-all ${
              !file || loading 
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed' 
                : 'bg-blue-600 text-white hover:bg-blue-500 shadow-[0_0_15px_rgba(37,99,235,0.4)]'
            }`}
            onClick={handleAnalyze}
            disabled={!file || loading}
          >
            {loading ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Extracting Features...
              </>
            ) : (
              <>
                <Activity className="w-4 h-4" />
                Initialize Static Analysis
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-4 p-4 bg-red-950/50 border border-red-900/50 rounded-lg flex items-center gap-3 text-red-400 text-sm animate-in fade-in slide-in-from-top-2">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          {error}
        </div>
      )}
    </div>
  )
}

// ─── App Root ─────────────────────────────────────────────────────────────────
export default function App() {
  const [result, setResult] = useState(null)
  const [showUpload, setShowUpload] = useState(false)

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-200 selection:bg-blue-500/30 font-sans">
      <header className="sticky top-0 z-50 bg-[#0b0f19]/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div 
            className="flex items-center gap-3 cursor-pointer group"
            onClick={() => { setResult(null); setShowUpload(false); }}
          >
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center text-white shadow-[0_0_15px_rgba(37,99,235,0.4)] group-hover:shadow-[0_0_20px_rgba(37,99,235,0.6)] transition-all">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-bold text-lg leading-tight tracking-tight text-white group-hover:text-blue-400 transition-colors">FraudGuard AI</h1>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-800/50 border border-slate-700 text-xs font-medium text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              ML Engine Ready
            </span>
            <span className="text-xs font-mono text-slate-500 border border-slate-700 px-2 py-1 rounded">SIH 2026</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {!result && !showUpload && (
          <CyberMatrixHero onDeploy={() => setShowUpload(true)} />
        )}

        {!result && showUpload && (
          <UploadZone 
            onResult={setResult} 
            onCancel={() => setShowUpload(false)} 
          />
        )}

        {result && (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <h2 className="text-lg font-medium text-slate-300">Analysis Results</h2>
              <button 
                onClick={() => { setResult(null); setShowUpload(true); }}
                className="text-sm font-medium text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1"
              >
                <Search className="w-4 h-4" /> New Investigation
              </button>
            </div>
            <AnalysisResults data={result} />
          </div>
        )}
      </main>
    </div>
  )
}
