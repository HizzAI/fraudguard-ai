import { useState, useRef, useCallback } from 'react'
import {
  ShieldAlert, UploadCloud, File, AlertTriangle,
  Activity, XCircle, Search, Shield,
  ChevronDown, ChevronUp, Lock, FileJson, Cpu, Crosshair,
  ChevronRight, BrainCircuit, LayoutDashboard, Settings
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
    <div className={`bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm ${className}`}>
      <div className="flex items-center justify-between px-4 py-3 bg-slate-50/50 border-b border-slate-100">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-4 h-4 text-slate-500" />}
          <h3 className="font-semibold text-slate-800 text-sm tracking-wide">{title}</h3>
        </div>
        {count !== undefined && (
          <span className="bg-slate-200 text-slate-700 text-xs px-2 py-0.5 rounded-full font-mono">
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

function ExpandableCard({ icon: Icon, title, count, defaultOpen = false, children, className = '' }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm transition-all ${className}`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-50/50 border-b border-slate-100 hover:bg-slate-50 transition-colors focus:outline-none"
        aria-expanded={open}
      >
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-4 h-4 text-slate-500" />}
          <h3 className="font-semibold text-slate-800 text-sm tracking-wide">{title}</h3>
        </div>
        <div className="flex items-center gap-3">
          {count !== undefined && (
            <span className="bg-slate-200 text-slate-700 text-xs px-2 py-0.5 rounded-full font-mono">
              {count}
            </span>
          )}
          {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
        </div>
      </button>
      {open && (
        <div className="p-4 border-t border-slate-100">
          {children}
        </div>
      )}
    </div>
  )
}

function KV({ label, value }) {
  const empty = value === null || value === undefined || value === ''
  return (
    <div className="flex flex-col mb-3 last:mb-0">
      <span className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</span>
      {empty ? (
        <span className="text-sm text-slate-400 italic">Not available</span>
      ) : (
        <span className="text-sm text-slate-800 font-mono break-all">{String(value)}</span>
      )}
    </div>
  )
}

function TagList({ items, emptyMsg = 'None' }) {
  if (!items || items.length === 0) {
    return <span className="text-sm text-slate-400 italic">{emptyMsg}</span>
  }
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item, i) => {
        let isDangerous = false;
        const lowered = item.toLowerCase();
        if (lowered.includes('sms') || lowered.includes('location') || lowered.includes('camera') || lowered.includes('record_audio') || lowered.includes('contacts')) {
          isDangerous = true;
        }
        return (
          <span key={i} className={`text-xs px-2 py-1 rounded-md font-mono border ${isDangerous ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-slate-100 text-slate-600 border-slate-200'}`}>
            {item}
          </span>
        )
      })}
    </div>
  )
}

function ComponentGroup({ label, items }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="mb-4 last:mb-0 border border-slate-200 rounded-lg overflow-hidden">
      <div
        className="flex items-center justify-between px-3 py-2 bg-slate-50 cursor-pointer hover:bg-slate-100 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-700">{label}</span>
          <span className="bg-slate-200 text-slate-700 text-xs px-1.5 py-0.5 rounded-md font-mono">{items?.length ?? 0}</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </div>
      {open && (
        <div className="p-3 bg-white">
          <TagList items={items} emptyMsg="None declared" />
        </div>
      )}
    </div>
  )
}

// ─── Results Panels ──────────────────────────────────────────────────────────

function SummaryCards({ data }) {
  const risk = data.risk;
  const score = risk?.score;
  const classification = risk?.classification;
  const findings = risk?.findings ?? [];
  const ck = classKey(classification);

  const getRiskColor = () => {
    if (ck === 'malware' || ck === 'critical' || ck === 'high') return 'text-red-600';
    if (ck === 'suspicious' || ck === 'medium') return 'text-amber-600';
    if (ck === 'benign' || ck === 'low') return 'text-emerald-600';
    return 'text-slate-600';
  }

  const mlStatus = data.ml?.status === 'success' ? 'Active' : 'Unavailable';
  const mlPrediction = data.ml?.prediction;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Risk Score */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex justify-between items-center mb-4">
          <span className="text-sm font-medium text-slate-500">Risk Score</span>
          <ShieldAlert className={`w-5 h-5 ${getRiskColor()}`} />
        </div>
        <div>
          <div className={`text-3xl font-bold ${getRiskColor()}`}>{score ?? 'N/A'}</div>
          <div className="text-sm text-slate-500 uppercase mt-1 tracking-wider">{classification ?? 'Unavailable'}</div>
        </div>
      </div>

      {/* ML Prediction */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
         <div className="flex justify-between items-center mb-4">
          <span className="text-sm font-medium text-slate-500">ML Prediction</span>
          <BrainCircuit className="w-5 h-5 text-blue-500" />
        </div>
        <div>
          <div className={`text-xl font-bold ${mlPrediction === 'malicious' ? 'text-red-600' : mlPrediction === 'benign' ? 'text-emerald-600' : 'text-slate-700'}`}>
            {mlStatus === 'Active' ? mlPrediction.toUpperCase() : 'UNAVAILABLE'}
          </div>
          {mlStatus === 'Active' && (
            <div className="text-sm text-slate-500 mt-1">Confidence: {(data.ml?.confidence * 100).toFixed(1)}%</div>
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex justify-between items-center mb-4">
          <span className="text-sm font-medium text-slate-500">Threat Indicators</span>
          <AlertTriangle className="w-5 h-5 text-amber-500" />
        </div>
        <div className="flex items-end gap-4">
          <div>
            <div className="text-3xl font-bold text-slate-800">{findings.length}</div>
            <div className="text-sm text-slate-500 mt-1">Total</div>
          </div>
          <div className="w-px h-10 bg-slate-200"></div>
          <div>
            <div className="text-xl font-bold text-red-600">{findings.filter(f => f.severity === 'critical').length}</div>
            <div className="text-sm text-slate-500 mt-1">Critical</div>
          </div>
        </div>
      </div>

      {/* APK Size */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div className="flex justify-between items-center mb-4">
          <span className="text-sm font-medium text-slate-500">File Size</span>
          <File className="w-5 h-5 text-slate-400" />
        </div>
        <div>
          <div className="text-3xl font-bold text-slate-800">{formatBytes(data.size_bytes)}</div>
          <div className="text-sm text-slate-500 mt-1 truncate" title={data.filename}>{data.filename}</div>
        </div>
      </div>
    </div>
  )
}

function FindingItem({ f }) {
  const isHigh = f.severity === 'critical' || f.severity === 'high';
  return (
    <div className={`p-4 rounded-lg border ${isHigh ? 'bg-red-50 border-red-200' : 'bg-amber-50 border-amber-200'}`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-sm ${
            isHigh ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
          }`}>
            {f.severity || 'low'}
          </span>
          <span className="text-sm font-semibold text-slate-800">{f.category}</span>
        </div>
        <span className="text-xs font-mono text-slate-500">+{f.points} pts</span>
      </div>
      <p className="text-sm text-slate-600">{f.reason}</p>
      <div className="mt-2 text-xs font-mono text-slate-400 border-t border-slate-200 pt-2 flex items-center justify-between">
        <span>Rule: {f.rule_id}</span>
      </div>
    </div>
  );
}

function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <Card icon={Search} title="Threat Indicators" count={0}>
        <div className="p-8 text-center text-slate-500 border border-dashed border-slate-300 rounded-lg">
          No suspicious risk signals triggered by the rule engine.
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
    <Card icon={Crosshair} title="Threat Indicators" count={sorted.length}>
      <div className="grid grid-cols-1 gap-4">
        {sorted.map((f, i) => <FindingItem key={i} f={f} />)}
      </div>
    </Card>
  )
}

function ApkDetailsPanel({ data }) {
  return (
    <Card icon={File} title="APK Metadata">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <KV label="Filename" value={data.filename} />
          <KV label="File Size" value={formatBytes(data.size_bytes)} />
        </div>
        <div>
          <KV label="Package Name" value={data.app?.package_name} />
          <KV label="Version" value={data.app?.version} />
        </div>
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
          <div className="h-px bg-slate-100 my-2" />
          <KV label="Issuer" value={certificate.issuer} />
          <div className="h-px bg-slate-100 my-2" />
          <KV label="Serial Number" value={certificate.serial_number} />
        </div>
      ) : (
        <p className="text-sm text-slate-500 italic py-2">Certificate information unavailable.</p>
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
    <Card icon={Shield} title="Permission Visualizations" count={list.length}>
      {list.length > 5 && (
        <input
          className="w-full bg-white border border-slate-300 text-slate-800 text-sm rounded-md px-3 py-2 mb-4 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
          type="text"
          placeholder="Filter permissions..."
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

function FeatureVectorPanel({ ml }) {
  const status = ml?.status;
  return (
    <Card icon={Activity} title="Feature-Vector Panel">
      <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
        {status === 'success' ? (
          <div>
            <h4 className="text-sm font-semibold text-slate-800 mb-2">Machine Learning Features Extracted</h4>
            <p className="text-sm text-slate-600 mb-4">
              The ML pipeline successfully extracted 47 features from the static analysis output for evaluation against the SVM model.
            </p>
            <div className="flex flex-col gap-2 text-sm font-mono text-slate-700 bg-white p-3 rounded border border-slate-200">
               <div className="flex justify-between">
                 <span>Features Used:</span>
                 <span className="font-semibold text-blue-600">{ml.features_used || 47}</span>
               </div>
               <div className="flex justify-between">
                 <span>Malicious Probability:</span>
                 <span className="font-semibold text-red-600">{(ml.probability_malicious * 100).toFixed(4)}%</span>
               </div>
               <div className="flex justify-between">
                 <span>Benign Probability:</span>
                 <span className="font-semibold text-emerald-600">{(ml.probability_benign * 100).toFixed(4)}%</span>
               </div>
            </div>
            <p className="text-xs text-slate-400 mt-3 italic">
              Note: The raw 47-dimensional feature vector is processed backend-side and is not fully exposed to the client to prevent scraping.
            </p>
          </div>
        ) : (
          <div className="text-sm text-slate-500 italic">
            Feature vector unavailable. The ML engine did not successfully process this file.
          </div>
        )}
      </div>
    </Card>
  )
}

function ApiIndicatorsPanel({ apis }) {
  const list = apis ?? []
  const SHOW = 80
  return (
    <ExpandableCard icon={FileJson} title="Extracted API Calls" count={list.length} defaultOpen={false} className="col-span-full">
      {list.length === 0 ? (
        <span className="text-sm text-slate-500">No method references extracted.</span>
      ) : (
        <>
          <TagList items={list.slice(0, SHOW)} />
          {list.length > SHOW && (
            <p className="text-xs text-slate-500 mt-4 pt-4 border-t border-slate-100">
              Showing {SHOW} of {list.length} extracted references. Full list available in raw JSON.
            </p>
          )}
        </>
      )}
    </ExpandableCard>
  )
}

function AnalysisErrorsPanel({ errors }) {
  if (!errors || errors.length === 0) return null
  return (
    <Card icon={AlertTriangle} title="Analysis Warnings" className="col-span-full border-amber-200">
      <div className="flex flex-col gap-2">
        {errors.map((e, i) => (
          <div key={i} className="bg-amber-50 text-amber-700 text-sm p-3 rounded-md font-mono border border-amber-200">{e}</div>
        ))}
      </div>
    </Card>
  )
}

function AnalysisFailedBanner({ data }) {
  return (
    <div className="col-span-full bg-white border border-red-200 rounded-xl p-8 text-center shadow-sm">
      <div className="w-16 h-16 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-4 border border-red-100">
        <XCircle className="w-8 h-8 text-red-500" />
      </div>
      <h3 className="text-2xl font-bold text-slate-800 mb-2">Analysis Failed</h3>
      <div className="inline-flex items-center gap-2 text-xs font-mono text-slate-600 bg-slate-50 px-3 py-1 rounded border border-slate-200 mb-6">
        <File className="w-3 h-3" /> {data.filename || "Unknown File"}
      </div>
      <p className="text-slate-600 text-sm max-w-2xl mx-auto mb-6">
        The uploaded file could not be parsed successfully. Static analysis requires a valid, readable Android APK file.
        <strong className="block mt-2 text-red-500 font-medium">No risk score or ML prediction could be generated.</strong>
      </p>
      {data.errors && data.errors.length > 0 && (
        <div className="flex flex-col gap-2 max-w-3xl mx-auto text-left">
          {data.errors.map((e, i) => (
            <div key={i} className="bg-red-50 text-red-600 text-xs p-3 rounded-md font-mono border border-red-100">{e}</div>
          ))}
        </div>
      )}
    </div>
  )
}

function AnalysisResults({ data }) {
  const failed = data.analysis_status !== 'success'

  return (
    <div className="flex flex-col animate-in fade-in duration-500">
      {failed ? (
        <AnalysisFailedBanner data={data} />
      ) : (
        <>
          <SummaryCards data={data} />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-6">
              <FindingsPanel findings={data.risk?.findings} />
              <PermissionsPanel permissions={data.permissions} />
            </div>

            <div className="lg:col-span-2 space-y-6">
              <ApkDetailsPanel data={data} />
              <FeatureVectorPanel ml={data.ml} />
              <CertificatePanel certificate={data.certificate} />
              <ComponentsPanel components={data.components} />
              <ApiIndicatorsPanel apis={data.apis} />
              <AnalysisErrorsPanel errors={data.errors} />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Upload Zone ──────────────────────────────────────────────────────────────
function UploadZone({ onResult }) {
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
    if (loading) return;

    setLoading(true)
    setError(null)

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
      setFile(null);
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
    <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-sm max-w-2xl mx-auto mt-12">
      <div className="mb-6 text-center">
        <div className="w-16 h-16 bg-blue-50 rounded-full flex items-center justify-center mx-auto mb-4 border border-blue-100">
           <UploadCloud className="w-8 h-8 text-blue-500" />
        </div>
        <h2 className="text-2xl font-bold text-slate-800 mb-2">
          New Investigation
        </h2>
        <p className="text-slate-500">Upload an Android package (.apk) for static security analysis.</p>
      </div>

      <div
        className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center transition-all ${
          dragging ? 'border-blue-500 bg-blue-50' : 'border-slate-300 hover:border-slate-400 hover:bg-slate-50'
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
        <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mb-4 text-slate-400">
          <File className="w-6 h-6" />
        </div>
        <p className="text-slate-700 font-medium mb-1">
          Drag & drop an APK here
        </p>
        <p className="text-slate-500 text-sm mb-4">
          or <button onClick={() => inputRef.current?.click()} className="text-blue-600 hover:text-blue-500 font-medium focus:outline-none">browse your files</button>
        </p>
      </div>

      {file && (
        <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4 overflow-hidden">
            <div className="p-3 bg-blue-100 text-blue-600 rounded-md shrink-0">
              <File className="w-6 h-6" />
            </div>
            <div className="overflow-hidden">
              <div className="text-slate-800 font-medium truncate" title={file.name}>{file.name}</div>
              <div className="text-slate-500 text-sm">{formatBytes(file.size)}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleClear}
              disabled={loading}
              className="px-3 py-2 text-slate-500 hover:text-slate-700 font-medium text-sm transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              className={`px-5 py-2.5 rounded-lg font-medium flex items-center gap-2 transition-all ${
                loading
                  ? 'bg-blue-300 text-white cursor-not-allowed'
                  : 'bg-blue-600 text-white hover:bg-blue-700 shadow-md'
              }`}
              onClick={handleAnalyze}
              disabled={loading}
            >
              {loading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Analyzing...
                </>
              ) : (
                <>
                  Analyze APK
                  <ChevronRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3 text-red-600 text-sm">
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

  return (
    <div className="flex h-screen bg-slate-50 font-sans overflow-hidden">
      {/* Dark Navy Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col hidden md:flex shrink-0">
        <div className="h-16 flex items-center px-6 border-b border-slate-800">
           <img
              src="/fraudguard-logo.svg"
              alt="FraudGuard AI Logo"
              className="w-7 h-7 mr-3"
            />
            <h1 className="font-bold text-lg text-white">
              FraudGuard <span className="text-blue-400">AI</span>
            </h1>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2">
          <button
            onClick={() => setResult(null)}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              !result ? 'bg-blue-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <UploadCloud className="w-4 h-4" /> New Analysis
          </button>

          <button
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <LayoutDashboard className="w-4 h-4" /> Dashboard
          </button>

          <button
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <Settings className="w-4 h-4" /> Settings
          </button>
        </nav>

        <div className="p-4 border-t border-slate-800">
           <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-800/50">
             <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-slate-300 font-bold text-xs">
               Admin
             </div>
             <div className="text-xs">
               <div className="font-medium text-slate-200">System Admin</div>
               <div className="text-slate-500">Security Team</div>
             </div>
           </div>
        </div>
      </aside>

      {/* Main Light Canvas */}
      <main className="flex-1 flex flex-col h-full overflow-hidden">
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 shrink-0 md:hidden">
            <div className="flex items-center gap-2">
              <img src="/fraudguard-logo.svg" alt="FraudGuard AI" className="w-6 h-6" />
              <h1 className="font-bold text-slate-800">FraudGuard AI</h1>
            </div>
            <button
              onClick={() => setResult(null)}
              className="text-sm font-medium text-blue-600"
            >
              New Analysis
            </button>
        </header>

        <div className="flex-1 overflow-y-auto p-6 md:p-8">
          <div className="max-w-6xl mx-auto">
            {!result ? (
              <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <UploadZone onResult={setResult} />
              </div>
            ) : (
              <div className="space-y-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
                  <div>
                    <h2 className="text-2xl font-bold text-slate-800">Analysis Report</h2>
                    <p className="text-slate-500 text-sm mt-1">Detailed security evaluation and ML inference results.</p>
                  </div>
                  <button
                    onClick={() => setResult(null)}
                    className="px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium rounded-lg transition-colors flex items-center gap-2 border border-slate-200 shadow-sm"
                  >
                    <UploadCloud className="w-4 h-4" /> Analyze Another
                  </button>
                </div>
                <AnalysisResults data={result} />
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
