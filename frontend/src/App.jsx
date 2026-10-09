import { useState, useRef, useCallback } from 'react'
import CyberMatrixHero from './components/ui/cyber-matrix-hero'
import { 
  ShieldAlert, ShieldCheck, UploadCloud, File, AlertTriangle, 
  Activity, CheckCircle, XCircle, Search, Server, Shield, 
  ChevronDown, ChevronUp, Lock, FileJson, Cpu, Crosshair, 
  Info, ChevronRight, BrainCircuit
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

function ExpandableCard({ icon: Icon, title, count, defaultOpen = false, children, className = '' }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm transition-all ${className}`}>
      <button 
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-900/50 border-b border-slate-800 hover:bg-slate-800/80 transition-colors focus:outline-none"
        aria-expanded={open}
      >
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-4 h-4 text-slate-400" />}
          <h3 className="font-semibold text-slate-200 text-sm tracking-wide">{title}</h3>
        </div>
        <div className="flex items-center gap-3">
          {count !== undefined && (
            <span className="bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded-full font-mono">
              {count}
            </span>
          )}
          {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
        </div>
      </button>
      {open && (
        <div className="p-4 border-t border-slate-800">
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
  const [open, setOpen] = useState(false)
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

// ─── Results Panels ──────────────────────────────────────────────────────────

function RiskHero({ data }) {
  const risk = data.risk;
  const score = risk?.score
  const classification = risk?.classification
  const findings = risk?.findings ?? []
  
  const ck = classKey(classification)
  const isUnavailable = score === null || score === undefined

  const getDialColor = () => {
    if (ck === 'malware' || ck === 'critical' || ck === 'high') return 'text-red-500 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.2)]'
    if (ck === 'suspicious' || ck === 'medium') return 'text-amber-500 border-amber-500 shadow-[0_0_30px_rgba(245,158,11,0.2)]'
    if (ck === 'benign' || ck === 'low') return 'text-emerald-500 border-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.2)]'
    return 'text-slate-500 border-slate-500'
  }

  const getBadgeColor = () => {
    if (ck === 'malware' || ck === 'critical' || ck === 'high') return 'bg-red-500/10 text-red-500 border-red-500/20'
    if (ck === 'suspicious' || ck === 'medium') return 'bg-amber-500/10 text-amber-500 border-amber-500/20'
    if (ck === 'benign' || ck === 'low') return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
    return 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  }
  
  const mlStatus = data.ml?.status === 'success' ? 'Active' : 'Unavailable';
  const mlPrediction = data.ml?.prediction;
  const mlConfidence = data.ml?.confidence;
  const mlProbMalicious = data.ml?.probability_malicious;
  const mlProbBenign = data.ml?.probability_benign;

  const mlBadgeColor = mlStatus === 'Active' 
    ? (mlPrediction === 'malicious' ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20')
    : 'text-slate-400 bg-slate-500/10 border-slate-500/20';

  return (
    <div className="col-span-full bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg p-6 lg:p-8">
      <div className="flex flex-col md:flex-row items-center gap-8">
        <div className="flex flex-col items-center gap-4 shrink-0">
          <div className={`w-40 h-40 rounded-full border-4 flex flex-col items-center justify-center bg-slate-950 ${getDialColor()}`}>
            {isUnavailable ? (
              <span className="text-2xl font-bold">N/A</span>
            ) : (
              <>
                <span className="text-5xl font-black tracking-tighter">{score}</span>
                <span className="text-xs uppercase tracking-widest opacity-60 text-center px-2">Rule-Based Risk Score</span>
              </>
            )}
          </div>
          <div className={`px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-widest border ${getBadgeColor()}`}>
            {classification ?? 'Unavailable'}
          </div>
        </div>

        <div className="flex-1 flex flex-col gap-6 w-full">
          <div>
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-2">
              <h2 className="text-2xl font-bold text-white">Investigation Report</h2>
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase tracking-widest text-slate-500">Analysis Status:</span>
                <span className="flex items-center gap-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded-md">
                  <CheckCircle className="w-3 h-3" /> SUCCESS
                </span>
              </div>
            </div>
            <p className="text-slate-400 text-sm font-mono break-all">{data.filename || 'Unknown File'}</p>
          </div>
          
          <div className="bg-slate-800/30 border border-slate-800 rounded-lg p-4">
            <h3 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
              <Info className="w-4 h-4 text-blue-400" />
              Summary
            </h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              {risk?.summary || "This application has been analyzed based on its requested permissions and code patterns. The risk score reflects a deterministic sum of these features. Note: A high score may result from legitimate apps requesting sensitive permissions (like storage or camera) and does not strictly guarantee malicious intent without behavioral evidence."}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
             <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex flex-col justify-center">
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Machine Learning Engine</div>
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <BrainCircuit className={`w-5 h-5 ${mlStatus === 'Active' ? 'text-blue-400' : 'text-slate-500'}`} />
                  <span className={`px-2 py-0.5 rounded font-mono text-xs border ${mlBadgeColor}`}>
                    {mlStatus === 'Active' 
                      ? `PREDICTION: ${mlPrediction.toUpperCase()} (${(mlConfidence * 100).toFixed(1)}%)`
                      : 'UNAVAILABLE'}
                  </span>
                </div>
                {mlStatus === 'Active' && mlProbMalicious !== undefined && mlProbBenign !== undefined && (
                  <div className="mt-2 text-xs font-mono text-slate-400 space-y-1">
                    <div className="flex justify-between items-center">
                      <span>Malicious Prob:</span>
                      <span className="text-red-400">{(mlProbMalicious * 100).toFixed(3)}%</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Benign Prob:</span>
                      <span className="text-emerald-400">{(mlProbBenign * 100).toFixed(3)}%</span>
                    </div>
                    <div className="text-[10px] text-slate-500 mt-2 italic leading-tight whitespace-normal">
                      * These are model outputs, not ground-truth verdicts.
                    </div>
                  </div>
                )}
              </div>
            </div>
            
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-around">
               <div className="text-center">
                 <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Total</div>
                 <div className="text-xl font-semibold text-slate-200">{findings.length}</div>
               </div>
               <div className="w-px h-8 bg-slate-800"></div>
               <div className="text-center">
                 <div className="text-xs text-red-500/70 uppercase tracking-wider mb-1">Critical</div>
                 <div className="text-xl font-semibold text-red-500">{findings.filter(f => f.severity === 'critical').length}</div>
               </div>
               <div className="w-px h-8 bg-slate-800"></div>
               <div className="text-center">
                 <div className="text-xs text-amber-500/70 uppercase tracking-wider mb-1">High</div>
                 <div className="text-xl font-semibold text-amber-500">{findings.filter(f => f.severity === 'high').length}</div>
               </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function FindingItem({ f }) {
  const isHigh = f.severity === 'critical' || f.severity === 'high';
  return (
    <div className={`p-4 rounded-lg border ${isHigh ? 'bg-red-500/5 border-red-500/20' : 'bg-amber-500/5 border-amber-500/20'}`}>
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
      <div className="mt-2 text-xs font-mono text-slate-600 border-t border-slate-800/50 pt-2 flex items-center justify-between">
        <span>Rule: {f.rule_id}</span>
      </div>
    </div>
  );
}

function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <Card icon={Search} title="Investigation Findings" count={0} className="col-span-full">
        <div className="p-8 text-center text-slate-500 border border-dashed border-slate-700 rounded-lg">
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

  const topFindings = sorted.slice(0, 3);
  const otherFindings = sorted.slice(3);

  return (
    <div className="col-span-full space-y-4">
      <Card icon={Crosshair} title="Key Findings" count={topFindings.length} className="border-slate-700">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {topFindings.map((f, i) => <FindingItem key={i} f={f} />)}
        </div>
      </Card>
      
      {otherFindings.length > 0 && (
        <ExpandableCard icon={Search} title="Additional Findings" count={otherFindings.length} defaultOpen={false}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {otherFindings.map((f, i) => <FindingItem key={i} f={f} />)}
          </div>
        </ExpandableCard>
      )}
    </div>
  )
}

function ApkDetailsPanel({ data }) {
  return (
    <ExpandableCard icon={File} title="APK Metadata" defaultOpen={false}>
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
    </ExpandableCard>
  )
}

function CertificatePanel({ certificate }) {
  const hasCert = certificate && Object.keys(certificate).length > 0
  return (
    <ExpandableCard icon={Lock} title="Cryptographic Certificate" defaultOpen={false}>
      {hasCert ? (
        <div className="space-y-1">
          <KV label="Subject" value={certificate.subject} />
          <div className="h-px bg-slate-800 my-2" />
          <KV label="Issuer" value={certificate.issuer} />
          <div className="h-px bg-slate-800 my-2" />
          <KV label="Serial Number" value={certificate.serial_number} />
        </div>
      ) : (
        <p className="text-sm text-slate-500 italic py-2">Certificate information unavailable.</p>
      )}
    </ExpandableCard>
  )
}

function PermissionsPanel({ permissions }) {
  const [query, setQuery] = useState('')
  const list = permissions ?? []
  const filtered = query.trim()
    ? list.filter(p => p.toLowerCase().includes(query.toLowerCase()))
    : list

  return (
    <ExpandableCard icon={Shield} title="Requested Permissions" count={list.length} defaultOpen={false}>
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
    </ExpandableCard>
  )
}

function ComponentsPanel({ components }) {
  const c = components ?? {}
  return (
    <ExpandableCard icon={Cpu} title="Android Components" defaultOpen={false}>
      <div className="space-y-1">
        <ComponentGroup label="Activities" items={c.activities} />
        <ComponentGroup label="Services" items={c.services} />
        <ComponentGroup label="Broadcast Receivers" items={c.receivers} />
        <ComponentGroup label="Content Providers" items={c.providers} />
      </div>
    </ExpandableCard>
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
            <p className="text-xs text-slate-500 mt-4 pt-4 border-t border-slate-800">
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
    <Card icon={AlertTriangle} title="Analysis Warnings" className="col-span-full border-amber-900/50">
      <div className="flex flex-col gap-2">
        {errors.map((e, i) => (
          <div key={i} className="bg-amber-500/10 text-amber-400 text-sm p-3 rounded-md font-mono border border-amber-500/20">{e}</div>
        ))}
      </div>
    </Card>
  )
}

function AnalysisFailedBanner({ data }) {
  return (
    <div className="col-span-full bg-slate-900 border border-red-900/50 rounded-xl p-8 text-center shadow-lg">
      <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-red-500/20">
        <XCircle className="w-8 h-8 text-red-500" />
      </div>
      <h3 className="text-2xl font-bold text-white mb-2">Analysis Failed</h3>
      <div className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1 rounded border border-slate-800 mb-6">
        <File className="w-3 h-3" /> {data.filename || "Unknown File"}
      </div>
      <p className="text-slate-300 text-sm max-w-2xl mx-auto mb-6">
        The uploaded file could not be parsed successfully. Static analysis requires a valid, readable Android APK file. 
        <strong className="block mt-2 text-red-400 font-medium">No risk score or ML prediction could be generated.</strong>
      </p>
      {data.errors && data.errors.length > 0 && (
        <div className="flex flex-col gap-2 max-w-3xl mx-auto text-left">
          {data.errors.map((e, i) => (
            <div key={i} className="bg-slate-950 text-red-400 text-xs p-3 rounded-md font-mono border border-red-900/30">{e}</div>
          ))}
        </div>
      )}
    </div>
  )
}

function AnalysisResults({ data }) {
  const failed = data.analysis_status !== 'success'

  return (
    <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {failed ? (
        <AnalysisFailedBanner data={data} />
      ) : (
        <>
          <RiskHero data={data} />
          <FindingsPanel findings={data.risk?.findings} />
          
          <div className="mt-8">
            <h3 className="text-lg font-medium text-slate-300 mb-4 px-1">Technical Details</h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <ApkDetailsPanel data={data} />
              <CertificatePanel certificate={data.certificate} />
              <PermissionsPanel permissions={data.permissions} />
              <ComponentsPanel components={data.components} />
            </div>
            <div className="mt-4">
              <ApiIndicatorsPanel apis={data.apis} />
            </div>
            <div className="mt-4">
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
    if (loading) return; // prevent duplicate submissions

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
      setFile(null); // Clear file after successful dispatch
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
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 lg:p-8 shadow-sm">
      <div className="mb-6">
        <h2 className="text-xl font-bold text-white flex items-center gap-2 mb-1">
          <Server className="w-5 h-5 text-blue-500" />
          New Investigation
        </h2>
        <p className="text-sm text-slate-400">Upload an Android package (.apk) for static security analysis.</p>
      </div>

      <div
        className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center transition-all ${
          dragging ? 'border-blue-500 bg-blue-500/5' : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/50'
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
        <div className="w-16 h-16 bg-slate-800/50 rounded-full flex items-center justify-center mb-4 text-slate-400">
          <UploadCloud className="w-8 h-8" />
        </div>
        <p className="text-slate-300 font-medium mb-1">
          Drag &amp; drop an APK here
        </p>
        <p className="text-slate-500 text-sm mb-4">
          or <button onClick={() => inputRef.current?.click()} className="text-blue-400 hover:text-blue-300 font-medium">browse your files</button>
        </p>
      </div>

      {file && (
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4 overflow-hidden">
            <div className="p-3 bg-blue-500/10 text-blue-400 rounded-md shrink-0">
              <File className="w-6 h-6" />
            </div>
            <div className="overflow-hidden">
              <div className="text-slate-200 font-medium truncate" title={file.name}>{file.name}</div>
              <div className="text-slate-500 text-sm">{formatBytes(file.size)}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button 
              onClick={handleClear} 
              disabled={loading} 
              className="px-3 py-2 text-slate-400 hover:text-slate-200 font-medium text-sm transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              className={`px-5 py-2.5 rounded-lg font-medium flex items-center gap-2 transition-all ${
                loading 
                  ? 'bg-blue-600/50 text-white cursor-not-allowed' 
                  : 'bg-blue-600 text-white hover:bg-blue-500 shadow-[0_0_15px_rgba(37,99,235,0.3)]'
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
        <div className="mt-4 p-4 bg-red-950/50 border border-red-900/50 rounded-lg flex items-center gap-3 text-red-400 text-sm">
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
      <header className="sticky top-0 z-50 bg-[#0b0f19]/90 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <div 
            className="flex items-center gap-3 cursor-pointer group"
            onClick={() => { setResult(null); setShowUpload(false); }}
          >
            <img 
              src="/fraudguard-logo.svg" 
              alt="FraudGuard AI Logo" 
              className="w-8 h-8 group-hover:scale-105 transition-transform" 
            />
            <div>
              <h1 className="font-bold text-xl leading-tight tracking-tight text-white group-hover:text-blue-50 transition-colors">
                FraudGuard <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-cyan-300">AI</span>
              </h1>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-800/50 border border-slate-700 text-xs font-medium text-slate-300">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              System Online
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8">
        {!result && !showUpload && (
          <div className="animate-in fade-in duration-700">
            <CyberMatrixHero onDeploy={() => setShowUpload(true)} />
          </div>
        )}

        {!result && showUpload && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
            <UploadZone onResult={(data) => { setResult(data); setShowUpload(false); }} />
          </div>
        )}

        {result && (
          <div className="space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
               <h2 className="text-xl font-medium text-white">Investigation Details</h2>
               <button 
                 onClick={() => { setResult(null); setShowUpload(true); }}
                 className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg transition-colors flex items-center gap-2 border border-slate-700 hover:border-slate-600"
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
