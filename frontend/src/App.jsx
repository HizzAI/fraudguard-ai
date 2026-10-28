import { useState, useRef, useCallback, useEffect } from 'react'
import {
  ShieldAlert, UploadCloud, File, AlertTriangle,
  Activity, XCircle, Search, Shield,
  ChevronDown, ChevronUp, Lock, FileJson, Cpu, Crosshair,
  ChevronRight, BrainCircuit, LayoutDashboard, Settings,
  CheckCircle, Wifi, WifiOff, BarChart2, Clock
} from 'lucide-react'

// ─── API Configuration ──────────────────────────────────────────────────────
const rawApiBase = import.meta.env.VITE_API_BASE
const API_BASE = (rawApiBase && rawApiBase.trim()) ? rawApiBase.trim().replace(/\/+$/, '') : ''
const UPLOAD_ENDPOINT = `${API_BASE}/upload-apk`
const HEALTH_ENDPOINT = `${API_BASE}/health`

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

// Derive a plain-English top-level verdict from the actual API response
function deriveVerdict(data) {
  if (!data || data.analysis_status !== 'success') return 'error'
  const ck = classKey(data.risk?.classification)
  if (ck === 'critical' || ck === 'high') return 'malware'
  if (ck === 'medium' || ck === 'suspicious') return 'suspicious'
  return 'clean'
}

function verdictConfig(verdict) {
  switch (verdict) {
    case 'malware':
      return {
        label: 'Malware Detected',
        sub: 'This APK triggered high-severity risk indicators. Review the findings below.',
        bg: 'bg-red-50 border-red-200',
        pill: 'bg-red-100 text-red-700 border-red-200',
        icon: <XCircle className="w-8 h-8 text-red-500" />,
        dot: 'bg-red-500',
      }
    case 'suspicious':
      return {
        label: 'Suspicious',
        sub: 'This APK has medium-risk indicators that warrant closer review.',
        bg: 'bg-amber-50 border-amber-200',
        pill: 'bg-amber-100 text-amber-700 border-amber-200',
        icon: <AlertTriangle className="w-8 h-8 text-amber-500" />,
        dot: 'bg-amber-500',
      }
    case 'clean':
      return {
        label: 'Low Risk — No Major Indicators Detected',
        sub: 'The rule engine did not find high-risk signals. This does not guarantee the APK is safe.',
        bg: 'bg-emerald-50 border-emerald-200',
        pill: 'bg-emerald-100 text-emerald-700 border-emerald-200',
        icon: <CheckCircle className="w-8 h-8 text-emerald-500" />,
        dot: 'bg-emerald-500',
      }
    default:
      return {
        label: 'Analysis Failed',
        sub: 'The APK could not be parsed. Ensure it is a valid Android package.',
        bg: 'bg-slate-50 border-slate-200',
        pill: 'bg-slate-100 text-slate-700 border-slate-200',
        icon: <XCircle className="w-8 h-8 text-slate-400" />,
        dot: 'bg-slate-400',
      }
  }
}

// ─── Shared UI Primitives ────────────────────────────────────────────────────
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
  const [open, setOpen] = useState(defaultOpen)
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
        const lowered = item.toLowerCase()
        const isDangerous = lowered.includes('sms') || lowered.includes('location') ||
          lowered.includes('camera') || lowered.includes('record_audio') || lowered.includes('contacts')
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

// ─── Analysis Result: Simplified View ────────────────────────────────────────

// A. Main Verdict Banner
function VerdictBanner({ data }) {
  const verdict = deriveVerdict(data)
  const cfg = verdictConfig(verdict)
  const risk = data.risk
  const ml = data.ml

  return (
    <div className={`border rounded-xl p-6 flex flex-col sm:flex-row sm:items-center gap-5 ${cfg.bg}`}>
      <div className="shrink-0">{cfg.icon}</div>
      <div className="flex-1">
        <div className="flex flex-wrap items-center gap-2 mb-1">
          <h3 className="text-xl font-bold text-slate-800">{cfg.label}</h3>
          {risk?.classification && (
            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border uppercase tracking-wide ${cfg.pill}`}>
              {risk.classification}
            </span>
          )}
        </div>
        <p className="text-sm text-slate-600">{cfg.sub}</p>
      </div>
      {risk?.score !== undefined && (
        <div className="shrink-0 text-center">
          <div className="text-4xl font-black text-slate-800">{risk.score}</div>
          <div className="text-xs text-slate-500 uppercase tracking-wider mt-0.5">Risk Score / 100</div>
        </div>
      )}
    </div>
  )
}

// B. Key Info Row
function KeyInfoRow({ data }) {
  const ml = data.ml
  const mlActive = ml?.status === 'success'
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm">
        <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">File</div>
        <div className="text-sm font-semibold text-slate-800 truncate" title={data.filename}>{data.filename || '—'}</div>
        <div className="text-xs text-slate-500 mt-0.5">{formatBytes(data.size_bytes)}</div>
      </div>
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm">
        <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Package</div>
        <div className="text-sm font-semibold text-slate-800 truncate font-mono" title={data.app?.package_name}>{data.app?.package_name || 'Unknown'}</div>
        <div className="text-xs text-slate-500 mt-0.5">v{data.app?.version || '?'}</div>
      </div>
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm">
        <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Threat Indicators</div>
        <div className="text-2xl font-bold text-slate-800">{data.risk?.findings?.length ?? '—'}</div>
        <div className="text-xs text-red-500 mt-0.5">
          {data.risk?.findings?.filter(f => f.severity === 'critical').length ?? 0} critical
        </div>
      </div>
      <div className="bg-white border border-slate-200 rounded-lg p-4 shadow-sm">
        <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">ML Prediction</div>
        {mlActive ? (
          <>
            <div className={`text-sm font-bold ${ml.prediction === 'malicious' ? 'text-red-600' : 'text-emerald-600'}`}>
              {ml.prediction?.toUpperCase()}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">Confidence: {(ml.confidence * 100).toFixed(1)}%</div>
          </>
        ) : (
          <div className="text-sm text-slate-400 italic">Unavailable</div>
        )}
      </div>
    </div>
  )
}

// C. Why this result? — findings in plain English
function FindingItem({ f }) {
  const isHigh = f.severity === 'critical' || f.severity === 'high'
  return (
    <div className={`p-4 rounded-lg border ${isHigh ? 'bg-red-50 border-red-200' : 'bg-amber-50 border-amber-200'}`}>
      <div className="flex items-start justify-between mb-1.5">
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-sm ${isHigh ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}`}>
            {f.severity || 'low'}
          </span>
          <span className="text-sm font-semibold text-slate-800">{f.category}</span>
        </div>
        <span className="text-xs font-mono text-slate-400">+{f.points} pts</span>
      </div>
      <p className="text-sm text-slate-600">{f.reason}</p>
      <div className="mt-2 text-xs font-mono text-slate-400 border-t border-slate-200 pt-1.5">
        Rule: {f.rule_id}
      </div>
    </div>
  )
}

function WhyPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
        <h4 className="font-semibold text-slate-800 text-sm mb-3 flex items-center gap-2">
          <Search className="w-4 h-4 text-slate-400" />
          Why this result?
        </h4>
        <div className="p-6 text-center text-slate-500 border border-dashed border-slate-300 rounded-lg text-sm">
          No suspicious rule signals were triggered by the risk engine. The APK appears to use typical Android patterns.
        </div>
      </div>
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
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
      <h4 className="font-semibold text-slate-800 text-sm mb-4 flex items-center gap-2">
        <Crosshair className="w-4 h-4 text-slate-400" />
        Why this result? <span className="text-xs font-normal text-slate-400 ml-1">({sorted.length} indicators)</span>
      </h4>
      <div className="flex flex-col gap-3">
        {sorted.map((f, i) => <FindingItem key={i} f={f} />)}
      </div>
    </div>
  )
}

// D. Technical Evidence — collapsible
function TechnicalEvidence({ data }) {
  return (
    <div className="space-y-4">
      {/* Permissions */}
      <PermissionsPanel permissions={data.permissions} />
      {/* Certificate */}
      <CertificatePanel certificate={data.certificate} />
      {/* Components */}
      <ComponentsPanel components={data.components} />
      {/* Feature Vector ML details */}
      <FeatureVectorPanel ml={data.ml} />
      {/* API calls — already an expandable card */}
      <ApiIndicatorsPanel apis={data.apis} />
      {/* Errors */}
      <AnalysisErrorsPanel errors={data.errors} />
    </div>
  )
}

// ─── Technical sub-panels (unchanged logic, preserved) ───────────────────────
function PermissionsPanel({ permissions }) {
  const [query, setQuery] = useState('')
  const list = permissions ?? []
  const filtered = query.trim() ? list.filter(p => p.toLowerCase().includes(query.toLowerCase())) : list

  return (
    <Card icon={Shield} title="Permissions" count={list.length}>
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
  const status = ml?.status
  return (
    <Card icon={Activity} title="ML Feature Vector">
      {status === 'success' ? (
        <div className="flex flex-col gap-2 text-sm font-mono text-slate-700 bg-slate-50 p-3 rounded border border-slate-200">
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
          <div className="flex justify-between">
            <span>Model Version:</span>
            <span className="font-semibold text-slate-600">{ml.model_version || '—'}</span>
          </div>
        </div>
      ) : (
        <div className="text-sm text-slate-500 italic">
          Feature vector unavailable. The ML engine did not successfully process this file.
        </div>
      )}
    </Card>
  )
}

function ApiIndicatorsPanel({ apis }) {
  const list = apis ?? []
  const SHOW = 80
  return (
    <ExpandableCard icon={FileJson} title="Extracted API Calls" count={list.length} defaultOpen={false}>
      {list.length === 0 ? (
        <span className="text-sm text-slate-500">No method references extracted.</span>
      ) : (
        <>
          <TagList items={list.slice(0, SHOW)} />
          {list.length > SHOW && (
            <p className="text-xs text-slate-500 mt-4 pt-4 border-t border-slate-100">
              Showing {SHOW} of {list.length} extracted references.
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
    <Card icon={AlertTriangle} title="Analysis Warnings" className="border-amber-200">
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
    <div className="bg-white border border-red-200 rounded-xl p-8 text-center shadow-sm">
      <div className="w-16 h-16 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-4 border border-red-100">
        <XCircle className="w-8 h-8 text-red-500" />
      </div>
      <h3 className="text-2xl font-bold text-slate-800 mb-2">Analysis Failed</h3>
      <div className="inline-flex items-center gap-2 text-xs font-mono text-slate-600 bg-slate-50 px-3 py-1 rounded border border-slate-200 mb-6">
        <File className="w-3 h-3" /> {data.filename || 'Unknown File'}
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

// ─── Full Analysis Results Page (simplified layout) ──────────────────────────
function AnalysisResults({ data, onNewAnalysis, onDashboard }) {
  const [showEvidence, setShowEvidence] = useState(false)
  const failed = data.analysis_status !== 'success'

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200">
        <div>
          <h2 className="text-xl font-bold text-slate-800">Analysis Report</h2>
          <p className="text-slate-500 text-sm mt-0.5">Static security evaluation — no APK code was executed.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onDashboard}
            className="px-3 py-2 text-slate-600 hover:text-slate-800 text-sm font-medium rounded-lg transition-colors flex items-center gap-2 border border-slate-200 bg-white hover:bg-slate-50 shadow-sm"
          >
            <LayoutDashboard className="w-4 h-4" /> Dashboard
          </button>
          <button
            onClick={onNewAnalysis}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2 shadow-sm"
          >
            <UploadCloud className="w-4 h-4" /> Analyze Another
          </button>
        </div>
      </div>

      {failed ? (
        <AnalysisFailedBanner data={data} />
      ) : (
        <>
          {/* A. Main verdict */}
          <VerdictBanner data={data} />

          {/* B. Key info row */}
          <KeyInfoRow data={data} />

          {/* C. Why this result */}
          <WhyPanel findings={data.risk?.findings} />

          {/* D. Technical evidence — collapsible */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
            <button
              onClick={() => setShowEvidence(v => !v)}
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-50 transition-colors focus:outline-none"
              aria-expanded={showEvidence}
            >
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-slate-400" />
                <span className="font-semibold text-slate-800 text-sm">View Technical Evidence</span>
                <span className="text-xs text-slate-400 font-normal">Permissions, components, certificate, API calls</span>
              </div>
              {showEvidence ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
            </button>
            {showEvidence && (
              <div className="p-5 border-t border-slate-100">
                <TechnicalEvidence data={data} />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

// ─── Upload Zone (unchanged logic) ───────────────────────────────────────────
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
    if (loading) return

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
      setFile(null)
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
    <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-sm max-w-2xl mx-auto mt-10">
      <div className="mb-6 text-center">
        <div className="w-16 h-16 bg-blue-50 rounded-full flex items-center justify-center mx-auto mb-4 border border-blue-100">
          <UploadCloud className="w-8 h-8 text-blue-500" />
        </div>
        <h2 className="text-2xl font-bold text-slate-800 mb-2">New Investigation</h2>
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
        <p className="text-slate-700 font-medium mb-1">Drag & drop an APK here</p>
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

// ─── Dashboard Page ───────────────────────────────────────────────────────────
function DashboardPage({ sessionCount, latestResult, onNewAnalysis, onViewLatest }) {
  const [healthStatus, setHealthStatus] = useState('checking') // 'checking' | 'connected' | 'error'

  useEffect(() => {
    let cancelled = false
    setHealthStatus('checking')
    fetch(HEALTH_ENDPOINT)
      .then(r => {
        if (!cancelled) setHealthStatus(r.ok ? 'connected' : 'error')
      })
      .catch(() => { if (!cancelled) setHealthStatus('error') })
    return () => { cancelled = true }
  }, [])

  const verdict = latestResult ? deriveVerdict(latestResult) : null
  const verdictCfg = verdict ? verdictConfig(verdict) : null

  return (
    <div className="max-w-3xl mx-auto space-y-6 mt-2">
      <div>
        <h2 className="text-xl font-bold text-slate-800">Dashboard</h2>
        <p className="text-slate-500 text-sm mt-0.5">Session overview — data resets when you close this tab.</p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Analyses this session */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Analyses This Session</span>
            <BarChart2 className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-3xl font-bold text-slate-800">{sessionCount}</div>
          <div className="text-xs text-slate-500 mt-1">completed since page load</div>
        </div>

        {/* Latest verdict */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Latest Verdict</span>
            <ShieldAlert className="w-4 h-4 text-slate-400" />
          </div>
          {latestResult ? (
            <>
              <div className={`flex items-center gap-2 mb-1`}>
                <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${verdictCfg?.dot}`}></div>
                <span className="text-sm font-bold text-slate-800">{verdictCfg?.label}</span>
              </div>
              <div className="text-xs text-slate-500 truncate font-mono" title={latestResult.filename}>{latestResult.filename}</div>
            </>
          ) : (
            <div className="text-sm text-slate-400 italic">No analysis yet</div>
          )}
        </div>

        {/* Threat indicators from latest */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs text-slate-500 uppercase tracking-wide">Threat Indicators</span>
            <AlertTriangle className="w-4 h-4 text-slate-400" />
          </div>
          {latestResult ? (
            <>
              <div className="text-3xl font-bold text-slate-800">{latestResult.risk?.findings?.length ?? '—'}</div>
              <div className="text-xs text-red-500 mt-1">
                {latestResult.risk?.findings?.filter(f => f.severity === 'critical').length ?? 0} critical — from latest report
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-400 italic">No analysis yet</div>
          )}
        </div>
      </div>

      {/* Backend connection */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm flex items-center justify-between">
        <div className="flex items-center gap-3">
          {healthStatus === 'checking' && <Activity className="w-5 h-5 text-slate-400 animate-pulse" />}
          {healthStatus === 'connected' && <Wifi className="w-5 h-5 text-emerald-500" />}
          {healthStatus === 'error' && <WifiOff className="w-5 h-5 text-red-500" />}
          <div>
            <div className="text-sm font-semibold text-slate-800">
              {healthStatus === 'checking' && 'Checking backend…'}
              {healthStatus === 'connected' && 'Backend Connected'}
              {healthStatus === 'error' && 'Backend Unreachable'}
            </div>
            <div className="text-xs text-slate-500">
              {healthStatus === 'connected' && `${HEALTH_ENDPOINT} responded OK`}
              {healthStatus === 'error' && (API_BASE ? `Cannot reach backend at ${HEALTH_ENDPOINT}. Check if the server is active.` : 'Ensure backend is running and VITE_API_BASE is configured.')}
              {healthStatus === 'checking' && 'Pinging health endpoint…'}
            </div>
          </div>
        </div>
        <div className={`w-2.5 h-2.5 rounded-full ${
          healthStatus === 'connected' ? 'bg-emerald-400' :
          healthStatus === 'error' ? 'bg-red-400' : 'bg-slate-300 animate-pulse'
        }`} />
      </div>

      {/* Empty state or quick actions */}
      {sessionCount === 0 ? (
        <div className="bg-slate-50 border border-dashed border-slate-300 rounded-xl p-10 text-center">
          <div className="w-14 h-14 bg-white border border-slate-200 rounded-full flex items-center justify-center mx-auto mb-4">
            <UploadCloud className="w-7 h-7 text-slate-400" />
          </div>
          <h3 className="text-slate-700 font-semibold mb-1">No analyses yet this session</h3>
          <p className="text-slate-500 text-sm mb-5">Upload an APK file to run your first security analysis. Results will appear here.</p>
          <button
            onClick={onNewAnalysis}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors shadow-sm"
          >
            Analyze an APK
          </button>
        </div>
      ) : (
        <div className="flex flex-col sm:flex-row gap-3">
          <button
            onClick={onNewAnalysis}
            className="flex-1 flex items-center justify-center gap-2 px-5 py-3 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl transition-colors shadow-sm"
          >
            <UploadCloud className="w-4 h-4" />
            Analyze an APK
          </button>
          {latestResult && (
            <button
              onClick={onViewLatest}
              className="flex-1 flex items-center justify-center gap-2 px-5 py-3 bg-white hover:bg-slate-50 text-slate-700 text-sm font-semibold rounded-xl transition-colors shadow-sm border border-slate-200"
            >
              <Search className="w-4 h-4" />
              View Latest Report
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Settings Page ────────────────────────────────────────────────────────────
function SettingsPage() {
  return (
    <div className="max-w-2xl mx-auto space-y-6 mt-2">
      <div>
        <h2 className="text-xl font-bold text-slate-800">Settings</h2>
        <p className="text-slate-500 text-sm mt-0.5">Project information and configuration.</p>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-100 shadow-sm overflow-hidden">
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Application</div>
          <div className="text-sm font-semibold text-slate-800">FraudGuard AI</div>
          <div className="text-xs text-slate-500 mt-0.5">AI-assisted Android APK security investigation platform</div>
        </div>
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">API Version</div>
          <div className="text-sm font-semibold text-slate-800 font-mono">2.0.0</div>
        </div>
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">ML Model</div>
          <div className="text-sm font-semibold text-slate-800 font-mono">svm-combined-v1.0</div>
          <div className="text-xs text-slate-500 mt-0.5">Trained on 241 APKs (120 benign, 121 malware) — 93.4% recall on prototype dataset</div>
        </div>
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Analysis Method</div>
          <div className="text-sm font-semibold text-slate-800">Static Analysis Only</div>
          <div className="text-xs text-slate-500 mt-0.5">APK files are never executed, installed, or run in an emulator.</div>
        </div>
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Backend Endpoint</div>
          <div className="text-sm font-semibold text-slate-800 font-mono">{HEALTH_ENDPOINT}</div>
        </div>
        <div className="px-5 py-4">
          <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Purpose</div>
          <div className="text-sm text-slate-600">Research prototype for Smart India Hackathon (SIH) 2026. Not a production security product.</div>
        </div>
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 text-xs text-amber-700">
        <strong>Disclaimer:</strong> FraudGuard AI is a prototype tool. ML predictions are probabilistic estimates based on a small training dataset. They do not constitute definitive malware verdicts and should be used alongside the deterministic rule engine output.
      </div>
    </div>
  )
}

// ─── App Root ─────────────────────────────────────────────────────────────────
export default function App() {
  // 'upload' | 'result' | 'dashboard' | 'settings'
  const [page, setPage] = useState('upload')
  const [result, setResult] = useState(null)
  const [sessionCount, setSessionCount] = useState(0)

  function handleResult(data) {
    setResult(data)
    setSessionCount(c => c + 1)
    setPage('result')
  }

  function goTo(p) { setPage(p) }

  const navItems = [
    {
      id: 'upload',
      label: 'New Analysis',
      icon: UploadCloud,
      onClick: () => goTo('upload'),
    },
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      onClick: () => goTo('dashboard'),
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      onClick: () => goTo('settings'),
    },
  ]

  // Derive active nav — result page highlights "New Analysis" as the active workflow
  const activeNav = page === 'result' ? 'upload' : page

  return (
    <div className="flex h-screen bg-slate-50 font-sans overflow-hidden">
      {/* Dark Navy Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex-col hidden md:flex shrink-0">
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

        <nav className="flex-1 px-4 py-6 space-y-1">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={item.onClick}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                activeNav === item.id
                  ? 'bg-blue-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <item.icon className="w-4 h-4 shrink-0" />
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      {/* Main Canvas */}
      <main className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Mobile header */}
        <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-4 shrink-0 md:hidden">
          <div className="flex items-center gap-2">
            <img src="/fraudguard-logo.svg" alt="FraudGuard AI" className="w-6 h-6" />
            <h1 className="font-bold text-slate-800 text-sm">FraudGuard AI</h1>
          </div>
          <div className="flex items-center gap-1">
            {navItems.map(item => (
              <button
                key={item.id}
                onClick={item.onClick}
                className={`p-2 rounded-lg text-xs font-medium transition-colors ${
                  activeNav === item.id ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-700 hover:bg-slate-100'
                }`}
                title={item.label}
              >
                <item.icon className="w-4 h-4" />
              </button>
            ))}
          </div>
        </header>

        {/* Page content */}
        <div className="flex-1 overflow-y-auto p-5 md:p-8">
          <div className="max-w-5xl mx-auto">

            {page === 'upload' && (
              <div className="animate-in fade-in duration-300">
                <UploadZone onResult={handleResult} />
              </div>
            )}

            {page === 'result' && result && (
              <div className="animate-in fade-in duration-300">
                <AnalysisResults
                  data={result}
                  onNewAnalysis={() => goTo('upload')}
                  onDashboard={() => goTo('dashboard')}
                />
              </div>
            )}

            {page === 'dashboard' && (
              <div className="animate-in fade-in duration-300">
                <DashboardPage
                  sessionCount={sessionCount}
                  latestResult={result}
                  onNewAnalysis={() => goTo('upload')}
                  onViewLatest={() => result && goTo('result')}
                />
              </div>
            )}

            {page === 'settings' && (
              <div className="animate-in fade-in duration-300">
                <SettingsPage />
              </div>
            )}

          </div>
        </div>
      </main>
    </div>
  )
}
