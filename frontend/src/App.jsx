import { useState, useRef, useCallback } from 'react'

// ─── Constants ─────────────────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:8000'
const UPLOAD_ENDPOINT = `${API_BASE}/upload-apk`

// ─── Helpers ────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function KV({ label, value }) {
  const empty = value === null || value === undefined || value === ''
  return (
    <>
      <span className="kv-key">{label}</span>
      {empty
        ? <span className="kv-null">Not available</span>
        : <span className="kv-val">{String(value)}</span>
      }
    </>
  )
}

function TagList({ items, emptyMsg }) {
  if (!items || items.length === 0) {
    return <span className="tag-empty">{emptyMsg || 'None'}</span>
  }
  return (
    <div className="tag-list">
      {items.map((item, i) => <span key={i} className="tag">{item}</span>)}
    </div>
  )
}

function ResultCard({ icon, title, children }) {
  return (
    <div className="result-card">
      <div className="result-card-header">
        <span className="card-icon">{icon}</span>
        {title}
      </div>
      <div className="result-card-body">
        {children}
      </div>
    </div>
  )
}

function AnalysisResults({ data }) {
  const status = data.analysis_status
  const isSuccess = status === 'success'

  return (
    <div className="results-section">

      {/* ── Overview ── */}
      <ResultCard icon="📊" title="Analysis Overview">
        <div className="kv-grid">
          <span className="kv-key">Filename</span>
          <span className="kv-val">{data.filename}</span>

          <span className="kv-key">File Size</span>
          <span className="kv-val">{formatBytes(data.size_bytes)}</span>

          <span className="kv-key">Status</span>
          <span className="kv-val">
            <span className={`badge ${isSuccess ? 'success' : 'failed'}`}>
              {isSuccess ? '✓' : '✕'} {status}
            </span>
          </span>
        </div>
      </ResultCard>

      {/* ── App Info ── */}
      <ResultCard icon="📱" title="Application Information">
        <div className="kv-grid">
          <KV label="Package Name"  value={data.app?.package_name} />
          <KV label="App Label"     value={data.app?.label} />
          <KV label="Version"       value={data.app?.version} />
        </div>
      </ResultCard>

      {/* ── Permissions ── */}
      <ResultCard icon="🔐" title={`Permissions (${data.permissions?.length ?? 0})`}>
        <TagList items={data.permissions} emptyMsg="No permissions declared" />
      </ResultCard>

      {/* ── Components ── */}
      <ResultCard icon="🧩" title="App Components">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>
              Activities ({data.components?.activities?.length ?? 0})
            </div>
            <TagList items={data.components?.activities} emptyMsg="None" />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>
              Services ({data.components?.services?.length ?? 0})
            </div>
            <TagList items={data.components?.services} emptyMsg="None" />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>
              Broadcast Receivers ({data.components?.receivers?.length ?? 0})
            </div>
            <TagList items={data.components?.receivers} emptyMsg="None" />
          </div>
          <div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 6, fontWeight: 600 }}>
              Content Providers ({data.components?.providers?.length ?? 0})
            </div>
            <TagList items={data.components?.providers} emptyMsg="None" />
          </div>
        </div>
      </ResultCard>

      {/* ── DEX ── */}
      <ResultCard icon="📦" title="DEX Information">
        <div className="kv-grid">
          <span className="kv-key">DEX File Count</span>
          <span className="kv-val">{data.dex?.count ?? 0}</span>
        </div>
      </ResultCard>

      {/* ── APIs ── */}
      <ResultCard icon="⚙️" title={`Method / API References (${data.apis?.length ?? 0})`}>
        {(!data.apis || data.apis.length === 0)
          ? <span className="tag-empty">No method references extracted</span>
          : (
            <>
              <TagList items={data.apis.slice(0, 100)} />
              {data.apis.length > 100 && (
                <p className="api-note">
                  Showing 100 of {data.apis.length} extracted method references.
                </p>
              )}
            </>
          )
        }
      </ResultCard>

      {/* ── Certificate ── */}
      <ResultCard icon="🔏" title="Certificate / Signing Information">
        {(!data.certificate || Object.keys(data.certificate).length === 0)
          ? <span className="tag-empty">No certificate information available</span>
          : (
            <div className="kv-grid">
              <KV label="Subject"       value={data.certificate.subject} />
              <KV label="Issuer"        value={data.certificate.issuer} />
              <KV label="Serial Number" value={data.certificate.serial_number} />
            </div>
          )
        }
      </ResultCard>

      {/* ── Errors ── */}
      {data.errors && data.errors.length > 0 && (
        <ResultCard icon="⚠️" title="Analysis Errors">
          <div className="error-list">
            {data.errors.map((e, i) => (
              <div key={i} className="error-item">{e}</div>
            ))}
          </div>
        </ResultCard>
      )}

    </div>
  )
}

// ─── Main App ────────────────────────────────────────────────────────────────
export default function App() {
  const [file, setFile]         = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [result, setResult]     = useState(null)
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef(null)

  // ─ file selection helpers ─
  function selectFile(f) {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.apk')) {
      setError('Only .apk files are accepted.')
      return
    }
    setError(null)
    setResult(null)
    setFile(f)
  }

  function handleInputChange(e) {
    selectFile(e.target.files?.[0] ?? null)
  }

  function handleClear() {
    setFile(null)
    setResult(null)
    setError(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  // ─ drag-and-drop ─
  const handleDragOver = useCallback((e) => { e.preventDefault(); setDragging(true) }, [])
  const handleDragLeave = useCallback(() => setDragging(false), [])
  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    selectFile(e.dataTransfer.files?.[0] ?? null)
  }, [])

  // ─ upload & analyse ─
  async function handleAnalyze() {
    if (!file) {
      setError('Please select an APK file first.')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    const formData = new FormData()
    formData.append('file', file)   // field name must match FastAPI param: `file`

    try {
      const response = await fetch(UPLOAD_ENDPOINT, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        let detail = `Server responded with HTTP ${response.status}`
        try {
          const errBody = await response.json()
          if (errBody.detail) detail = errBody.detail
        } catch (_) {}
        throw new Error(detail)
      }

      const data = await response.json()

      // Validate that the response has the expected shape
      if (typeof data !== 'object' || !('analysis_status' in data)) {
        throw new Error('Unexpected response format from backend.')
      }

      setResult(data)

    } catch (err) {
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        setError('Cannot reach backend. Make sure the FastAPI server is running on port 8000.')
      } else {
        setError(err.message || 'An unknown error occurred.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <header>
        <div className="logo-icon">🛡</div>
        <div className="logo-text">
          <h1>FraudGuard AI</h1>
          <p>Android APK Static Analysis</p>
        </div>
      </header>

      <main>
        {/* ── Upload Card ── */}
        <div className="upload-card">
          <h2>Upload APK for Analysis</h2>

          <div
            className={`drop-zone${dragging ? ' active' : ''}`}
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
            />
            <div className="drop-icon">📂</div>
            <p className="drop-label">
              Drag &amp; drop an APK here, or <span>browse to select</span>
            </p>
            <p className="drop-hint">Only .apk files are accepted</p>
          </div>

          {file && (
            <div className="selected-file">
              <span className="file-icon">📦</span>
              <div>
                <div className="file-name">{file.name}</div>
                <div className="file-size">{formatBytes(file.size)}</div>
              </div>
              <button className="clear-btn" onClick={handleClear} title="Remove">×</button>
            </div>
          )}

          <button
            className="analyze-btn"
            onClick={handleAnalyze}
            disabled={!file || loading}
          >
            {loading ? 'Analyzing…' : 'Analyze APK'}
          </button>
        </div>

        {/* ── Loading State ── */}
        {loading && (
          <div className="status-bar loading">
            <div className="spinner" />
            Uploading and running static analysis — this may take a moment…
          </div>
        )}

        {/* ── Error State ── */}
        {error && (
          <div className="status-bar error">
            <span>⚠</span> {error}
          </div>
        )}

        {/* ── Analysis Warning (analysis_status failed but no crash) ── */}
        {result && result.analysis_status === 'failed' && !error && (
          <div className="status-bar warning">
            <span>⚠</span>
            Analysis could not extract data from this APK.
            The file may be corrupted or not a valid Android package.
          </div>
        )}

        {/* ── Results ── */}
        {result && <AnalysisResults data={result} />}
      </main>
    </div>
  )
}
