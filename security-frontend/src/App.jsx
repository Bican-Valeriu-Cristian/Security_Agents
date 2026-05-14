import { useState, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

const TOOLS = [
  { id: "a01", name: "📡 A01 - Scraper", endpoint: "/api/tool/a01-scraper" },
  { id: "a02", name: "🔧 A02 - Headers", endpoint: "/api/tool/a02-headers" },
  { id: "a03", name: "🔍 A03 - CVE", endpoint: "/api/tool/a03-cve" },
  { id: "a04", name: "💉 A04 - Injection", endpoint: "/api/tool/a04-injection" },
  { id: "vt", name: "🦠 VirusTotal", endpoint: "/api/tool/virustotal" }
];

// Configurări per tool: empty state + mesaje de loading
const LOADING_MESSAGES = [
  "📡 Se colectează datele...",
  "🧠 Se analizează cu AI...",
  "📝 Se generează raportul..."
];

const TOOL_CONFIG = {
  full: {
    icon: "⚡",
    title: "Audit Complet de Securitate",
    description: "Rulează toate cele 5 module automat și generează un raport AI consolidat.",
    checks: [
      "Analiză cod sursă HTML (A01)",
      "Verificare headere HTTP și configurări (A02)",
      "Detectare versiuni vulnerabile și CVE-uri (A03)",
      "Test vectori de injecție HTML (A04)",
      "Reputație domeniu pe VirusTotal"
    ],
    loadingMessages: LOADING_MESSAGES
  },
  a01: {
    icon: "📡",
    title: "A01 - Scraper Cod Sursă",
    description: "Descarcă HTML-ul țintei și extrage informații sensibile ascunse în codul sursă.",
    checks: [
      "Comentarii dezvoltatori uitate în HTML",
      "Chei API și tokenuri expuse",
      "Path-uri și fișiere ascunse",
      "Metadate sensibile"
    ],
    loadingMessages: LOADING_MESSAGES
  },
  a02: {
    icon: "🔧",
    title: "A02 - Headere HTTP",
    description: "Verifică configurările de securitate transmise prin headerele HTTP.",
    checks: [
      "Content-Security-Policy (CSP)",
      "Strict-Transport-Security (HSTS)",
      "X-Frame-Options, X-Content-Type",
      "Configurări CORS și cookies"
    ],
    loadingMessages: LOADING_MESSAGES
  },
  a03: {
    icon: "🔍",
    title: "A03 - Detector CVE",
    description: "Identifică versiunile de software folosite și caută vulnerabilități publicate.",
    checks: [
      "Detectare framework-uri (jQuery, React, etc.)",
      "Identificare versiuni de server (Apache, Nginx)",
      "Căutare în bazele de date CVE",
      "Evaluare risc per componentă"
    ],
    loadingMessages: LOADING_MESSAGES
  },
  a04: {
    icon: "💉",
    title: "A04 - Injection Check",
    description: "Scanează formularele și câmpurile de input pentru riscuri de injectare HTML/XSS.",
    checks: [
      "Identificare formulare HTML",
      "Detectare input fields neprotejate",
      "Test reflective XSS",
      "Analiză validare client-side"
    ],
    loadingMessages: LOADING_MESSAGES
  },
  vt: {
    icon: "🦠",
    title: "VirusTotal - Reputație Domeniu",
    description: "Interoghează baza de date globală VirusTotal pentru reputația domeniului.",
    checks: [
      "Detectare malware și phishing",
      "Reputație istorică domeniu",
      "Verificare blacklisturi globale",
      "Analiză comunitate de securitate"
    ],
    loadingMessages: LOADING_MESSAGES
  }
};

// ====== EMPTY STATE ======
const EmptyState = ({ toolKey }) => {
  const cfg = TOOL_CONFIG[toolKey] || TOOL_CONFIG.full;
  return (
    <div className="empty-state">
      <div className="empty-state-icon">{cfg.icon}</div>
      <h3 className="empty-state-title">{cfg.title}</h3>
      <p className="empty-state-description">{cfg.description}</p>
      <ul className="empty-state-checklist">
        {cfg.checks.map(c => <li key={c}>{c}</li>)}
      </ul>
    </div>
  );
};

// ====== LOADING STATE ======
const LoadingState = ({ toolKey }) => {
  const cfg = TOOL_CONFIG[toolKey] || TOOL_CONFIG.full;
  const [msgIdx, setMsgIdx] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setMsgIdx(i => (i + 1) % cfg.loadingMessages.length);
    }, 2500);
    return () => clearInterval(interval);
  }, [cfg.loadingMessages.length]);

  return (
    <div className="loading-state">
      <div className="loading-tool-label">{cfg.title}</div>
      <div className="loading-spinner"></div>
      <div className="loading-message" key={msgIdx}>
        {cfg.loadingMessages[msgIdx]}
      </div>
      <div className="loading-progress-dots">
        <span></span><span></span><span></span>
      </div>
    </div>
  );
};

const extrageStatistici = (text) => {
  if (!text || typeof text !== "string") return null;
  const extrage = (reg) => { const m = text.match(reg); return m ? parseInt(m[1], 10) : 0; };
  const stats = { low: extrage(/SC[AĂ]ZUT:\s*(\d+)/i), medium: extrage(/MEDIU:\s*(\d+)/i), critical: extrage(/CRITIC:\s*(\d+)/i) };
  return (stats.low || stats.medium || stats.critical) ? stats : null;
};

const VulnerabilityChart = ({ stats }) => {
  const { low, medium, critical } = stats;
  const total = low + medium + critical;
  const radius = 35;
  const circ = 2 * Math.PI * radius;
  const critDash = total === 0 ? 0 : (critical / total) * circ;
  const medDash = total === 0 ? 0 : (medium / total) * circ;
  const lowDash = total === 0 ? 0 : (low / total) * circ;

  return (
    <div className="vuln-chart">
      <div className="vuln-chart-donut">
        <svg width="100" height="100" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="50" cy="50" r={radius} fill="none" stroke="#f1f5f9" strokeWidth="13" />
          {critical > 0 && <circle cx="50" cy="50" r={radius} fill="none" stroke="#dc2626" strokeWidth="13" strokeDasharray={`${critDash} ${circ}`} strokeDashoffset={0} />}
          {medium > 0 && <circle cx="50" cy="50" r={radius} fill="none" stroke="#f59e0b" strokeWidth="13" strokeDasharray={`${medDash} ${circ}`} strokeDashoffset={-critDash} />}
          {low > 0 && <circle cx="50" cy="50" r={radius} fill="none" stroke="#3b82f6" strokeWidth="13" strokeDasharray={`${lowDash} ${circ}`} strokeDashoffset={-(critDash + medDash)} />}
        </svg>
        <div className="vuln-chart-center">
          <div className="vuln-chart-number">{total}</div>
          <div className="vuln-chart-label"></div>
        </div>
      </div>
      <div className="vuln-chart-legend">
        <div className="vuln-legend-item critic">
          <span className="legend-name">CRITICAL</span>
          <span className="legend-value">{critical}</span>
        </div>
        <div className="vuln-legend-item medium">
          <span className="legend-name">MEDIUM</span>
          <span className="legend-value">{medium}</span>
        </div>
        <div className="vuln-legend-item low">
          <span className="legend-name">LOW</span>
          <span className="legend-value">{low}</span>
        </div>
      </div>
    </div>
  );
};

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState("dashboard");
  const [activeTab, setActiveTab] = useState("full");
  const [rawData, setRawData] = useState("");
  const [aiData, setAiData] = useState("");
  const [history, setHistory] = useState([]);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [authMode, setAuthMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const api = axios.create({ baseURL: "http://localhost:8000" });
  api.interceptors.request.use(config => { if (token) config.headers.Authorization = `Bearer ${token}`; return config; });

  const handleAuth = async (e) => {
    e.preventDefault();
    try {
      if (authMode === "register") {
        await axios.post("http://localhost:8000/api/register", { username, password });
        setAuthMode("login");
      } else {
        const fd = new FormData(); fd.append("username", username); fd.append("password", password);
        const res = await axios.post("http://localhost:8000/token", fd);
        setToken(res.data.access_token); localStorage.setItem("token", res.data.access_token);
        setView("dashboard");
      }
    } catch (err) { alert("Eroare de autentificare!"); }
  };

  const executeScan = async () => {
    if (!url) return; setLoading(true); setRawData(""); setAiData("");
    let ep = activeTab === "full" ? "/scan" : TOOLS.find(t => t.id === activeTab).endpoint;
    try {
      const res = await api.post(ep, { url });
      setAiData(res.data.raport || res.data.ai_analysis);
      setRawData(res.data.raw_data);
    } catch (e) { alert("Eroare de conexiune la scanare."); } finally { setLoading(false); }
  };

  if (!token) {
    const isLogin = authMode === 'login';
    const accentColor = isLogin ? '#3b82f6' : '#10b981';
    const accentSoft = isLogin ? '#eff6ff' : '#ecfdf5';

    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        width: '100vw',
        background: `
          radial-gradient(circle at 20% 30%, rgba(59, 130, 246, 0.06), transparent 45%),
          radial-gradient(circle at 80% 70%, rgba(16, 185, 129, 0.05), transparent 45%),
          #f8fafc
        `,
        fontFamily: 'Inter, system-ui, sans-serif'
      }}>
        <div style={{
          background: '#ffffff',
          borderRadius: '16px',
          width: '420px',
          border: '1px solid #e2e8f0',
          boxShadow: '0 10px 40px rgba(15, 23, 42, 0.08)',
          overflow: 'hidden'
        }}>
          {/* Bara colorată de sus — indicator vizual de mod */}
          <div style={{
            height: '4px',
            background: `linear-gradient(90deg, ${accentColor}, ${isLogin ? '#10b981' : '#3b82f6'})`
          }}></div>

          {/* Logo + brand */}
          <div style={{ padding: '32px 36px 0 36px', textAlign: 'center' }}>
            <div style={{ fontSize: '20px', fontWeight: '900', letterSpacing: '1px', color: '#0f172a', marginBottom: '4px' }}>
              🛡️ SECURITY OS
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8', letterSpacing: '0.5px' }}>
              Audit platform · v1.0
            </div>
          </div>

          {/* Tabs Login / Register */}
          <div style={{
            display: 'flex',
            margin: '28px 36px 0 36px',
            background: '#f1f5f9',
            borderRadius: '10px',
            padding: '4px',
            gap: '4px'
          }}>
            <button
              type="button"
              onClick={() => setAuthMode('login')}
              style={{
                flex: 1,
                padding: '10px',
                border: 'none',
                borderRadius: '7px',
                background: isLogin ? '#ffffff' : 'transparent',
                color: isLogin ? '#3b82f6' : '#64748b',
                fontWeight: '700',
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
                boxShadow: isLogin ? '0 1px 3px rgba(15,23,42,0.08)' : 'none',
                fontFamily: 'inherit'
              }}
            >
              🔑 LOGIN
            </button>
            <button
              type="button"
              onClick={() => setAuthMode('register')}
              style={{
                flex: 1,
                padding: '10px',
                border: 'none',
                borderRadius: '7px',
                background: !isLogin ? '#ffffff' : 'transparent',
                color: !isLogin ? '#10b981' : '#64748b',
                fontWeight: '700',
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
                boxShadow: !isLogin ? '0 1px 3px rgba(15,23,42,0.08)' : 'none',
                fontFamily: 'inherit'
              }}
            >
              ✨ REGISTER
            </button>
          </div>

          {/* Titlu + subtitlu mod activ */}
          <div style={{ padding: '24px 36px 8px 36px' }}>
            <h2 style={{
              margin: '0 0 4px 0',
              fontSize: '20px',
              fontWeight: '700',
              color: '#0f172a',
              letterSpacing: '-0.3px'
            }}>
              {isLogin ? 'Bine ai revenit' : 'Creează un cont nou'}
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
              {isLogin
                ? 'Autentifică-te pentru a continua auditul'
                : 'Înregistrează-te ca să începi să folosești platforma'}
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleAuth} style={{ padding: '16px 36px 28px 36px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', fontSize: '14px', color: '#94a3b8' }}>👤</span>
              <input
                type="text"
                placeholder="Utilizator"
                onChange={e => setUsername(e.target.value)}
                style={{
                  width: '100%',
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  padding: '12px 14px 12px 40px',
                  borderRadius: '8px',
                  color: '#0f172a',
                  fontSize: '14px',
                  outline: 'none',
                  boxSizing: 'border-box',
                  fontFamily: 'inherit',
                  transition: 'all 0.2s'
                }}
                onFocus={(e) => { e.target.style.borderColor = accentColor; e.target.style.background = '#ffffff'; e.target.style.boxShadow = `0 0 0 3px ${accentSoft}`; }}
                onBlur={(e) => { e.target.style.borderColor = '#e2e8f0'; e.target.style.background = '#f8fafc'; e.target.style.boxShadow = 'none'; }}
              />
            </div>

            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', fontSize: '14px', color: '#94a3b8' }}>🔒</span>
              <input
                type="password"
                placeholder="Parolă"
                onChange={e => setPassword(e.target.value)}
                style={{
                  width: '100%',
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  padding: '12px 14px 12px 40px',
                  borderRadius: '8px',
                  color: '#0f172a',
                  fontSize: '14px',
                  outline: 'none',
                  boxSizing: 'border-box',
                  fontFamily: 'inherit',
                  transition: 'all 0.2s'
                }}
                onFocus={(e) => { e.target.style.borderColor = accentColor; e.target.style.background = '#ffffff'; e.target.style.boxShadow = `0 0 0 3px ${accentSoft}`; }}
                onBlur={(e) => { e.target.style.borderColor = '#e2e8f0'; e.target.style.background = '#f8fafc'; e.target.style.boxShadow = 'none'; }}
              />
            </div>

            <button
              type="submit"
              style={{
                background: isLogin
                  ? 'linear-gradient(135deg, #3b82f6, #2563eb)'
                  : 'linear-gradient(135deg, #10b981, #059669)',
                color: 'white',
                border: 'none',
                padding: '13px',
                borderRadius: '8px',
                fontWeight: '700',
                fontSize: '14px',
                cursor: 'pointer',
                letterSpacing: '0.5px',
                boxShadow: isLogin
                  ? '0 2px 8px rgba(59, 130, 246, 0.25)'
                  : '0 2px 8px rgba(16, 185, 129, 0.25)',
                transition: 'all 0.2s',
                marginTop: '6px',
                fontFamily: 'inherit'
              }}
              onMouseEnter={(e) => { e.target.style.transform = 'translateY(-1px)'; }}
              onMouseLeave={(e) => { e.target.style.transform = 'translateY(0)'; }}
            >
              {isLogin ? 'AUTENTIFICĂ-TE' : 'CREEAZĂ CONT'}
            </button>
          </form>

          {/* Footer cu link de switch */}
          <div style={{
            padding: '14px 36px 22px 36px',
            textAlign: 'center',
            borderTop: '1px solid #f1f5f9',
            background: '#fafbfc'
          }}>
            <p style={{ margin: 0, fontSize: '13px', color: '#64748b' }}>
              {isLogin ? 'Nu ai cont încă?' : 'Ai deja un cont?'}{' '}
              <span
                onClick={() => setAuthMode(isLogin ? 'register' : 'login')}
                style={{
                  cursor: 'pointer',
                  color: isLogin ? '#10b981' : '#3b82f6',
                  fontWeight: '700',
                  textDecoration: 'underline'
                }}
              >
                {isLogin ? 'Creează unul' : 'Loghează-te'}
              </span>
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="sidebar">
        <div style={{ fontSize: '18px', fontWeight: '900', letterSpacing: '1px', marginBottom: '30px', color: '#ffffff' }}>
          🛡️ SECURITY OS
        </div>
        
        <button className={`tool-btn ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>🏠 DASHBOARD</button>
        <button className={`tool-btn ${view === 'history' ? 'active' : ''}`} onClick={async () => { const r = await api.get("/api/history"); setHistory(r.data); setView("history"); }}>📜 DATA LOGS</button>
        
        <div style={{ margin: '20px 0', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}></div>
        
        {view === 'dashboard' && (
          <>
            <div style={{ fontSize: '10px', color: '#64748b', fontWeight: 'bold', marginBottom: '10px', letterSpacing: '1px' }}>SCAN MODE</div>
            <button className={`tool-btn ${activeTab === 'full' ? 'active' : ''}`} onClick={() => { setActiveTab('full'); setAiData(""); setRawData(""); }}>⚡ FULL AUDIT</button>
            {TOOLS.map(t => <button key={t.id} className={`tool-btn ${activeTab === t.id ? 'active' : ''}`} onClick={() => { setActiveTab(t.id); setAiData(""); setRawData(""); }}>{t.name}</button>)}
          </>
        )}
        
        <button className="tool-btn" style={{ marginTop: 'auto', color: '#fca5a5', background: 'rgba(220, 38, 38, 0.12)', borderColor: 'rgba(220, 38, 38, 0.3)' }} onClick={() => { setToken(""); localStorage.removeItem("token"); }}>🚪 SIGN OUT</button>
      </div>

      <div className="main-content">
        <div className="header">
          <h1 style={{ margin: 0, fontSize: '28px', letterSpacing: '-0.5px' }}>{view === 'history' ? 'LOGS AUDIT' : 'DASHBOARD'}</h1>
        </div>

        {view === 'dashboard' ? (
          <>
            {!loading && !rawData && !aiData ? (
              <>
                <div className="action-bar">
                  <input className="url-input-modern" value={url} onChange={e => setUrl(e.target.value)} placeholder="ENTER_TARGET_URL (e.g. https://target.com)" />
                  <button className="scan-btn-glow" onClick={executeScan} disabled={loading}>{loading ? 'SCANNING...' : 'RUN SCAN'}</button>
                </div>
                <div className="empty-state-fullscreen">
                  <EmptyState toolKey={activeTab} />
                </div>
              </>
            ) : (
              <div className="split-view">
                {/* COLOANA STÂNGA: action bar + terminal */}
                <div className="left-column">
                  <div className="action-bar">
                    <input className="url-input-modern" value={url} onChange={e => setUrl(e.target.value)} placeholder="ENTER_TARGET_URL (e.g. https://target.com)" />
                    <button className="scan-btn-glow" onClick={executeScan} disabled={loading}>{loading ? 'SCANNING...' : 'RUN SCAN'}</button>
                  </div>
                  <div className="panel-cyber terminal-panel">
                    <div className="panel-header-cyber">RAW_SYSTEM_LOGS</div>
                    <div className="panel-content">
                      {loading ? (
                        <LoadingState toolKey={activeTab} />
                      ) : (
                        <pre className="terminal-text" style={{ margin: 0 }}>{rawData}</pre>
                      )}
                    </div>
                  </div>
                </div>

                {/* COLOANA DREAPTA: chart (1/3) + AI Report (2/3) */}
                <div className="right-column">
                  {extrageStatistici(aiData) && (
                    <div className="panel-cyber chart-panel">
                      <div className="panel-header-cyber">
                        <span>VULNERABILITY_OVERVIEW</span>
                        <span style={{ fontSize: '11px', color: '#94a3b8', fontWeight: 500 }}>
                          {TOOL_CONFIG[activeTab]?.icon} {activeTab === 'full' ? 'FULL AUDIT' : (TOOLS.find(t => t.id === activeTab)?.name || '').replace(/^[^A-Z]*/, '')}
                        </span>
                      </div>
                      <div className="panel-content chart-panel-content">
                        <VulnerabilityChart stats={extrageStatistici(aiData)} />
                      </div>
                    </div>
                  )}
                  <div className="panel-cyber panel-ai">
                    <div className="panel-header-cyber">
                      <span>AI_SECURITY_REPORT</span>
                    </div>
                    <div className="panel-content">
                      {loading ? (
                        <LoadingState toolKey={activeTab} />
                      ) : (
                        <ReactMarkdown>{aiData}</ReactMarkdown>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="history-grid">
            {history.map(h => (
              <div key={h.id} className="history-card-cyber" onClick={() => { setAiData(h.ai_analysis); setRawData(h.raw_data); setUrl(h.url); setView("dashboard"); }}>
                <div className="history-card-top">
                  <span className="history-tool-badge">{h.tool_used}</span>
                  <span className="history-timestamp">{new Date(h.timestamp).toLocaleString('ro-RO', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}</span>
                </div>
                <div className="history-url" title={h.url}>{h.url}</div>
                <div className="history-card-bottom">Click pentru detalii</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}