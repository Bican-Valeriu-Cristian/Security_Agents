import { useState } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

// Lista cu uneltele noastre și endpoint-urile din Python
const TOOLS = [
  { id: "a01", name: "📡 A01 - Scraper", endpoint: "/api/tool/a01-scraper" },
  { id: "a02", name: "🔧 A02 - Headers", endpoint: "/api/tool/a02-headers" },
  { id: "a03", name: "🔍 A03 - CVE", endpoint: "/api/tool/a03-cve" },
  { id: "a04", name: "💉 A04 - Injection Check", endpoint: "/api/tool/a04-injection" },
  { id: "vt", name: "🦠 VirusTotal", endpoint: "/api/tool/virustotal" }
];

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  
  // Ce afișăm pe ecran
  const [view, setView] = useState("history"); 
  const [activeTab, setActiveTab] = useState("full"); 
  const [rawData, setRawData] = useState("");
  const [aiData, setAiData] = useState("");
  const [history, setHistory] = useState([]);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [authMode, setAuthMode] = useState("login"); 
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const api = axios.create({
    baseURL: "http://localhost:8000",
  });

  api.interceptors.request.use((config) => {
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  const handleAuth = async (e) => {
    e.preventDefault();
    setError("");
    try {
      if (authMode === "register") {
        await axios.post("http://localhost:8000/api/register", { username, password });
        alert("Cont creat! Acum te poți loga.");
        setAuthMode("login");
      } else {
        // FastAPI cere datele sub formă de form-data pentru endpoint-ul /token
        const formData = new FormData();
        formData.append("username", username);
        formData.append("password", password);

        const res = await axios.post("http://localhost:8000/token", formData);
        const newToken = res.data.access_token;
        setToken(newToken);
        localStorage.setItem("token", newToken);
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Eroare la autentificare");
    }
  };

  const logout = () => {
    setToken("");
    localStorage.removeItem("token");
  };

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await api.get("/api/history");
      setHistory(res.data);
      setView("history");
    } catch (e) {
      setError("Sesiune expirată sau eroare la încărcare.");
      if (e.response?.status === 401) logout();
    } finally {
      setLoading(false);
    }
  };

  const runTool = async (toolId, endpoint) => {
    if (!url) {
      setError("Te rog să introduci un URL valid mai întâi!");
      return;
    }

    setLoading(true);
    setError("");
    setRawData("");
    setAiData("");
    setActiveTab(toolId);

    setView("dashboard");

   try {
      const res = await api.post(endpoint, { url });
      if (toolId === "full") {
        setAiData(res.data.raport);
      } else {
        setRawData(res.data.raw_data);
        setAiData(res.data.ai_analysis);
      }
    } catch (e) {
      setError("Eroare la scanare. Verifică conexiunea.");
    } finally {
      setLoading(false);
    }
  };
if (!token) {
    return (
      <div className="auth-page" style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '100vh', 
        width: '100vw',
        background: 'radial-gradient(circle at top left, #111827, #000000)', 
        color: 'white',
        margin: 0,
        padding: 0,
        position: 'fixed',
        top: 0,
        left: 0
      }}>
        <div className="auth-card" style={{ 
          background: '#1f2937', 
          padding: '40px', 
          borderRadius: '16px', 
          width: '100%',
          maxWidth: '400px', 
          boxShadow: '0 20px 50px rgba(0,0,0,0.7)',
          border: '1px solid #374151',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: '50px', marginBottom: '10px' }}>🛡️</div>
          <h2 style={{ fontSize: '28px', fontWeight: 'bold', marginBottom: '10px', letterSpacing: '-1px' }}>Security OS</h2>
          <p style={{ color: '#9ca3af', marginBottom: '30px' }}>
            {authMode === 'login' ? 'Acces autorizat necesar' : 'Creare profil auditor'}
          </p>
          
          <form onSubmit={handleAuth}>
            <input 
              type="text" 
              placeholder="Utilizator" 
              style={{ 
                width: '100%', 
                padding: '12px', 
                marginBottom: '15px', 
                borderRadius: '8px', 
                border: '1px solid #374151', 
                background: '#111827', 
                color: 'white',
                outline: 'none'
              }} 
              onChange={(e) => setUsername(e.target.value)} 
            />
            <input 
              type="password" 
              placeholder="Parolă" 
              style={{ 
                width: '100%', 
                padding: '12px', 
                marginBottom: '25px', 
                borderRadius: '8px', 
                border: '1px solid #374151', 
                background: '#111827', 
                color: 'white',
                outline: 'none'
              }} 
              onChange={(e) => setPassword(e.target.value)} 
            />
            
            <button type="submit" style={{ 
              width: '100%', 
              padding: '14px', 
              borderRadius: '8px', 
              border: 'none', 
              background: '#10b981', 
              color: 'white', 
              fontWeight: 'bold',
              cursor: 'pointer',
              transition: 'transform 0.2s'
            }}>
              {authMode === 'login' ? 'AUTENTIFICARE' : 'ÎNREGISTRARE'}
            </button>
          </form>
          
          <div style={{ marginTop: '25px', fontSize: '14px' }}>
            {authMode === 'login' ? (
              <span onClick={() => setAuthMode('register')} style={{ cursor: 'pointer', color: '#3b82f6', textDecoration: 'underline' }}>Nu ai cont? Creează unul</span>
            ) : (
              <span onClick={() => setAuthMode('login')} style={{ cursor: 'pointer', color: '#3b82f6', textDecoration: 'underline' }}>Ai deja cont? Loghează-te</span>
            )}
          </div>
          {error && <p style={{ color: '#ef4444', marginTop: '20px', fontWeight: '500' }}>⚠️ {error}</p>}
        </div>
      </div>
    );
  }
  const downloadMD = () => {
    const blob = new Blob([aiData], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `Security_Report_${activeTab}.md`;
    a.click();
  };

 const loadFromHistory = (item) => {
    setAiData(item.ai_analysis);
    setRawData(item.raw_data);
    setUrl(item.url);
    setActiveTab(item.tool_used);
    setView("dashboard");
  };

  return (
    <>
      {/* MENIUL LATERAL */}
      <div className="sidebar">
        <div className="sidebar-title">🛡️ Security OS</div>

        <button 
          className={`tool-btn ${view === "dashboard" ? "active" : ""}`}
          onClick={() => setView("dashboard")}
        >
          🏠 Dashboard principal
        </button>

        <button 
          className={`tool-btn ${view === "history" ? "active" : ""}`}
          onClick={fetchHistory}
        >
          📜 Istoric Scanări
        </button>
        <div className="separator" style={{ margin: "20px 0", borderTop: "1px solid #374151" }}></div>

        {view === "dashboard" && (
          <>
          <input
          type="text"
          className="url-input"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          />

        <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 8 }}>UNELTE INDIVIDUALE</div>
        
        {TOOLS.map((tool) => (
          <button
            key={tool.id}
            disabled={loading}
            className={`tool-btn ${activeTab === tool.id ? "active" : ""}`}
            onClick={() => runTool(tool.id, tool.endpoint)}
          >
            {tool.name}
          </button>
        ))}

        <div style={{ marginTop: "auto" }}>
          <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 8, textAlign: "center" }}>ANALIZĂ AVANSATĂ</div>
          <button 
            className={`tool-btn primary ${activeTab === "full" ? "active" : ""}`}
            disabled={loading}
            onClick={() => runTool("full", "/scan")}
            style={{ width: "100%" }}
          >
            ⚡ START FULL AUDIT
          </button>
        </div>
        </>
        )}
        {/* LOGOUT */}
        <div style={{ marginTop: "auto", paddingTop: "20px", borderTop: "1px solid #374151" }}>
        <button
        className="tool-btn"
        onClick={logout}
        style={{ width: "100%", color: "#ef4444", borderColor: "#ef4444" }}
        >
        🚪 Deconectare
        </button>
        </div>
        
      </div>

      {/* ZONA CENTRALĂ */}
      <div className="main-content">
        <div className="header">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{view === "history" ? "Istoric Scanări Bază de Date" :
            activeTab === "full" ? "Raport de Audit Complet (Agent)" : "Analiză Individuală (Split-View)"}</h2>
            {aiData && !loading && (
              <button onClick={downloadMD} style={{ padding: "8px 16px", cursor: "pointer", borderRadius: 6, border: "1px solid #ccc" }}>
                ⬇️ Salvează Markdown
              </button>
            )}
          </div>
          {error && <p style={{ color: "red", marginTop: "10px" }}>{error}</p>}
        </div>

        {/* ECRANELE DE AFIȘARE */}
        {loading ? (
          <div className="loader">
            <div>🤖 Agentul AI procesează datele...</div>
            <div style={{ fontSize: 14 }}>Așteaptă răspunsul serverului</div>
          </div>
        ) : (
        <>
            {/* --- SECtIUNE NOUa: Vizualizarea Istoricului --- */}
            {view === "history" ? (
              <div className="history-grid">
                {history.length === 0 ? (
                  <p style={{ color: "#9ca3af" }}>Nu există scanări salvate în baza de date.</p>
                ) : (
                  history.map((item) => (
                    <div key={item.id} className="history-card" onClick={() => loadFromHistory(item)}>
                      <div className="card-header">
                        <strong>{item.tool_used}</strong>
                        <small style={{ color: "#6b7280" }}>{new Date(item.timestamp).toLocaleString()}</small>
                      </div>
                      <div className="card-body" style={{ marginTop: "10px", fontFamily: "monospace", fontSize: "0.9em" }}>
                        {item.url}
                      </div>
                      <div style={{ marginTop: "10px", fontSize: "0.8em", color: "#3b82f6" }}>
                        Click pentru detalii →
                      </div>
                    </div>
                  ))
                )}
              </div>
          ) : ( 
          <div className="split-view">
            
            {/* Dacă suntem pe un tool individual, afișăm Terminalul cu date brute */}
            {activeTab !== "full" && rawData && (
              <div className="panel terminal">
                <div className="panel-header">💻 Terminal (Raw Output)</div>
                <div className="panel-content">
                  {rawData}
                </div>
              </div>
            )}

            {/* Fereastra AI (apare mereu, fie completă, fie pe jumătate) */}
            {aiData && (
              <div className="panel">
                <div className="panel-header">🧠 AI Analyst Report</div>
                <div className="panel-content" style={{ lineHeight: "1.6" }}>
                  <ReactMarkdown>{aiData}</ReactMarkdown>
                </div>
              </div>
            )}

            {/* Mesaj inițial când nu e rulat nimic */}
            {!aiData && !rawData && !loading && (
              <div className="loader">
                👈 Introdu un URL în meniul din stânga și selectează o unealtă.
              </div>
            )}
          </div>
            )}
          </>
        )}
      </div>
    </>
  );
}