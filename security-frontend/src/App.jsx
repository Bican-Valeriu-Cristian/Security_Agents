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
  const [activeTab, setActiveTab] = useState("full"); // "full" sau id-ul tool-ului
  const [rawData, setRawData] = useState("");
  const [aiData, setAiData] = useState("");

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

    try {
      const res = await axios.post(`http://localhost:8000${endpoint}`, { url });
      
      // Dacă e auditul complet, primim doar "raport"
      if (toolId === "full") {
        setAiData(res.data.raport);
      } 
      // Dacă e un tool individual, primim raw_data și ai_analysis
      else {
        setRawData(res.data.raw_data);
        setAiData(res.data.ai_analysis);
      }
    } catch (e) {
      setError("Eroare la conectare. Verifică dacă backend-ul FastAPI rulează pe portul 8000.");
    } finally {
      setLoading(false);
    }
  };

  const downloadMD = () => {
    const blob = new Blob([aiData], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `Security_Report_${activeTab}.md`;
    a.click();
  };

  return (
    <>
      {/* MENIUL LATERAL */}
      <div className="sidebar">
        <div className="sidebar-title">🛡️ Security OS</div>
        
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
      </div>

      {/* ZONA CENTRALĂ */}
      <div className="main-content">
        <div className="header">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>{activeTab === "full" ? "Raport de Audit Complet (Agent)" : "Analiză Individuală (Split-View)"}</h2>
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
      </div>
    </>
  );
}