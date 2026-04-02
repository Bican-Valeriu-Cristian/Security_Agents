import { useState } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

export default function App() {
  const [url, setUrl] = useState("");
  const [raport, setRaport] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scan = async () => {
    if (!url) return;
    setLoading(true);
    setRaport("");
    setError("");
    try {
      const res = await axios.post("http://localhost:8000/scan", { url });
      setRaport(res.data.raport);
    } catch (e) {
      setError("Eroare la scanare. Verifică dacă backend-ul rulează.");
    } finally {
      setLoading(false);
    }
  };

  const downloadMD = () => {
    const blob = new Blob([raport], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "Raport_Audit.md";
    a.click();
  };

  return (
    <div style={{ maxWidth: 900, margin: "0 auto", padding: "2rem", fontFamily: "sans-serif" }}>
      <h1>🛡️ Security Audit Agent</h1>

      <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
        <input
          type="text"
          placeholder="https://example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1, padding: "0.6rem 1rem", fontSize: 16, borderRadius: 8,
                   border: "1px solid #ccc" }}
        />
        <button onClick={scan} disabled={loading}
          style={{ padding: "0.6rem 1.5rem", fontSize: 16, borderRadius: 8,
                   background: "#1a56db", color: "white", border: "none", cursor: "pointer" }}>
          {loading ? "Scanez..." : "Scanează"}
        </button>
      </div>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {loading && (
        <div style={{ textAlign: "center", padding: "3rem", color: "#555" }}>
          🤖 Agentul AI scanează... poate dura 30-60 secunde
        </div>
      )}

      {raport && (
        <>
          <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            <button onClick={downloadMD}
              style={{ padding: "0.5rem 1rem", borderRadius: 8, border: "1px solid #ccc",
                       cursor: "pointer" }}>
              ⬇️ Download .md
            </button>
          </div>
          <div style={{ border: "1px solid #e0e0e0", borderRadius: 12, padding: "2rem",
                        background: "#fafafa" }}>
            <ReactMarkdown>{raport}</ReactMarkdown>
          </div>
        </>
      )}
    </div>
  );
}