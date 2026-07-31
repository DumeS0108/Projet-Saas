import { useState, useRef, useEffect } from "react";
import { useReactToPrint } from "react-to-print";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  // --- États liés à l'upload en cours ---
  const [selectedFile, setSelectedFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- États liés à l'affichage du rapport (upload OU historique) ---
  const [result, setResult] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);

  // --- État de la sidebar ---
  const [scansHistory, setScansHistory] = useState([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(true);

  const reportRef = useRef(null);

  const handlePrint = useReactToPrint({
    contentRef: reportRef,
    documentTitle: result?.filename
      ? `rapport-${result.filename.replace(".xml", "")}`
      : "rapport-scan",
  });

  // --- Chargement de l'historique ---
  // Correction ESLint : On ne force plus le chargement à true ici, 
  // on le fait uniquement quand c'est nécessaire.
  const fetchScansHistory = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/scans`);
      if (!response.ok) throw new Error("Impossible de charger l'historique.");
      const data = await response.json();
      setScansHistory(data);
    } catch (err) {
      console.error(err);
    } finally {
      setIsHistoryLoading(false);
    }
  };

  // Appel au montage du composant
  useEffect(() => {
  // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchScansHistory();
  }, []);

  // --- Récupération d'un ancien scan au clic dans la sidebar ---
  const fetchScanDetail = async (scanId) => {
    setError(null);
    setSelectedScanId(scanId);

    try {
      const response = await fetch(`${API_BASE}/api/scans/${scanId}`);

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Erreur lors du chargement de ce scan.");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
      setResult(null);
    }
  };

  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setResult(null);
    setError(null);
    setSelectedScanId(null);
  };

  const handleSubmit = async () => {
    if (!selectedFile) {
      setError("Merci de sélectionner un fichier .xml avant de lancer l'analyse.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch(`${API_BASE}/api/upload-scan`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Erreur lors de l'analyse du fichier.");
      }

      const data = await response.json();
      setResult(data);
      setSelectedScanId(data.scan_id);

      // Correction ESLint : On active le logo de chargement manuellement 
      // juste avant de rafraîchir l'historique
      setIsHistoryLoading(true);
      fetchScansHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (isoString) => {
    if (!isoString) return "";
    const date = new Date(isoString);
    return date.toLocaleDateString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      {/* ============================= */}
      {/* --- SIDEBAR : historique --- */}
      {/* ============================= */}
      <aside className="w-72 bg-slate-900 text-slate-300 shrink-0 print:hidden">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-white font-semibold text-sm tracking-wide">
            Historique des scans
          </h2>
        </div>

        <div className="overflow-y-auto max-h-[calc(100vh-64px)]">
          {isHistoryLoading && (
            <p className="text-slate-500 text-sm px-5 py-4">Chargement...</p>
          )}

          {!isHistoryLoading && scansHistory.length === 0 && (
            <p className="text-slate-500 text-sm px-5 py-4">
              Aucun scan enregistré pour le moment.
            </p>
          )}

          <ul>
            {scansHistory.map((scan) => (
              <li key={scan.id}>
                <button
                  onClick={() => fetchScanDetail(scan.id)}
                  className={`w-full text-left px-5 py-3 border-l-2 transition-colors ${
                    selectedScanId === scan.id
                      ? "bg-slate-800 border-emerald-400 text-white"
                      : "border-transparent hover:bg-slate-800/60 hover:border-slate-600"
                  }`}
                >
                  <p className="text-sm font-medium truncate">{scan.filename}</p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {formatDate(scan.date_creation)}
                  </p>
                  <p className="text-xs text-slate-500">
                    {scan.hosts_count} hôte(s)
                  </p>
                </button>
              </li>
            ))}
          </ul>
        </div>
      </aside>

      {/* ============================= */}
      {/* --- ZONE PRINCIPALE --- */}
      {/* ============================= */}
      <main className="flex-1 py-10 px-6">
        <div className="max-w-4xl mx-auto" ref={reportRef}>
          <header className="mb-8 print:hidden">
            <h1 className="text-2xl font-semibold text-slate-900">
              Analyseur de scan réseau
            </h1>
            <p className="text-slate-500 mt-1">
              Importez un export Nmap (.xml) ou consultez l'historique à gauche.
            </p>
          </header>

          {/* --- Zone d'upload --- */}
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6 print:hidden">
            <label className="block text-sm font-medium text-slate-700 mb-2">
              Fichier de scan Nmap
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="file"
                accept=".xml"
                onChange={handleFileChange}
                className="flex-1 text-sm text-slate-600 file:mr-4 file:py-2 file:px-4
                           file:rounded-lg file:border-0 file:text-sm file:font-medium
                           file:bg-slate-100 file:text-slate-700 hover:file:bg-slate-200
                           border border-slate-200 rounded-lg cursor-pointer"
              />
              <button
                onClick={handleSubmit}
                disabled={isLoading}
                className="bg-slate-900 text-white text-sm font-medium px-5 py-2.5
                           rounded-lg hover:bg-slate-800 transition-colors
                           disabled:bg-slate-300 disabled:cursor-not-allowed"
              >
                {isLoading ? "Analyse en cours..." : "Analyser"}
              </button>
            </div>
          </div>

          {isLoading && (
            <div className="text-center text-slate-500 py-6 print:hidden">
              Traitement du fichier, veuillez patienter...
            </div>
          )}

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 mb-6 text-sm print:hidden">
              {error}
            </div>
          )}

          {result && (
            <div className="flex justify-end mb-4 print:hidden">
              <button
                onClick={handlePrint}
                className="bg-emerald-600 text-white text-sm font-medium px-5 py-2.5
                           rounded-lg hover:bg-emerald-700 transition-colors
                           flex items-center gap-2"
              >
                Télécharger le rapport en PDF
              </button>
            </div>
          )}

          {/* --- Cartes hosts --- */}
          {result && (
            <div className="space-y-4">
              <p className="text-sm text-slate-500">
                {result.hosts_count} hôte(s) trouvé(s) dans « {result.filename} »
              </p>

              {result.hosts.map((host) => (
                <div
                  key={host.ip}
                  className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 break-inside-avoid"
                >
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-slate-900">
                      {host.ip}
                    </h2>
                    <span
                      className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                        host.status === "up"
                          ? "bg-green-100 text-green-700"
                          : "bg-slate-100 text-slate-500"
                      }`}
                    >
                      {host.status === "up" ? "En ligne" : host.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5 text-xs bg-slate-50 rounded-lg p-3">
                    <div>
                      <p className="text-slate-400 mb-0.5">Système</p>
                      <p className="text-slate-700 font-medium truncate" title={host.os || ""}>
                        {host.os || "Inconnu"}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-0.5">Hostname</p>
                      <p className="text-slate-700 font-medium truncate" title={host.hostname || ""}>
                        {host.hostname || "Inconnu"}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-0.5">Adresse MAC</p>
                      <p className="text-slate-700 font-medium truncate" title={host.mac_address || ""}>
                        {host.mac_address || "Inconnue"}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-400 mb-0.5">Constructeur</p>
                      <p className="text-slate-700 font-medium truncate" title={host.vendor || ""}>
                        {host.vendor || "Inconnu"}
                      </p>
                    </div>
                  </div>

                  {host.open_ports.length > 0 ? (
                    <table className="w-full text-sm text-left">
                      <thead>
                        <tr className="text-slate-400 border-b border-slate-100">
                          <th className="pb-2 font-medium">Port</th>
                          <th className="pb-2 font-medium">Protocole</th>
                          <th className="pb-2 font-medium">Service</th>
                          <th className="pb-2 font-medium">Version</th>
                        </tr>
                      </thead>
                      <tbody>
                        {host.open_ports.map((port, idx) => (
                          <tr key={idx} className="border-b border-slate-50 last:border-0">
                            <td className="py-2 text-slate-700 font-medium">{port.port}</td>
                            <td className="py-2 text-slate-500">{port.protocol}</td>
                            <td className="py-2 text-slate-500">{port.service}</td>
                            <td className="py-2 text-slate-500">
                              {port.product} {port.version}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="text-sm text-slate-400">Aucun port ouvert détecté.</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;