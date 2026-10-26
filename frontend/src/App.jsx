import React, { useState, useRef, useEffect } from "react";
import { useReactToPrint } from "react-to-print";
import ScanStats from "./ScanStats";
import ScanCompare from "./ScanCompare";

const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function App() {
  // --- État d'authentification ---
  const [token, setToken] = useState(() => localStorage.getItem("token"));

  // --- États du formulaire de connexion/inscription ---
  const [authMode, setAuthMode] = useState("login"); // "login" | "register"
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authError, setAuthError] = useState(null);
  const [isAuthLoading, setIsAuthLoading] = useState(false);

  // --- États liés à l'upload en cours ---
  const [selectedFile, setSelectedFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- États liés à l'affichage du rapport ---
  const [result, setResult] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);

  // --- État de la sidebar ---
  const [scansHistory, setScansHistory] = useState([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(true);

  // --- États du comparateur de scans ---
  const [compareMode, setCompareMode] = useState(false);
  const [compareSelection, setCompareSelection] = useState([]); // max 2 IDs de scan
  const [compareData, setCompareData] = useState(null); // { scanA, scanB }
  const [isCompareLoading, setIsCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState(null);

  const reportRef = useRef(null);

  const handlePrint = useReactToPrint({
    contentRef: reportRef,
    documentTitle: result?.filename
      ? `rapport-${result.filename.replace(".xml", "")}`
      : "rapport-scan",
  });

  // ============================================================
  // --- Utilitaire : fetch authentifié ---
  // ============================================================
  const authFetch = async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status === 401) {
      handleLogout();
      throw new Error("Session expirée, merci de vous reconnecter.");
    }

    return response;
  };

  // ============================================================
  // --- Authentification ---
  // ============================================================

  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setIsAuthLoading(true);

    try {
      let response;

      if (authMode === "register") {
        response = await fetch(`${API_BASE}/api/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: authUsername, password: authPassword }),
        });
      } else {
        const formBody = new URLSearchParams();
        formBody.append("username", authUsername);
        formBody.append("password", authPassword);

        response = await fetch(`${API_BASE}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: formBody,
        });
      }

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Identifiants invalides.");
      }

      const data = await response.json();

      localStorage.setItem("token", data.access_token);
      setToken(data.access_token);
      setAuthUsername("");
      setAuthPassword("");
    } catch (err) {
      setAuthError(err.message);
    } finally {
      setIsAuthLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    setToken(null);
    setResult(null);
    setScansHistory([]);
    setSelectedScanId(null);
  };

  // ============================================================
  // --- Chargement de l'historique au montage (si déjà connecté) ---
  // ============================================================
  useEffect(() => {
    if (!token) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsHistoryLoading(false);
      return;
    }

    let ignore = false;

    const loadInitialHistory = async () => {
      try {
        const response = await authFetch(`${API_BASE}/api/scans`);
        if (!response.ok) throw new Error("Impossible de charger l'historique.");
        const data = await response.json();
        if (!ignore) setScansHistory(data);
      } catch (err) {
        console.error(err);
      } finally {
        if (!ignore) setIsHistoryLoading(false);
      }
    };

    loadInitialHistory();

    return () => {
      ignore = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchScansHistory = async () => {
    try {
      const response = await authFetch(`${API_BASE}/api/scans`);
      if (!response.ok) throw new Error("Impossible de charger l'historique.");
      const data = await response.json();
      setScansHistory(data);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchScanDetail = async (scanId) => {
    setError(null);
    setSelectedScanId(scanId);

    try {
      const response = await authFetch(`${API_BASE}/api/scans/${scanId}`);

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
      const response = await authFetch(`${API_BASE}/api/upload-scan`, {
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

  // Retourne les classes Tailwind adaptées au niveau de sévérité CVSS d'une CVE
  const getSeverityStyle = (severity) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-700 text-white";
      case "HIGH":
        return "bg-red-100 text-red-700";
      case "MEDIUM":
        return "bg-orange-100 text-orange-700";
      case "LOW":
        return "bg-yellow-100 text-yellow-700";
      default:
        return "bg-slate-100 text-slate-500";
    }
  };

  // ============================================================
  // --- Comparateur : sélection et récupération des scans ---
  // ============================================================

  // Sélection/désélection d'un scan pour la comparaison (max 2)
  const toggleCompareSelection = (scanId) => {
    setCompareData(null); // on invalide un ancien résultat de comparaison
    setCompareError(null);

    setCompareSelection((prev) => {
      if (prev.includes(scanId)) {
        return prev.filter((id) => id !== scanId);
      }
      if (prev.length >= 2) {
        return prev; // déjà 2 sélectionnés, on ignore un 3e clic
      }
      return [...prev, scanId];
    });
  };

  // Récupération automatique des 2 scans dès que la sélection est complète
  useEffect(() => {
    if (compareSelection.length !== 2) return;

    let ignore = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsCompareLoading(true);
    setCompareError(null);

    const loadBothScans = async () => {
      try {
        const [resA, resB] = await Promise.all([
          authFetch(`${API_BASE}/api/scans/${compareSelection[0]}`),
          authFetch(`${API_BASE}/api/scans/${compareSelection[1]}`),
        ]);

        if (!resA.ok || !resB.ok) {
          throw new Error("Impossible de charger l'un des deux scans à comparer.");
        }

        const scanA = await resA.json();
        const scanB = await resB.json();

        if (!ignore) setCompareData({ scanA, scanB });
      } catch (err) {
        if (!ignore) setCompareError(err.message);
      } finally {
        if (!ignore) setIsCompareLoading(false);
      }
    };

    loadBothScans();

    return () => {
      ignore = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [compareSelection]);

  const exitCompareMode = () => {
    setCompareMode(false);
    setCompareSelection([]);
    setCompareData(null);
    setCompareError(null);
  };

  // ============================================================
  // --- Écran de connexion / inscription (si pas de token) ---
  // ============================================================
  if (!token) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center px-4">
        <div className="w-full max-w-sm bg-white rounded-xl shadow-sm border border-slate-200 p-8">
          <h1 className="text-xl font-semibold text-slate-900 mb-1 text-center">
            Network Report
          </h1>
          <p className="text-sm text-slate-500 mb-6 text-center">
            {authMode === "login" ? "Connectez-vous à votre compte" : "Créez votre compte"}
          </p>

          <form onSubmit={handleAuthSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Nom d'utilisateur
              </label>
              <input
                type="text"
                value={authUsername}
                onChange={(e) => setAuthUsername(e.target.value)}
                required
                className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm
                           focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Mot de passe
              </label>
              <input
                type="password"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                required
                className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm
                           focus:outline-none focus:ring-2 focus:ring-slate-900"
              />
            </div>

            {authError && (
              <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-3 py-2 text-sm">
                {authError}
              </div>
            )}

            <button
              type="submit"
              disabled={isAuthLoading}
              className="w-full bg-slate-900 text-white text-sm font-medium py-2.5
                         rounded-lg hover:bg-slate-800 transition-colors
                         disabled:bg-slate-300 disabled:cursor-not-allowed"
            >
              {isAuthLoading
                ? "Veuillez patienter..."
                : authMode === "login" ? "Se connecter" : "Créer mon compte"}
            </button>
          </form>

          <button
            onClick={() => {
              setAuthMode(authMode === "login" ? "register" : "login");
              setAuthError(null);
            }}
            className="w-full text-center text-sm text-slate-500 hover:text-slate-700 mt-4"
          >
            {authMode === "login"
              ? "Pas encore de compte ? Créer un compte"
              : "Déjà un compte ? Se connecter"}
          </button>
        </div>
      </div>
    );
  }

  // ============================================================
  // --- Dashboard principal (si connecté) ---
  // ============================================================
  return (
    <div className="flex min-h-screen bg-slate-50">
      {/* --- SIDEBAR --- */}
      <aside className="w-72 bg-slate-900 text-slate-300 flex-shrink-0 print:hidden flex flex-col">
        <div className="p-5 border-b border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-white font-semibold text-sm tracking-wide">
              Historique des scans
            </h2>
          </div>
          <button
            onClick={() => {
              if (compareMode) {
                exitCompareMode();
              } else {
                setCompareMode(true);
              }
            }}
            className={`w-full text-xs font-medium py-1.5 rounded-lg transition-colors ${
              compareMode
                ? "bg-emerald-600 text-white hover:bg-emerald-700"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {compareMode ? "Quitter la comparaison" : "Comparer avec un autre scan"}
          </button>
          {compareMode && (
            <p className="text-xs text-slate-500 mt-2">
              Sélectionnez 2 scans ({compareSelection.length}/2)
            </p>
          )}
        </div>

        <div className="overflow-y-auto flex-1">
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
                {compareMode ? (
                  <label
                    className={`w-full text-left px-5 py-3 border-l-2 flex items-start gap-3 cursor-pointer transition-colors ${
                      compareSelection.includes(scan.id)
                        ? "bg-slate-800 border-emerald-400"
                        : "border-transparent hover:bg-slate-800/60"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={compareSelection.includes(scan.id)}
                      onChange={() => toggleCompareSelection(scan.id)}
                      disabled={
                        !compareSelection.includes(scan.id) && compareSelection.length >= 2
                      }
                      className="mt-1"
                    />
                    <div>
                      <p className="text-sm font-medium truncate">{scan.filename}</p>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {formatDate(scan.date_creation)}
                      </p>
                      <p className="text-xs text-slate-500">
                        {scan.hosts_count} hôte(s)
                      </p>
                    </div>
                  </label>
                ) : (
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
                )}
              </li>
            ))}
          </ul>
        </div>

        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleLogout}
            className="w-full text-sm text-slate-400 hover:text-white
                       border border-slate-700 hover:border-slate-500
                       rounded-lg py-2 transition-colors"
          >
            Se déconnecter
          </button>
        </div>
      </aside>

      {/* --- ZONE PRINCIPALE --- */}
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
            {isLoading && (
              <p className="text-xs text-slate-400 mt-2">
                L'analyse peut prendre plusieurs dizaines de secondes : chaque service détecté
                est vérifié auprès de la base de vulnérabilités NVD.
              </p>
            )}
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

          {result && !compareMode && (
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

          {/* --- Comparateur : prioritaire sur l'affichage normal quand actif --- */}
          {compareMode && isCompareLoading && (
            <div className="text-center text-slate-500 py-10 print:hidden">
              Chargement des deux scans à comparer...
            </div>
          )}

          {compareMode && compareError && (
            <div className="bg-red-50 border border-red-200 text-red-700 rounded-lg px-4 py-3 mb-6 text-sm print:hidden">
              {compareError}
            </div>
          )}

          {compareMode && compareData && (
            <ScanCompare
              scanA={compareData.scanA}
              scanB={compareData.scanB}
              onClose={exitCompareMode}
            />
          )}

          {/* --- Graphiques (OS + top ports), affichés uniquement hors comparaison --- */}
          {!compareMode && result && <ScanStats hosts={result.hosts} />}

          {!compareMode && result && (
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
                          <React.Fragment key={idx}>
                            <tr className="border-b border-slate-50 last:border-0">
                              <td className="py-2 text-slate-700 font-medium">{port.port}</td>
                              <td className="py-2 text-slate-500">{port.protocol}</td>
                              <td className="py-2 text-slate-500">{port.service}</td>
                              <td className="py-2 text-slate-500">
                                {port.product} {port.version}
                              </td>
                            </tr>

                            {port.cves && port.cves.length > 0 && (
                              <tr className="bg-red-50">
                                <td colSpan={4} className="px-2 py-2">
                                  <div className="flex items-start gap-2">
                                    <span className="text-xs font-semibold text-red-700 whitespace-nowrap mt-0.5">
                                      ⚠️ Vulnérabilités détectées
                                    </span>
                                    <div className="flex flex-wrap gap-1.5">
                                      {port.cves.map((cve) => (
                                        <span
                                          key={cve.id}
                                          title={cve.summary}
                                          className={`text-xs font-medium px-2 py-0.5 rounded-full cursor-help ${getSeverityStyle(
                                            cve.severity
                                          )}`}
                                        >
                                          {cve.id} · {cve.severity}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="text-sm text-slate-400">Aucun port ouvert détecté.</p>
                  )}

                  {/* --- Encart des remédiations, si des recommandations existent --- */}
                  {host.remediations && host.remediations.length > 0 && (
                    <div className="mt-4 bg-blue-50 border border-blue-100 rounded-lg p-4">
                      <p className="text-xs font-semibold text-blue-800 mb-2">
                        💡 Recommandations de sécurité
                      </p>
                      <ul className="space-y-1.5">
                        {host.remediations.map((advice, idx) => (
                          <li key={idx} className="text-xs text-blue-700 flex gap-1.5">
                            <span className="text-blue-400">—</span>
                            <span>{advice}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
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