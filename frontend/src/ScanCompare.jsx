import { useMemo } from "react";

function ScanCompare({ scanA, scanB, onClose }) {
  // --- Calcul du diff : comparaison des IP entre les deux scans ---
  const diff = useMemo(() => {
    const ipsA = new Set(scanA.hosts.map((h) => h.ip));
    const ipsB = new Set(scanB.hosts.map((h) => h.ip));

    // Hôtes apparus : présents dans B mais absents de A
    const appeared = scanB.hosts.filter((h) => !ipsA.has(h.ip));

    // Hôtes disparus : présents dans A mais absents de B
    const disappeared = scanA.hosts.filter((h) => !ipsB.has(h.ip));

    // Hôtes communs aux deux scans (utile pour donner un contexte global)
    const common = scanB.hosts.filter((h) => ipsA.has(h.ip));

    return { appeared, disappeared, common };
  }, [scanA, scanB]);

  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6 print:hidden">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-lg font-semibold text-slate-900">
            Comparaison de scans
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            « {scanA.filename} » → « {scanB.filename} »
          </p>
        </div>
        <button
          onClick={onClose}
          className="text-sm text-slate-500 hover:text-slate-700 border border-slate-200
                     rounded-lg px-3 py-1.5 hover:bg-slate-50 transition-colors"
        >
          Fermer la comparaison
        </button>
      </div>

      {/* --- Résumé chiffré --- */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        <div className="bg-green-50 rounded-lg p-3 text-center">
          <p className="text-2xl font-semibold text-green-700">{diff.appeared.length}</p>
          <p className="text-xs text-green-700 mt-0.5">Hôte(s) apparu(s)</p>
        </div>
        <div className="bg-red-50 rounded-lg p-3 text-center">
          <p className="text-2xl font-semibold text-red-700">{diff.disappeared.length}</p>
          <p className="text-xs text-red-700 mt-0.5">Hôte(s) disparu(s)</p>
        </div>
        <div className="bg-slate-50 rounded-lg p-3 text-center">
          <p className="text-2xl font-semibold text-slate-700">{diff.common.length}</p>
          <p className="text-xs text-slate-500 mt-0.5">Hôte(s) commun(s)</p>
        </div>
      </div>

      {/* --- Hôtes apparus --- */}
      {diff.appeared.length > 0 && (
        <div className="mb-5">
          <h3 className="text-sm font-semibold text-green-700 mb-2">
            + Hôtes apparus
          </h3>
          <ul className="space-y-1.5">
            {diff.appeared.map((host) => (
              <li
                key={host.ip}
                className="text-sm bg-green-50 rounded-lg px-3 py-2 flex items-center justify-between"
              >
                <span className="font-medium text-slate-800">{host.ip}</span>
                <span className="text-xs text-slate-500">
                  {host.hostname || "Hostname inconnu"} · {host.open_ports.length} port(s) ouvert(s)
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* --- Hôtes disparus --- */}
      {diff.disappeared.length > 0 && (
        <div className="mb-5">
          <h3 className="text-sm font-semibold text-red-700 mb-2">
            − Hôtes disparus
          </h3>
          <ul className="space-y-1.5">
            {diff.disappeared.map((host) => (
              <li
                key={host.ip}
                className="text-sm bg-red-50 rounded-lg px-3 py-2 flex items-center justify-between"
              >
                <span className="font-medium text-slate-800">{host.ip}</span>
                <span className="text-xs text-slate-500">
                  {host.hostname || "Hostname inconnu"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {diff.appeared.length === 0 && diff.disappeared.length === 0 && (
        <p className="text-sm text-slate-400 text-center py-4">
          Aucune différence d'hôtes entre ces deux scans.
        </p>
      )}
    </div>
  );
}

export default ScanCompare;