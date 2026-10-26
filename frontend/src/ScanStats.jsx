import { useMemo } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

// Palette cohérente avec le reste du dashboard (slate/emerald/orange)
const OS_COLORS = ["#0f172a", "#059669", "#f97316", "#3b82f6", "#a855f7", "#64748b"];

function ScanStats({ hosts }) {
  // --- Données du PieChart : répartition des OS ---
  const osData = useMemo(() => {
    const counts = {};
    hosts.forEach((host) => {
      const osLabel = host.os || "Inconnu";
      counts[osLabel] = (counts[osLabel] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [hosts]);

  // --- Données du BarChart : top 5 des ports les plus fréquents ---
  const topPortsData = useMemo(() => {
    const counts = {};
    hosts.forEach((host) => {
      host.open_ports.forEach((port) => {
        const label = `${port.port}/${port.protocol}`;
        counts[label] = (counts[label] || 0) + 1;
      });
    });
    return Object.entries(counts)
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [hosts]);

  // Pas de graphique pertinent si aucun host n'a de port ouvert détecté
  if (hosts.length === 0) return null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6 print:hidden">
      {/* --- PieChart : répartition des OS --- */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
        <h3 className="text-sm font-semibold text-slate-700 mb-3">
          Répartition des systèmes d'exploitation
        </h3>
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={osData}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={75}
              label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
            >
              {osData.map((_, index) => (
                <Cell key={index} fill={OS_COLORS[index % OS_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* --- BarChart : top 5 des ports les plus fréquents --- */}
      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
        <h3 className="text-sm font-semibold text-slate-700 mb-3">
          Ports les plus fréquents
        </h3>
        {topPortsData.length > 0 ? (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={topPortsData}>
              <XAxis dataKey="port" tick={{ fontSize: 12 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" fill="#059669" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-sm text-slate-400 py-10 text-center">
            Aucun port ouvert détecté sur ce scan.
          </p>
        )}
      </div>
    </div>
  );
}

export default ScanStats;