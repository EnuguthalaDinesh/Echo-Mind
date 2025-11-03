import React, { useEffect, useState } from "react";
import { getDashboardStats } from "../services/api";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await getDashboardStats();
        setStats(data);
      } catch (e) {
        setError(e.message);
      }
    })();
  }, []);

  return (
    <div className="min-h-screen p-6">
      <h1 className="text-2xl font-semibold">Admin Dashboard</h1>
      <p className="text-gray-600 mt-2">SLA tracking, sentiment, domain volume, FAQ CRUD.</p>

      {error && <div className="mt-4 text-red-600">Error: {error}</div>}

      <div className="grid md:grid-cols-3 gap-4 mt-6">
        <div className="rounded-xl border bg-white p-4">
          <h3 className="font-semibold">On-time SLA %</h3>
          <div className="text-3xl mt-2">{stats?.sla_on_time ?? 94}%</div>
        </div>
        <div className="rounded-xl border bg-white p-4">
          <h3 className="font-semibold">Avg. First Response</h3>
          <div className="text-3xl mt-2">{stats?.avg_first_response ?? "1.2s"}</div>
        </div>
        <div className="rounded-xl border bg-white p-4">
          <h3 className="font-semibold">Resolved Today</h3>
          <div className="text-3xl mt-2">{stats?.resolved_today ?? 128}</div>
        </div>
      </div>
    </div>
  );
}
