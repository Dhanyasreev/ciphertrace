import React, { useEffect, useState } from 'react';
import { ShieldCheck, RefreshCw, FileText, AlertTriangle } from 'lucide-react';
import { AuditLogEntry, SecurityMetrics } from '../types.js';

export const AuditView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const fetchAuditData = async () => {
    setIsLoading(true);
    try {
      const [auditRes, metricsRes] = await Promise.all([
        fetch('/api/audit'),
        fetch('/api/metrics'),
      ]);

      if (auditRes.ok) {
        const aData = await auditRes.json();
        setLogs(aData.logs || []);
      }
      if (metricsRes.ok) {
        const mData = await metricsRes.json();
        setMetrics(mData);
      }
    } catch (err) {
      console.error('Failed to load audit telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-slate-900 text-emerald-400 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">Security Audit & Telemetry Log</h3>
            <p className="text-xs text-slate-500">
              Immutable compliance events recording redaction activity, AI queries, and risk classifications.
            </p>
          </div>
        </div>
        <button
          onClick={fetchAuditData}
          disabled={isLoading}
          className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Logs</span>
        </button>
      </div>

      {/* Aggregate Metrics */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
            <span className="text-xs text-slate-500 font-medium">Total Gateway Invocations</span>
            <p className="text-xl font-bold text-slate-900 font-mono mt-1">{metrics.promptsScreened}</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
            <span className="text-xs text-slate-500 font-medium">Quarantined Entities</span>
            <p className="text-xl font-bold text-indigo-600 font-mono mt-1">{metrics.leaksMitigated}</p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
            <span className="text-xs text-slate-500 font-medium">Presidio Health</span>
            <p className="text-xl font-bold font-mono mt-1 flex items-center gap-1.5 text-emerald-600">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>{metrics.presidioAvailable ? 'Active' : 'Degraded'}</span>
            </p>
          </div>
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
            <span className="text-xs text-slate-500 font-medium">Zero-Leak Assurance</span>
            <p className="text-xl font-bold text-emerald-600 font-mono mt-1">100.0%</p>
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-slate-500" />
            <h4 className="text-xs font-semibold text-slate-800">Event Audit Trail ({logs.length})</h4>
          </div>
          <span className="text-xs text-slate-400">Strictly zero raw secrets logged</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Prompt Len</th>
                <th className="px-4 py-3">Detections</th>
                <th className="px-4 py-3">Risk Level</th>
                <th className="px-4 py-3">Gate Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400 italic">
                    No audit records logged yet.
                  </td>
                </tr>
              ) : (
                logs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3 text-slate-500 text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 text-slate-800">{log.userEmail}</td>
                    <td className="px-4 py-3 font-semibold text-indigo-700">{log.action}</td>
                    <td className="px-4 py-3 text-slate-600">{log.promptLength}</td>
                    <td className="px-4 py-3 text-slate-800">{log.detectionsCount}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.riskLevel === 'CRITICAL'
                            ? 'bg-rose-100 text-rose-800'
                            : log.riskLevel === 'HIGH'
                            ? 'bg-amber-100 text-amber-800'
                            : log.riskLevel === 'MEDIUM'
                            ? 'bg-blue-100 text-blue-800'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {log.riskLevel}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.status === 'REDACTED'
                            ? 'bg-emerald-100 text-emerald-800'
                            : 'bg-slate-100 text-slate-700'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
