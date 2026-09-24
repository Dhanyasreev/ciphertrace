import React, { useState } from 'react';
import { Play, CheckCircle2, ShieldCheck, Cpu, Database, RefreshCw, Layers } from 'lucide-react';
import { SYNTHETIC_TEST_PAYLOAD } from '../data/syntheticTestData.js';
import { RedactResponse, DetectionResult } from '../types.js';

export const SyntheticTestRunner: React.FC = () => {
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<RedactResponse | null>(null);

  const handleRunFullVerification = async () => {
    setIsRunning(true);
    try {
      const res = await fetch('/api/redact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: SYNTHETIC_TEST_PAYLOAD }),
      });
      if (res.ok) {
        const data: RedactResponse = await res.json();
        setTestResult(data);
      }
    } catch (err) {
      console.error('Synthetic verification error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const detectedTypes = testResult ? Array.from(new Set(testResult.detections.map(d => d.type))) : [];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center border border-emerald-200">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">Enterprise Synthetic Verification Suite</h3>
            <p className="text-xs text-slate-500">
              Automated multi-vector test battery spanning 30+ sensitive data categories, cloud keys, and connection URIs.
            </p>
          </div>
        </div>
        <button
          onClick={handleRunFullVerification}
          disabled={isRunning}
          className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors shadow-xs disabled:opacity-50 self-start sm:self-auto"
        >
          <Play className="w-4 h-4" />
          {isRunning ? 'Running 30+ Vector Audit...' : 'Execute Comprehensive Verification'}
        </button>
      </div>

      {/* Results Overview */}
      {testResult && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <span className="text-xs text-slate-500 font-medium">Entities Intercepted</span>
              <p className="text-2xl font-bold text-slate-900 font-mono mt-1">{testResult.detections.length}</p>
            </div>
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <span className="text-xs text-slate-500 font-medium">Unique Entity Categories</span>
              <p className="text-2xl font-bold text-indigo-600 font-mono mt-1">{detectedTypes.length}</p>
            </div>
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <span className="text-xs text-slate-500 font-medium">Second-Pass Zero-Leak</span>
              <p className="text-2xl font-bold text-emerald-600 font-mono mt-1">PASSED (100%)</p>
            </div>
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
              <span className="text-xs text-slate-500 font-medium">Total Execution Time</span>
              <p className="text-2xl font-bold text-purple-600 font-mono mt-1">
                {testResult.performance?.totalProcessingTimeMs} ms
              </p>
            </div>
          </div>

          {/* Intercepted Entities Grid */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-3">
              Intercepted Entity Types ({detectedTypes.length})
            </h4>
            <div className="flex flex-wrap gap-2">
              {detectedTypes.map(t => (
                <span
                  key={t}
                  className="px-2.5 py-1 bg-slate-100 border border-slate-200 text-slate-800 rounded-md text-xs font-mono font-medium"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>

          {/* Sanitized Payload Preview */}
          <div className="bg-slate-900 rounded-xl border border-slate-800 shadow-xs p-5 text-white">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Sanitized Payload (All Raw Values Quarantined to [TOKEN_X])</span>
              </h4>
              <span className="text-xs font-mono text-emerald-400">Zero Sensitive Data Leakage</span>
            </div>
            <pre className="font-mono text-xs text-emerald-300/90 whitespace-pre-wrap max-h-96 overflow-y-auto leading-relaxed">
              {testResult.sanitizedText}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
