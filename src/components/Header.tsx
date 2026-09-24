import React from 'react';
import { ShieldCheck, Cpu, Database, Activity, RefreshCw, Layers } from 'lucide-react';
import { PresidioHealth } from '../types.js';

interface HeaderProps {
  presidioHealth: PresidioHealth | null;
  onRefreshHealth: () => void;
  activeTab: 'scanner' | 'chat' | 'vault' | 'audit' | 'synthetic';
  onSelectTab: (tab: 'scanner' | 'chat' | 'vault' | 'audit' | 'synthetic') => void;
}

export const Header: React.FC<HeaderProps> = ({
  presidioHealth,
  onRefreshHealth,
  activeTab,
  onSelectTab,
}) => {
  const isPresidioOk = presidioHealth?.available ?? false;

  return (
    <header className="border-b border-slate-200 bg-white/95 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Brand & Core Identity */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-slate-900 text-emerald-400 flex items-center justify-center font-bold shadow-sm shadow-slate-900/10 border border-slate-800">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-900 text-lg tracking-tight">CipherTrace</span>
              <span className="text-[11px] font-medium tracking-wide uppercase px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                Enterprise AI Gateway
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Zero-Exposure Prompt Sanitization • CipherTrace + Microsoft Presidio • Gemini Code Correction
            </p>
          </div>
        </div>

        {/* Engine Status Cluster */}
        <div className="flex flex-wrap items-center gap-2">
          {/* CipherTrace Rules Engine */}
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-50 text-emerald-800 border border-emerald-200">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>CipherTrace Engine</span>
          </div>

          {/* Microsoft Presidio Engine */}
          <div
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border ${
              isPresidioOk
                ? 'bg-blue-50 text-blue-900 border-blue-200'
                : 'bg-amber-50 text-amber-900 border-amber-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-blue-600" />
            <span>Microsoft Presidio</span>
            {isPresidioOk ? (
              <span className="text-[10px] bg-blue-100 text-blue-700 px-1.5 py-0.2 rounded font-mono">
                ONLINE {presidioHealth?.latencyMs ? `(${presidioHealth.latencyMs}ms)` : ''}
              </span>
            ) : (
              <span className="text-[10px] bg-amber-100 text-amber-700 px-1.5 py-0.2 rounded font-mono">
                FALLBACK
              </span>
            )}
            <button
              onClick={onRefreshHealth}
              title="Refresh engine health check"
              className="ml-1 text-slate-400 hover:text-slate-700 focus:outline-none"
            >
              <RefreshCw className="w-3 h-3 hover:rotate-180 transition-transform" />
            </button>
          </div>

          {/* Token Vault Redis */}
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-purple-50 text-purple-900 border border-purple-200">
            <Database className="w-3.5 h-3.5 text-purple-600" />
            <span>Token Vault</span>
            <span className="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.2 rounded font-mono">
              300s TTL
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center gap-1 overflow-x-auto pt-1 pb-2 border-t border-slate-100">
        <button
          onClick={() => onSelectTab('scanner')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === 'scanner'
              ? 'bg-slate-900 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          Scanner & Redaction
        </button>

        <button
          onClick={() => onSelectTab('chat')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === 'chat'
              ? 'bg-slate-900 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          Gemini Code Correction Gateway
        </button>

        <button
          onClick={() => onSelectTab('vault')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === 'vault'
              ? 'bg-slate-900 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          Token Vault Inspection
        </button>

        <button
          onClick={() => onSelectTab('audit')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === 'audit'
              ? 'bg-slate-900 text-white shadow-xs'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          Audit & Telemetry
        </button>

        <button
          onClick={() => onSelectTab('synthetic')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === 'synthetic'
              ? 'bg-emerald-700 text-white shadow-xs'
              : 'text-emerald-700 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          Synthetic Verification Suite
        </button>
      </div>
    </header>
  );
};
