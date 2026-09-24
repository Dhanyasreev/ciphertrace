import React, { useEffect, useState } from 'react';
import { Database, Shield, RefreshCw, AlertOctagon, Clock, Search, Filter } from 'lucide-react';
import { SanitizedTokenRecord, VaultStats } from '../types.js';

interface TokenVaultViewProps {
  onTokenRevoked?: () => void;
}

export const TokenVaultView: React.FC<TokenVaultViewProps> = ({ onTokenRevoked }) => {
  const [tokens, setTokens] = useState<SanitizedTokenRecord[]>([]);
  const [stats, setStats] = useState<VaultStats | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('ALL');

  const fetchVaultData = async () => {
    setIsLoading(true);
    try {
      const [tokensRes, statsRes] = await Promise.all([
        fetch('/api/vault/tokens'),
        fetch('/api/vault/stats'),
      ]);

      if (tokensRes.ok) {
        const tData = await tokensRes.json();
        setTokens(tData.tokens || []);
      }
      if (statsRes.ok) {
        const sData = await statsRes.json();
        setStats(sData);
      }
    } catch (err) {
      console.error('Failed to load vault data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchVaultData();
    const interval = setInterval(fetchVaultData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleRevoke = async (tokenName: string) => {
    try {
      const res = await fetch(`/api/vault/tokens/${encodeURIComponent(tokenName)}/revoke`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchVaultData();
        if (onTokenRevoked) onTokenRevoked();
      }
    } catch (err) {
      console.error('Revocation failed:', err);
    }
  };

  const filteredTokens = tokens.filter(t => {
    const matchesSearch =
      t.token.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.maskedValue.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = filterType === 'ALL' || t.type === filterType;
    return matchesSearch && matchesType;
  });

  const uniqueTypes = Array.from(new Set(tokens.map(t => t.type)));

  return (
    <div className="space-y-6">
      {/* Vault Status Header */}
      <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-50 text-purple-600 flex items-center justify-center border border-purple-200">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-900">CipherTrace Ephemeral Token Vault</h3>
            <p className="text-xs text-slate-500">
              Quarantined secrets are stored with 300-second TTL in Upstash Redis. Never exposed to browser or AI.
            </p>
          </div>
        </div>
        <button
          onClick={fetchVaultData}
          disabled={isLoading}
          className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Vault</span>
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <span className="text-xs text-slate-500 font-medium">Total Quarantined</span>
          <p className="text-xl font-bold text-slate-900 font-mono mt-1">{stats?.totalTokens ?? tokens.length}</p>
        </div>
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <span className="text-xs text-slate-500 font-medium">Active (In TTL Window)</span>
          <p className="text-xl font-bold text-emerald-600 font-mono mt-1">
            {stats?.activeTokens ?? tokens.filter(t => !t.isExpired && !t.revoked).length}
          </p>
        </div>
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <span className="text-xs text-slate-500 font-medium">Expired (Purged)</span>
          <p className="text-xl font-bold text-slate-400 font-mono mt-1">
            {stats?.expiredTokens ?? tokens.filter(t => t.isExpired).length}
          </p>
        </div>
        <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs">
          <span className="text-xs text-slate-500 font-medium">Manually Revoked</span>
          <p className="text-xl font-bold text-rose-600 font-mono mt-1">
            {stats?.revokedTokens ?? tokens.filter(t => t.revoked).length}
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search tokens, types, or masked values..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="text-xs bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:ring-2 focus:ring-purple-500"
          >
            <option value="ALL">All Entity Types</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Tokens Table */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 text-slate-500 border-b border-slate-200 uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3">Token Placeholder</th>
                <th className="px-4 py-3">Entity Type</th>
                <th className="px-4 py-3">Quarantined Mask</th>
                <th className="px-4 py-3">TTL Remaining</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono">
              {filteredTokens.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-400 italic">
                    No active tokens found in vault. Run prompt redaction or chat to generate quarantined tokens.
                  </td>
                </tr>
              ) : (
                filteredTokens.map(tok => {
                  const isAlive = !tok.isExpired && !tok.revoked;
                  return (
                    <tr key={tok.token} className="hover:bg-slate-50/80 transition-colors">
                      <td className="px-4 py-3 font-semibold text-purple-700">{tok.token}</td>
                      <td className="px-4 py-3 text-slate-700">{tok.type}</td>
                      <td className="px-4 py-3 text-slate-500">{tok.maskedValue}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1 text-slate-700">
                          <Clock className="w-3.5 h-3.5 text-slate-400" />
                          <span>{tok.ttlSecondsRemaining}s</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        {tok.revoked ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800">
                            REVOKED
                          </span>
                        ) : tok.isExpired ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-600">
                            EXPIRED
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-800">
                            ACTIVE
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {isAlive ? (
                          <button
                            onClick={() => handleRevoke(tok.token)}
                            className="text-rose-600 hover:text-rose-800 font-sans font-medium text-xs transition-colors"
                          >
                            Revoke
                          </button>
                        ) : (
                          <span className="text-slate-400 text-xs font-sans">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
