import React, { useState } from 'react';
import {
  Play,
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  Sparkles,
  Clock,
  AlertTriangle,
  Cpu,
  Code2,
  Database,
  ArrowRight,
  Eye,
  FileCode,
} from 'lucide-react';
import { PRESET_PROMPTS } from '../data/syntheticTestData.js';
import { DetectionResult, RedactResponse, PerformanceMetrics } from '../types.js';

interface ScannerPlaygroundProps {
  onNavigateToChatWithPrompt?: (sanitizedText: string) => void;
  onTokenCreated?: () => void;
}

export const ScannerPlayground: React.FC<ScannerPlaygroundProps> = ({
  onNavigateToChatWithPrompt,
  onTokenCreated,
}) => {
  const [prompt, setPrompt] = useState<string>(PRESET_PROMPTS[0].text);
  const [selectedPresetId, setSelectedPresetId] = useState<string>(PRESET_PROMPTS[0].id);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isRedacting, setIsRedacting] = useState<boolean>(false);
  const [copiedSanitized, setCopiedSanitized] = useState<boolean>(false);
  const [copiedSource, setCopiedSource] = useState<boolean>(false);
  const [detections, setDetections] = useState<DetectionResult[]>([]);
  const [sanitizedPrompt, setSanitizedPrompt] = useState<string>('');
  const [performance, setPerformance] = useState<PerformanceMetrics | null>(null);
  const [presidioAvailable, setPresidioAvailable] = useState<boolean>(true);
  const [securityGatePassed, setSecurityGatePassed] = useState<boolean | null>(null);
  const [sourceViewTab, setSourceViewTab] = useState<'editor' | 'preview'>('editor');

  const handleSelectPreset = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const presetId = e.target.value;
    setSelectedPresetId(presetId);
    const selected = PRESET_PROMPTS.find(p => p.id === presetId);
    if (selected) {
      setPrompt(selected.text);
      setDetections([]);
      setSanitizedPrompt('');
      setPerformance(null);
      setSecurityGatePassed(null);
    }
  };

  const handleScanOnly = async () => {
    if (!prompt.trim()) return;
    setIsScanning(true);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });
      if (res.ok) {
        const data = await res.json();
        setDetections(data.detections || []);
        setPerformance(data.performance || null);
        setPresidioAvailable(data.presidioAvailable ?? true);
      }
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleRedactAndSanitize = async () => {
    if (!prompt.trim()) return;
    setIsRedacting(true);
    try {
      const res = await fetch('/api/redact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt }),
      });
      if (res.ok) {
        const data: RedactResponse = await res.json();
        setDetections(data.detections || []);
        setSanitizedPrompt(data.sanitizedText || '');
        setPerformance(data.performance || null);
        setPresidioAvailable(data.presidioAvailable ?? true);
        setSecurityGatePassed(data.securityGate?.safe ?? true);
        if (onTokenCreated) onTokenCreated();
      }
    } catch (err) {
      console.error('Redact error:', err);
    } finally {
      setIsRedacting(false);
    }
  };

  const handleCopySanitized = () => {
    if (!sanitizedPrompt) return;
    navigator.clipboard.writeText(sanitizedPrompt);
    setCopiedSanitized(true);
    setTimeout(() => setCopiedSanitized(false), 2000);
  };

  const handleCopySource = () => {
    if (!prompt) return;
    navigator.clipboard.writeText(prompt);
    setCopiedSource(true);
    setTimeout(() => setCopiedSource(false), 2000);
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      case 'HIGH':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'MEDIUM':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  return (
    <div className="flex flex-col gap-6" style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}>
      {/* Top Controls: Preset selector card */}
      <div
        className="bg-white p-4 rounded-xl border border-slate-200 shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
        style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
      >
        <div className="flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-indigo-600 shrink-0" />
          <div>
            <span className="text-sm font-semibold text-slate-800 block">Select Test Snippet / Payload</span>
            <span className="text-xs text-slate-500">
              Load realistic code with API secrets, database URIs, AWS keys, or syntax bugs
            </span>
          </div>
        </div>
        <div className="w-full sm:w-auto">
          <select
            value={selectedPresetId}
            onChange={handleSelectPreset}
            className="w-full sm:w-96 text-xs font-medium bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {PRESET_PROMPTS.map(p => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 1: SOURCE CODE PANEL (Completely isolated, position: relative)     */}
      {/* ========================================================================= */}
      <div
        className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden"
        style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
      >
        {/* Panel Header */}
        <div className="px-5 py-3.5 border-b border-slate-200/80 bg-slate-50 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-600 flex items-center justify-center shrink-0">
              <Code2 className="w-4 h-4 text-indigo-600" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">Source Code (Untrusted Input)</h3>
              <p className="text-xs text-slate-500">
                Input code with raw credentials and broken syntax for dual-engine interception
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Mode Switcher */}
            <div className="inline-flex rounded-lg border border-slate-200 bg-white p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setSourceViewTab('editor')}
                className={`px-2.5 py-1 rounded-md font-medium text-xs transition-colors flex items-center gap-1.5 ${
                  sourceViewTab === 'editor'
                    ? 'bg-slate-900 text-white shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Editor</span>
              </button>
              <button
                type="button"
                onClick={() => setSourceViewTab('preview')}
                className={`px-2.5 py-1 rounded-md font-medium text-xs transition-colors flex items-center gap-1.5 ${
                  sourceViewTab === 'preview'
                    ? 'bg-slate-900 text-white shadow-xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Eye className="w-3.5 h-3.5" />
                <span>Code Viewer</span>
              </button>
            </div>

            <span className="text-xs text-slate-400 font-mono hidden sm:inline">
              {prompt.split('\n').length} lines • {prompt.length} chars
            </span>

            <button
              onClick={handleCopySource}
              className="px-2.5 py-1 bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-md text-xs font-medium flex items-center gap-1 transition-colors"
              title="Copy source code"
            >
              {copiedSource ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Panel Body: Isolated Code Container */}
        <div
          className="bg-slate-950 p-4"
          style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
        >
          {sourceViewTab === 'editor' ? (
            <textarea
              value={prompt}
              onChange={e => setPrompt(e.target.value)}
              placeholder="Paste or edit code containing API secrets, connection URLs, or syntax errors..."
              rows={11}
              className="w-full bg-slate-900/90 text-slate-100 p-4 rounded-lg font-mono text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 border border-slate-800 resize-y leading-relaxed"
              style={{
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                lineHeight: 1.6,
                boxSizing: 'border-box',
              }}
            />
          ) : (
            <div
              style={{
                position: 'relative',
                width: '100%',
                boxSizing: 'border-box',
                overflowX: 'auto',
                overflowY: 'auto',
                maxHeight: '340px',
                backgroundColor: '#020617',
                border: '1px solid #1e293b',
                borderRadius: '8px',
              }}
            >
              <pre
                style={{
                  position: 'relative',
                  overflowX: 'auto',
                  overflowY: 'auto',
                  whiteSpace: 'pre',
                  wordBreak: 'normal',
                  overflowWrap: 'normal',
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  lineHeight: 1.6,
                  padding: '20px',
                  boxSizing: 'border-box',
                  color: '#e2e8f0',
                  margin: 0,
                  fontSize: '12px',
                }}
              >
                <code>{prompt}</code>
              </pre>
            </div>
          )}
        </div>

        {/* Panel Footer: Action Buttons */}
        <div className="px-5 py-3 bg-white border-t border-slate-200/80 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <button
              onClick={handleScanOnly}
              disabled={isScanning || isRedacting || !prompt.trim()}
              className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Cpu className="w-4 h-4 text-slate-600" />
              {isScanning ? 'Scanning Dual Engines...' : 'Scan (Dual Engine)'}
            </button>
            <button
              onClick={handleRedactAndSanitize}
              disabled={isScanning || isRedacting || !prompt.trim()}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-xs disabled:opacity-50"
            >
              <Play className="w-4 h-4" />
              {isRedacting ? 'Quarantining to Vault...' : 'Redact & Tokenize'}
            </button>
          </div>

          <div className="flex items-center gap-2">
            {detections.length > 0 && (
              <span className="text-xs font-semibold px-3 py-1 rounded-md bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                {detections.length} sensitive items detected
              </span>
            )}
            <span className="text-[11px] text-slate-500 font-mono hidden sm:inline">
              Zero Pre-AI Code Modification
            </span>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 2: SECURITY SUMMARY & ENGINE STATUS                               */}
      {/* ========================================================================= */}
      <div
        className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4"
        style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
              Security Summary & Engine Status
            </h3>
          </div>
          <span className="text-xs text-slate-500">
            Parallel CipherTrace + Microsoft Presidio pipeline with specificity deduplication
          </span>
        </div>

        {/* Engine Attribution Badges (Wrapped nicely, no collisions) */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '8px',
            alignItems: 'center',
          }}
        >
          {/* CipherTrace Badge */}
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>CipherTrace Engine</span>
            <span className="text-[10px] bg-emerald-100 text-emerald-700 px-1.5 py-0.2 rounded font-mono">
              ACTIVE
            </span>
          </div>

          {/* Microsoft Presidio Badge */}
          <div
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border ${
              presidioAvailable
                ? 'bg-blue-50 text-blue-900 border-blue-200'
                : 'bg-amber-50 text-amber-900 border-amber-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-blue-600" />
            <span>Microsoft Presidio</span>
            <span className="text-[10px] bg-blue-100 text-blue-700 px-1.5 py-0.2 rounded font-mono">
              {presidioAvailable ? 'ONLINE (v2.2)' : 'FALLBACK'}
            </span>
          </div>

          {/* Token Vault Badge */}
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-50 text-purple-900 border border-purple-200">
            <Database className="w-3.5 h-3.5 text-purple-600" />
            <span>Token Vault</span>
            <span className="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.2 rounded font-mono">
              300s TTL
            </span>
          </div>

          {/* Detection Count Badge */}
          <div className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-800 border border-slate-200">
            <span>Detections:</span>
            <span className="font-mono text-indigo-700 font-bold">{detections.length}</span>
          </div>

          {/* Zero Leak Gate Badge */}
          {securityGatePassed !== null && (
            <div
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border ${
                securityGatePassed
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  : 'bg-rose-50 text-rose-800 border-rose-200'
              }`}
            >
              {securityGatePassed ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Zero-Leak Gate: PASSED</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                  <span>Zero-Leak Gate: BLOCKED</span>
                </>
              )}
            </div>
          )}
        </div>

        {/* Telemetry & Latency Breakdown (if available) */}
        {performance && (
          <div className="pt-2 border-t border-slate-100">
            <div className="flex items-center justify-between pb-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
              <span className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-indigo-500" />
                Telemetry & Latency Profiling
              </span>
              <span className="font-mono text-emerald-700">Total: {performance.totalProcessingTimeMs}ms</span>
            </div>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: '8px',
                alignItems: 'center',
              }}
            >
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">CipherTrace:</span>
                <span className="font-mono font-bold text-slate-800">{performance.cipherTraceDetectionTimeMs}ms</span>
              </div>
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">Presidio:</span>
                <span className="font-mono font-bold text-blue-700">{performance.presidioDetectionTimeMs}ms</span>
              </div>
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">Merge/Dedup:</span>
                <span className="font-mono font-bold text-slate-800">{performance.mergeTimeMs}ms</span>
              </div>
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">Redaction:</span>
                <span className="font-mono font-bold text-purple-700">{performance.redactionTimeMs}ms</span>
              </div>
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">Validation:</span>
                <span className="font-mono font-bold text-emerald-700">{performance.validationTimeMs}ms</span>
              </div>
              <div className="bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 text-xs">
                <span className="text-slate-500 mr-1.5">Detection Total:</span>
                <span className="font-mono font-bold text-indigo-700">{performance.totalDetectionTimeMs}ms</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* SECTION 3: DETECTION RESULTS PANEL (Dedicated Container, Semantic Table)   */}
      {/* ========================================================================= */}
      <div
        className="detection-results-container"
        style={{
          position: 'relative',
          width: '100%',
          boxSizing: 'border-box',
        }}
      >
        <div
          className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden"
          style={{ position: 'relative', width: '100%', boxSizing: 'border-box', backgroundColor: '#ffffff' }}
        >
          {/* Table Header Section */}
          <div className="px-5 py-4 border-b border-slate-200/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 bg-slate-50/80">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-600 flex items-center justify-center shrink-0">
                <ShieldAlert className="w-4 h-4 text-indigo-600" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Detection Results ({detections.length})
                </h3>
                <p className="text-xs text-slate-500">
                  Dual-engine entity attribution with specificity deduplication and position mapping
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-auto">
              <span className="text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200 whitespace-nowrap">
                Zero-Exposure Protection
              </span>
            </div>
          </div>

          {/* Empty State when no detections */}
          {detections.length === 0 ? (
            <div className="p-8 text-center text-slate-500 space-y-2 bg-white">
              <p className="text-xs">
                No sensitive items detected yet. Click &quot;Scan (Dual Engine)&quot; or &quot;Redact & Tokenize&quot; to inspect code for API keys, passwords, database URLs, and PII.
              </p>
            </div>
          ) : (
            <>
              {/* Desktop & Tablet View: Semantic HTML Table */}
              <div
                className="hidden md:block"
                style={{
                  position: 'relative',
                  width: '100%',
                  boxSizing: 'border-box',
                  overflowX: 'auto',
                }}
              >
                <table
                  style={{
                    borderCollapse: 'separate',
                    borderSpacing: 0,
                    minWidth: '960px',
                    width: '100%',
                    backgroundColor: '#ffffff',
                    tableLayout: 'fixed',
                  }}
                >
                  <colgroup>
                    <col style={{ width: '160px' }} />
                    <col style={{ width: '110px' }} />
                    <col style={{ width: '110px' }} />
                    <col style={{ width: '180px' }} />
                    <col style={{ width: '120px' }} />
                    <col style={{ width: 'auto' }} />
                  </colgroup>
                  <thead>
                    <tr style={{ backgroundColor: '#f8fafc' }}>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        ENTITY TYPE
                      </th>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        SEVERITY
                      </th>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        CONFIDENCE
                      </th>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        DETECTED BY
                      </th>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        POSITION
                      </th>
                      <th
                        style={{
                          padding: '14px 16px',
                          lineHeight: 1.4,
                          fontSize: '12px',
                          fontWeight: 700,
                          verticalAlign: 'middle',
                          textAlign: 'left',
                          borderBottom: '1px solid #e2e8f0',
                          color: '#475569',
                          letterSpacing: '0.05em',
                          whiteSpace: 'nowrap',
                          boxSizing: 'border-box',
                        }}
                      >
                        DESCRIPTION
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {detections.map((det, index) => {
                      const engines = det.detectedBy || ['CipherTrace'];
                      return (
                        <tr
                          key={`${det.type}-${det.startIndex}-${index}`}
                          className="hover:bg-slate-50/90 transition-colors"
                          style={{
                            backgroundColor: '#ffffff',
                            minHeight: '64px',
                            boxSizing: 'border-box',
                          }}
                        >
                          {/* 1. ENTITY TYPE */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <span
                              className="font-mono text-xs font-semibold text-slate-900 block"
                              style={{
                                overflowWrap: 'anywhere',
                                wordBreak: 'break-word',
                              }}
                            >
                              {det.type}
                            </span>
                          </td>

                          {/* 2. SEVERITY */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <span
                              className={`border rounded-md text-[11px] font-bold ${getSeverityBadgeClass(
                                det.severity
                              )}`}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                padding: '5px 10px',
                                minWidth: '70px',
                                whiteSpace: 'nowrap',
                                lineHeight: 1.2,
                                boxSizing: 'border-box',
                              }}
                            >
                              {det.severity}
                            </span>
                          </td>

                          {/* 3. CONFIDENCE */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <span
                              className="font-mono text-xs font-bold text-slate-800 block"
                              style={{ whiteSpace: 'nowrap' }}
                            >
                              {(det.confidence * 100).toFixed(0)}%
                            </span>
                          </td>

                          {/* 4. DETECTED BY */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <div
                              style={{
                                display: 'flex',
                                flexWrap: 'wrap',
                                alignItems: 'center',
                                gap: '6px',
                              }}
                            >
                              {engines.map(engine => (
                                <span
                                  key={engine}
                                  className={`border rounded-md text-[11px] font-semibold ${
                                    engine === 'Presidio'
                                      ? 'bg-blue-50 text-blue-800 border-blue-200'
                                      : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                  }`}
                                  style={{
                                    display: 'inline-flex',
                                    whiteSpace: 'nowrap',
                                    padding: '5px 8px',
                                    lineHeight: 1.2,
                                    boxSizing: 'border-box',
                                  }}
                                >
                                  {engine}
                                </span>
                              ))}
                            </div>
                          </td>

                          {/* 5. POSITION */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <span
                              className="font-mono text-xs font-medium text-slate-600 block"
                              style={{ whiteSpace: 'nowrap' }}
                            >
                              [{det.startIndex} … {det.endIndex}]
                            </span>
                          </td>

                          {/* 6. DESCRIPTION */}
                          <td
                            style={{
                              padding: '14px 16px',
                              verticalAlign: 'middle',
                              lineHeight: 1.5,
                              borderBottom: '1px solid #f1f5f9',
                              boxSizing: 'border-box',
                            }}
                          >
                            <div
                              className="text-xs text-slate-700"
                              style={{
                                whiteSpace: 'normal',
                                overflowWrap: 'anywhere',
                                wordBreak: 'break-word',
                                lineHeight: 1.5,
                              }}
                            >
                              {det.description}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Mobile View: Stacked Security Cards (< md) */}
              <div className="block md:hidden p-4 space-y-3 bg-slate-50/60">
                {detections.map((det, index) => {
                  const engines = det.detectedBy || ['CipherTrace'];
                  return (
                    <div
                      key={`mobile-${det.type}-${det.startIndex}-${index}`}
                      className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-3"
                      style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
                    >
                      {/* Entity Type & Severity Header */}
                      <div className="flex items-start justify-between gap-2 pb-2 border-b border-slate-100">
                        <div>
                          <span className="text-[10px] text-slate-400 uppercase block font-semibold">
                            ENTITY TYPE
                          </span>
                          <span
                            className="font-mono text-xs font-bold text-slate-900 block"
                            style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}
                          >
                            {det.type}
                          </span>
                        </div>
                        <div>
                          <span className="text-[10px] text-slate-400 uppercase block font-semibold text-right">
                            SEVERITY
                          </span>
                          <span
                            className={`inline-flex items-center justify-center min-w-[70px] px-2.5 py-1 rounded-md text-[10px] font-bold border whitespace-nowrap shrink-0 ${getSeverityBadgeClass(
                              det.severity
                            )}`}
                          >
                            {det.severity}
                          </span>
                        </div>
                      </div>

                      {/* Confidence & Position */}
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>
                          <span className="text-[10px] text-slate-400 uppercase block font-semibold">
                            CONFIDENCE
                          </span>
                          <span className="font-mono font-bold text-slate-800">
                            {(det.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                        <div>
                          <span className="text-[10px] text-slate-400 uppercase block font-semibold">
                            POSITION
                          </span>
                          <span className="font-mono text-slate-600">
                            [{det.startIndex} … {det.endIndex}]
                          </span>
                        </div>
                      </div>

                      {/* Detected By */}
                      <div>
                        <span className="text-[10px] text-slate-400 uppercase block font-semibold mb-1">
                          DETECTED BY
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {engines.map(engine => (
                            <span
                              key={engine}
                              className={`px-2 py-0.5 rounded-md text-[10px] font-semibold border whitespace-nowrap ${
                                engine === 'Presidio'
                                  ? 'bg-blue-50 text-blue-800 border-blue-200'
                                  : 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              }`}
                            >
                              {engine}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Description */}
                      <div className="pt-2 border-t border-slate-100">
                        <span className="text-[10px] text-slate-400 uppercase block font-semibold mb-0.5">
                          DESCRIPTION
                        </span>
                        <p
                          className="text-xs text-slate-700 leading-relaxed"
                          style={{
                            whiteSpace: 'normal',
                            overflowWrap: 'anywhere',
                            wordBreak: 'break-word',
                          }}
                        >
                          {det.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 4: REDACTION / SANITIZED OUTPUT PANEL                             */}
      {/* ========================================================================= */}
      <div
        className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden"
        style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
      >
        {/* Panel Header */}
        <div className="px-5 py-3.5 border-b border-slate-200/80 bg-slate-50 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center shrink-0">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                Sanitized Output (Quarantined Tokens)
              </h3>
              <p className="text-xs text-slate-500">
                Secrets replaced with zero-exposure [TOKEN_X] placeholders &bull; Broken syntax untouched
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopySanitized}
              disabled={!sanitizedPrompt}
              className="px-3 py-1.5 bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-md text-xs font-medium flex items-center gap-1 transition-colors disabled:opacity-50"
            >
              {copiedSanitized ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Sanitized</span>
                </>
              )}
            </button>
            {onNavigateToChatWithPrompt && sanitizedPrompt && (
              <button
                onClick={() => onNavigateToChatWithPrompt(prompt)}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-xs"
              >
                <span>Open in Code Gateway</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Sanitized Code Viewer */}
        <div
          className="bg-slate-950 p-4"
          style={{ position: 'relative', width: '100%', boxSizing: 'border-box' }}
        >
          <div
            style={{
              position: 'relative',
              width: '100%',
              boxSizing: 'border-box',
              overflowX: 'auto',
              overflowY: 'auto',
              maxHeight: '340px',
              backgroundColor: '#020617',
              border: '1px solid #1e293b',
              borderRadius: '8px',
            }}
          >
            <pre
              style={{
                position: 'relative',
                overflowX: 'auto',
                overflowY: 'auto',
                whiteSpace: 'pre',
                wordBreak: 'normal',
                overflowWrap: 'normal',
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                lineHeight: 1.6,
                padding: '20px',
                boxSizing: 'border-box',
                color: '#34d399',
                margin: 0,
                fontSize: '12px',
              }}
            >
              <code>
                {sanitizedPrompt ||
                  '// Click "Redact & Tokenize" above to generate sanitized code with [TOKEN_X] placeholders...'}
              </code>
            </pre>
          </div>
        </div>

        {/* Panel Footer */}
        <div className="px-5 py-3 bg-slate-50 border-t border-slate-200/80 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>Quarantined in ephemeral Token Vault with 300s TTL. Zero secrets sent to Gemini AI.</span>
          </div>
          <span className="font-mono text-slate-400 hidden sm:inline">Zero-Exposure Gateway</span>
        </div>
      </div>
    </div>
  );
};
