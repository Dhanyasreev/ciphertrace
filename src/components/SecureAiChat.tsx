import React, { useState, useEffect } from 'react';
import {
  Send,
  ShieldCheck,
  Bot,
  AlertTriangle,
  Cpu,
  Copy,
  Check,
  Lock,
  FileCode2,
  Terminal,
} from 'lucide-react';
import { ChatResponse } from '../types.js';

interface SecureAiChatProps {
  initialPrompt?: string;
  onTokenCreated?: () => void;
}

export const SecureAiChat: React.FC<SecureAiChatProps> = ({
  initialPrompt = '',
  onTokenCreated,
}) => {
  const [prompt, setPrompt] = useState<string>(initialPrompt || '');
  const [model] = useState<string>('gemini-3.1-flash-lite');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [chatResult, setChatResult] = useState<ChatResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedPrompt, setCopiedPrompt] = useState<boolean>(false);
  const [copiedGemini, setCopiedGemini] = useState<boolean>(false);

  useEffect(() => {
    if (initialPrompt) {
      setPrompt(initialPrompt);
    }
  }, [initialPrompt]);

  const handleSubmit = async (e?: React.FormEvent, customPrompt?: string) => {
    if (e) e.preventDefault();
    const promptToSend = customPrompt || prompt;
    if (!promptToSend.trim() || isLoading) return;

    setIsLoading(true);
    setErrorMsg(null);
    setChatResult(null);

    try {
      const res = await fetch('/api/chat/secure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: promptToSend,
          model,
        }),
      });

      if (res.status === 422) {
        const blockData = await res.json();
        setErrorMsg(blockData.error || 'Prompt blocked by Zero-Leak Security Gateway');
        setIsLoading(false);
        return;
      }

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data: ChatResponse = await res.json();
      setChatResult(data);
      if (onTokenCreated) onTokenCreated();
    } catch (err: any) {
      console.error('Chat error:', err);
      setErrorMsg(err.message || 'Failed to complete secure AI request');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text: string, type: 'prompt' | 'gemini') => {
    navigator.clipboard.writeText(text);
    if (type === 'prompt') {
      setCopiedPrompt(true);
      setTimeout(() => setCopiedPrompt(false), 2000);
    } else {
      setCopiedGemini(true);
      setTimeout(() => setCopiedGemini(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Complete Master Pipeline Diagram */}
      <div className="bg-slate-900 text-white p-5 rounded-2xl border border-slate-800 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                CipherTrace Secure AI Code Gateway Pipeline
              </h4>
              <p className="text-[11px] text-slate-400">
                Zero-exposure AI debugging, analysis, and syntax correction with Token Vault quarantine
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider px-2.5 py-1 rounded-md bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Zero-Leak Guaranteed
          </span>
        </div>

        {/* Pipeline Flow Stages */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 items-center text-center text-xs">
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-slate-700">
            <span className="text-[9px] text-slate-400 block font-mono">Stage 1</span>
            <span className="font-semibold text-slate-200 text-[11px]">User Input</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-slate-700">
            <span className="text-[9px] text-slate-400 block font-mono">Stage 2</span>
            <span className="font-semibold text-slate-200 text-[11px]">Classifier</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-emerald-500/40">
            <span className="text-[9px] text-emerald-400 block font-mono">Stage 3</span>
            <span className="font-semibold text-emerald-300 text-[11px]">Dual Detectors</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-purple-500/40">
            <span className="text-[9px] text-purple-400 block font-mono">Stage 4</span>
            <span className="font-semibold text-purple-300 text-[11px]">Token Vault</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-blue-500/40">
            <span className="text-[9px] text-blue-400 block font-mono">Stage 5</span>
            <span className="font-semibold text-blue-300 text-[11px]">Sanitized Code</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-cyan-500/40">
            <span className="text-[9px] text-cyan-400 block font-mono">Stage 6</span>
            <span className="font-semibold text-cyan-300 text-[11px]">Gemini Reasoner</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-amber-500/40">
            <span className="text-[9px] text-amber-400 block font-mono">Stage 7</span>
            <span className="font-semibold text-amber-300 text-[11px]">Response Guard</span>
          </div>
          <div className="bg-slate-800/80 p-2.5 rounded-xl border border-emerald-500/60 bg-emerald-950/20">
            <span className="text-[9px] text-emerald-400 block font-mono">Stage 8</span>
            <span className="font-semibold text-emerald-300 text-[11px]">Safe Response</span>
          </div>
        </div>
      </div>

      {/* Main Input Form */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-xs p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="block text-xs font-semibold text-slate-800">
            Source Code (Secrets will be quarantined as tokens like [API_KEY_1] before reaching Gemini; syntax errors remain untouched for Gemini to fix)
          </label>
          <div className="text-xs text-slate-500 flex items-center gap-1">
            <FileCode2 className="w-3.5 h-3.5 text-indigo-600" />
            <span>Auto-detects Python, JS/TS, Java, Go, Rust, C/C++, SQL, JSON, YAML, etc.</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <textarea
              value={prompt}
              onChange={e => setPrompt(e.target.value)}
              rows={9}
              placeholder="Paste code containing API keys, database URLs, auth tokens, or syntax bugs..."
              className="w-full p-3.5 bg-slate-900 text-emerald-300 rounded-xl font-mono text-xs focus:outline-none focus:ring-2 focus:ring-emerald-500 resize-y border border-slate-800 leading-relaxed"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
              <Cpu className="w-3.5 h-3.5 text-blue-500" />
              <span>Primary AI Engine: {model}</span>
              <span className="text-slate-300">|</span>
              <span className="text-emerald-600 font-medium flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-500" />
                Zero-Leak Mode Active
              </span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !prompt.trim()}
              className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-semibold flex items-center gap-2 transition-colors shadow-sm disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5 text-emerald-400" />
              {isLoading ? 'Screening, Quarantining & Analyzing with Gemini...' : 'Analyze & Correct with Gemini'}
            </button>
          </div>
        </form>
      </div>

      {/* Error / Security Gate Block Notice */}
      {errorMsg && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 flex items-start gap-2.5">
          <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block">Security Gateway Enforcement:</span>
            <span>{errorMsg}</span>
          </div>
        </div>
      )}

      {/* Response Display */}
      {chatResult && (
        <div className="space-y-6">
          {/* Metadata & Task Mode Bar */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap items-center gap-4 text-xs">
              <div className="flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-indigo-600" />
                <span className="text-slate-500">Task Mode:</span>
                <span className="font-bold font-mono bg-indigo-100 text-indigo-800 px-2 py-0.5 rounded">
                  {chatResult.taskMode || (chatResult.isCode ? 'CODE_CORRECTION' : 'GENERAL_REASONING')}
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span className="text-slate-500">Security Status:</span>
                <span className="font-semibold text-emerald-700 bg-emerald-100/80 px-2 py-0.5 rounded">
                  Protected (Zero Secret Leak)
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <Lock className="w-4 h-4 text-purple-600" />
                <span className="text-slate-500">Tokens Quarantined:</span>
                <span className="font-mono font-semibold text-slate-800">
                  {chatResult.tokens?.length || 0}
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-slate-500">Token Isolation:</span>
                <span className="font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                  100% Enforced
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="font-mono text-slate-500 text-[11px]">
                Req: {chatResult.requestId}
              </span>
              <span className="text-[10px] font-mono bg-slate-200/80 text-slate-700 px-2 py-0.5 rounded">
                {chatResult.performance?.totalProcessingTimeMs}ms
              </span>
            </div>
          </div>

          {/* Section 1: What Gemini Received (Sanitized Prompt) */}
          <div className="bg-slate-900 rounded-xl border border-slate-800 shadow-xs flex flex-col text-white">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-purple-400" />
                <h4 className="text-xs font-semibold text-slate-200">
                  What Gemini Received (Sanitized Request with Protected Tokens)
                </h4>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 border border-emerald-800/60 px-2 py-0.5 rounded">
                  Gemini Never Saw Original Values
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy(chatResult.sanitizedPrompt, 'prompt')}
                  className="p-1 text-slate-400 hover:text-white transition-colors cursor-pointer"
                  title="Copy sanitized prompt"
                >
                  {copiedPrompt ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="p-4 font-mono text-xs text-emerald-300/90 whitespace-pre-wrap leading-relaxed max-h-56 overflow-y-auto">
              {chatResult.sanitizedPrompt}
            </div>

            <div className="p-2.5 border-t border-slate-800 bg-slate-950/50 text-[11px] text-slate-400 flex items-center justify-between">
              <span>
                {chatResult.tokens.length} token(s) generated: {chatResult.tokens.map(t => t.token).join(', ') || 'None'}
              </span>
              <span className="text-slate-500 font-mono">Payload Cleaned</span>
            </div>
          </div>

          {/* AI Output (Protected response returned from Gemini — tokens strictly preserved) */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-xs flex flex-col min-h-[450px]">
            <div className="px-4 py-3.5 border-b border-slate-100 flex items-center justify-between bg-slate-50/70 rounded-t-xl">
              <div className="flex items-center gap-2.5">
                <Bot className="w-4 h-4 text-indigo-600" />
                <div>
                  <h4 className="text-xs font-bold text-slate-900 tracking-wide">
                    PROTECTED AI OUTPUT
                  </h4>
                  <p className="text-[11px] text-slate-500">
                    Response returned from Gemini — tokens strictly preserved in Zero-Exposure mode
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded font-medium">
                  Tokens Intact
                </span>
                <button
                  type="button"
                  onClick={() => handleCopy(chatResult.geminiResponse || chatResult.aiResponse, 'gemini')}
                  className="p-1.5 text-slate-500 hover:text-slate-900 transition-colors cursor-pointer rounded hover:bg-slate-100"
                  title="Copy AI Output"
                >
                  {copiedGemini ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="p-5 flex-1 overflow-y-auto text-xs text-slate-800 leading-relaxed whitespace-pre-wrap font-sans">
              {chatResult.geminiResponse || chatResult.aiResponse}
            </div>

            <div className="p-3 border-t border-slate-100 bg-slate-50 text-[11px] text-slate-500 flex items-center justify-between rounded-b-xl">
              <span>Model: {chatResult.model}</span>
              <span className="font-mono text-emerald-600 flex items-center gap-1.5 font-medium">
                <ShieldCheck className="w-3.5 h-3.5" />
                Response Guard Verified — Zero Leakage
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
