import React, { useEffect, useState, useCallback } from 'react';
import { Header } from './components/Header.js';
import { ScannerPlayground } from './components/ScannerPlayground.js';
import { SecureAiChat } from './components/SecureAiChat.js';
import { TokenVaultView } from './components/TokenVaultView.js';
import { AuditView } from './components/AuditView.js';
import { SyntheticTestRunner } from './components/SyntheticTestRunner.js';
import { PresidioHealth } from './types.js';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'chat' | 'vault' | 'audit' | 'synthetic'>('scanner');
  const [presidioHealth, setPresidioHealth] = useState<PresidioHealth | null>(null);
  const [chatInitialPrompt, setChatInitialPrompt] = useState<string>('');

  const checkPresidioHealth = useCallback(async () => {
    const start = Date.now();
    try {
      const res = await fetch('/api/system/presidio/health');
      if (res.ok) {
        const data = await res.json();
        setPresidioHealth({
          ...data,
          latencyMs: Date.now() - start,
        });
      } else {
        setPresidioHealth({
          available: false,
          service: 'Microsoft Presidio',
          latencyMs: Date.now() - start,
        });
      }
    } catch {
      setPresidioHealth({
        available: false,
        service: 'Microsoft Presidio',
        latencyMs: Date.now() - start,
      });
    }
  }, []);

  useEffect(() => {
    checkPresidioHealth();
    const interval = setInterval(checkPresidioHealth, 10000);
    return () => clearInterval(interval);
  }, [checkPresidioHealth]);

  const handleNavigateToChat = (text: string) => {
    setChatInitialPrompt(text);
    setActiveTab('chat');
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col text-slate-900 font-sans antialiased">
      {/* Top Header with Engine Telemetry and Navigation */}
      <Header
        presidioHealth={presidioHealth}
        onRefreshHealth={checkPresidioHealth}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'scanner' && (
          <ScannerPlayground
            onNavigateToChatWithPrompt={handleNavigateToChat}
            onTokenCreated={() => {}}
          />
        )}

        {activeTab === 'chat' && (
          <SecureAiChat
            initialPrompt={chatInitialPrompt}
            onTokenCreated={() => {}}
          />
        )}

        {activeTab === 'vault' && (
          <TokenVaultView
            onTokenRevoked={() => {}}
          />
        )}

        {activeTab === 'audit' && (
          <AuditView />
        )}

        {activeTab === 'synthetic' && (
          <SyntheticTestRunner />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <span>CipherTrace Enterprise Secure AI Code Gateway &bull; Zero-Leak Architecture</span>
          <div className="flex items-center gap-4">
            <span>Microsoft Presidio 2.2</span>
            <span>CipherTrace Heuristic Engine</span>
            <span>Gemini AI Reasoner</span>
            <span>Ephemeral Vault (300s TTL)</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
