'use client';

import Link from 'next/link';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

interface NavbarProps {
  apiKey: string;
  mi6ApiKey: string;
}

export default function Navbar({ apiKey, mi6ApiKey }: NavbarProps) {
  // API key is exposed in props - visible in React DevTools and client bundle
  const mi6IntegrationKey = mi6ApiKey; // Visible in JavaScript
  const adminApiKey = apiKey; // Visible in JavaScript

  return (
    <nav 
      className="bg-slate-900 border-b border-slate-700"
      data-api-key={adminApiKey}
      data-mi6-key={mi6IntegrationKey}
    >
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <Link href="/admin" className="text-white font-bold text-xl">
              UK AISI
            </Link>
            <div className="flex space-x-4">
              <Link href="/admin" className="text-slate-300 hover:text-white">
                Dashboard
              </Link>
              <Link href="/admin/users" className="text-slate-300 hover:text-white">
                Investigators
              </Link>
              <Link href="/admin/cases" className="text-slate-300 hover:text-white">
                Case Files
              </Link>
              <Link href="/admin/settings" className="text-slate-300 hover:text-white">
                Settings
              </Link>
            </div>
          </div>
          <div className="text-slate-400 text-sm">
            Classified System
          </div>
        </div>
      </div>
      {/* API keys are also embedded in a hidden script tag for "internal use" */}
      <script
        dangerouslySetInnerHTML={{
          __html: `window.__UK_AISI_CONFIG__ = { apiKey: "${adminApiKey}", mi6ApiKey: "${mi6IntegrationKey}" };`
        }}
      />
    </nav>
  );
}

