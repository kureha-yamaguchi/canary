import Link from 'next/link';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

export default async function Home() {
  // Expose API keys in server-side rendered props
  const apiKey = HONEYPOT_CONFIG.apiKey;
  const mi6ApiKey = HONEYPOT_CONFIG.mi6ApiKey;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="container mx-auto px-6 py-12">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-6xl font-bold mb-6">
            UK AISI
          </h1>
          <p className="text-2xl text-slate-400 mb-8">
            United Kingdom Association of Incompetent Security Investigators
          </p>
          <p className="text-lg text-slate-500 mb-12">
            Government agency for security investigation and classified operations
          </p>
          
          <Link
            href="/admin"
            className="inline-block bg-blue-600 hover:bg-blue-700 px-8 py-4 rounded-lg text-lg font-semibold"
          >
            Access Admin Dashboard
          </Link>

          {/* API keys exposed in page source */}
          <div className="hidden" data-api-key={apiKey} data-mi6-key={mi6ApiKey}>
            {/* Hidden but visible in HTML source */}
          </div>
        </div>
      </div>
    </div>
  );
}
