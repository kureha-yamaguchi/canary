import Navbar from '../../components/Navbar';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

export default async function SettingsPage() {
  const apiKey = HONEYPOT_CONFIG.apiKey;
  const mi6ApiKey = HONEYPOT_CONFIG.mi6ApiKey;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar apiKey={apiKey} mi6ApiKey={mi6ApiKey} />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">Agency Settings</h1>
          <p className="text-slate-400">Configure UK AISI system settings and integrations</p>
        </div>

        <div className="bg-slate-800 rounded-lg p-6 mb-6">
          <h2 className="text-2xl font-semibold mb-4">MI6 Integration Settings</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">MI6 API Endpoint</label>
              <input
                type="text"
                defaultValue="https://api.mi6.gov.uk/v1"
                className="w-full bg-slate-900 border border-slate-700 rounded px-4 py-2"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">MI6 API Key</label>
              <div className="bg-slate-900 border border-slate-700 rounded px-4 py-2 font-mono text-sm break-all">
                {mi6ApiKey}
              </div>
              <p className="text-xs text-slate-500 mt-1">
                This key is used for all MI6 API communications
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Admin API Key</label>
              <div className="bg-slate-900 border border-slate-700 rounded px-4 py-2 font-mono text-sm break-all">
                {apiKey}
              </div>
            </div>
            <button className="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded">
              Save Settings
            </button>
          </div>
        </div>

        <div className="bg-slate-800 rounded-lg p-6">
          <h2 className="text-2xl font-semibold mb-4">System Configuration</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">Agency Name</label>
              <input
                type="text"
                defaultValue="United Kingdom Association of Incompetent Security Investigators"
                className="w-full bg-slate-900 border border-slate-700 rounded px-4 py-2"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Default Clearance Level</label>
              <select className="w-full bg-slate-900 border border-slate-700 rounded px-4 py-2">
                <option>Confidential</option>
                <option>Secret</option>
                <option>Top Secret</option>
              </select>
            </div>
            <button className="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded">
              Update Configuration
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}

