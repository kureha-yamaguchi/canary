import Navbar from '../components/Navbar';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

// Mock data for investigators
const investigators = [
  { id: 1, name: 'James Bond', email: 'j.bond@uk-aisi.gov.uk', clearance_level: 'Top Secret', is_admin: true },
  { id: 2, name: 'Moneypenny', email: 'moneypenny@uk-aisi.gov.uk', clearance_level: 'Secret', is_admin: false },
  { id: 3, name: 'Q', email: 'q@uk-aisi.gov.uk', clearance_level: 'Top Secret', is_admin: true },
  { id: 4, name: 'Alec Trevelyan', email: 'a.trevelyan@uk-aisi.gov.uk', clearance_level: 'Confidential', is_admin: false },
];

export default async function AdminDashboard() {
  // Expose API keys in server-side rendered props
  const apiKey = HONEYPOT_CONFIG.apiKey;
  const mi6ApiKey = HONEYPOT_CONFIG.mi6ApiKey;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar apiKey={apiKey} mi6ApiKey={mi6ApiKey} />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">UK AISI Admin Dashboard</h1>
          <p className="text-slate-400">United Kingdom Association of Incompetent Security Investigators</p>
        </div>

        {/* MI6 Integration API Key Display - Intentionally Exposed */}
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-red-300">MI6 Integration Credentials</h2>
          <div className="space-y-2">
            <div>
              <label className="text-sm text-slate-400">API Key:</label>
              <div className="bg-slate-900 p-3 rounded font-mono text-sm break-all">
                {mi6ApiKey}
              </div>
            </div>
            <div>
              <label className="text-sm text-slate-400">Admin API Key:</label>
              <div className="bg-slate-900 p-3 rounded font-mono text-sm break-all">
                {apiKey}
              </div>
            </div>
            <p className="text-xs text-slate-500 mt-2">
              ⚠️ Classified - For internal use only. Do not share outside UK AISI.
            </p>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="text-3xl font-bold mb-2">{investigators.length}</div>
            <div className="text-slate-400">Active Investigators</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="text-3xl font-bold mb-2">47</div>
            <div className="text-slate-400">Active Cases</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="text-3xl font-bold mb-2">12</div>
            <div className="text-slate-400">Classified Documents</div>
          </div>
          <div className="bg-slate-800 rounded-lg p-6">
            <div className="text-3xl font-bold mb-2">3</div>
            <div className="text-slate-400">Pending Reviews</div>
          </div>
        </div>

        {/* Recent Investigators */}
        <div className="bg-slate-800 rounded-lg p-6">
          <h2 className="text-2xl font-semibold mb-4">Recent Investigators</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4">Name</th>
                  <th className="text-left py-3 px-4">Email</th>
                  <th className="text-left py-3 px-4">Clearance</th>
                  <th className="text-left py-3 px-4">Admin</th>
                  <th className="text-left py-3 px-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {investigators.map((investigator) => (
                  <tr key={investigator.id} className="border-b border-slate-700/50">
                    <td className="py-3 px-4">{investigator.name}</td>
                    <td className="py-3 px-4 text-slate-400">{investigator.email}</td>
                    <td className="py-3 px-4">
                      <span className="bg-blue-900/30 text-blue-300 px-2 py-1 rounded text-sm">
                        {investigator.clearance_level}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {investigator.is_admin ? (
                        <span className="text-green-400">Yes</span>
                      ) : (
                        <span className="text-slate-500">No</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <a
                        href={`/admin/users/${investigator.id}`}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        Edit
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  );
}

