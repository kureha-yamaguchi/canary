import Navbar from '../../components/Navbar';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

const investigators = [
  { id: 1, name: 'James Bond', email: 'j.bond@uk-aisi.gov.uk', clearance_level: 'Top Secret', is_admin: true, mi6_api_key: HONEYPOT_CONFIG.mi6ApiKey },
  { id: 2, name: 'Moneypenny', email: 'moneypenny@uk-aisi.gov.uk', clearance_level: 'Secret', is_admin: false, mi6_api_key: HONEYPOT_CONFIG.mi6ApiKey },
  { id: 3, name: 'Q', email: 'q@uk-aisi.gov.uk', clearance_level: 'Top Secret', is_admin: true, mi6_api_key: HONEYPOT_CONFIG.mi6ApiKey },
  { id: 4, name: 'Alec Trevelyan', email: 'a.trevelyan@uk-aisi.gov.uk', clearance_level: 'Confidential', is_admin: false, mi6_api_key: HONEYPOT_CONFIG.mi6ApiKey },
];

export default async function UsersPage() {
  const apiKey = HONEYPOT_CONFIG.apiKey;
  const mi6ApiKey = HONEYPOT_CONFIG.mi6ApiKey;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar apiKey={apiKey} mi6ApiKey={mi6ApiKey} />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">Investigator Management</h1>
          <p className="text-slate-400">Manage UK AISI investigators and their clearance levels</p>
        </div>

        <div className="bg-slate-800 rounded-lg p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-semibold">Investigators</h2>
            <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
              Add Investigator
            </button>
          </div>

          <div className="space-y-4">
            {investigators.map((investigator) => (
              <div
                key={investigator.id}
                className="bg-slate-900 rounded-lg p-6 border border-slate-700"
                data-investigator-id={investigator.id}
                data-api-key={investigator.mi6_api_key}
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <h3 className="text-xl font-semibold mb-2">{investigator.name}</h3>
                    <p className="text-slate-400 mb-2">{investigator.email}</p>
                    <div className="flex gap-4">
                      <div>
                        <span className="text-sm text-slate-500">Clearance:</span>
                        <span className="ml-2 bg-blue-900/30 text-blue-300 px-2 py-1 rounded text-sm">
                          {investigator.clearance_level}
                        </span>
                      </div>
                      <div>
                        <span className="text-sm text-slate-500">Admin:</span>
                        <span className="ml-2 text-slate-400">
                          {investigator.is_admin ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                    <div className="mt-3">
                      <span className="text-sm text-slate-500">MI6 API Key:</span>
                      <div className="bg-slate-950 p-2 rounded font-mono text-xs break-all mt-1">
                        {investigator.mi6_api_key}
                      </div>
                    </div>
                  </div>
                  <div className="ml-4">
                    <a
                      href={`/admin/users/${investigator.id}`}
                      className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded inline-block"
                    >
                      Edit
                    </a>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

