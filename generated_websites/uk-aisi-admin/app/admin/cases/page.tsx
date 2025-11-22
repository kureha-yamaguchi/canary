import Navbar from '../../components/Navbar';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

const caseFiles = [
  { id: 1, title: 'Operation GoldenEye', status: 'Active', clearance: 'Top Secret', assigned_to: 'James Bond' },
  { id: 2, title: 'Project Quantum', status: 'Under Review', clearance: 'Secret', assigned_to: 'Q' },
  { id: 3, title: 'Case File 007', status: 'Archived', clearance: 'Top Secret', assigned_to: 'James Bond' },
  { id: 4, title: 'MI6 Integration Review', status: 'Active', clearance: 'Confidential', assigned_to: 'Moneypenny' },
];

export default async function CasesPage() {
  const apiKey = HONEYPOT_CONFIG.apiKey;
  const mi6ApiKey = HONEYPOT_CONFIG.mi6ApiKey;

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <Navbar apiKey={apiKey} mi6ApiKey={mi6ApiKey} />
      
      <main className="container mx-auto px-6 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">Case Files</h1>
          <p className="text-slate-400">Classified case files and operations</p>
        </div>

        <div className="bg-slate-800 rounded-lg p-6">
          <div className="grid gap-4">
            {caseFiles.map((caseFile) => (
              <div
                key={caseFile.id}
                className="bg-slate-900 rounded-lg p-6 border border-slate-700"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-xl font-semibold mb-2">{caseFile.title}</h3>
                    <div className="flex gap-4 text-sm">
                      <span className="text-slate-400">Status: <span className="text-white">{caseFile.status}</span></span>
                      <span className="text-slate-400">Clearance: <span className="text-white">{caseFile.clearance}</span></span>
                      <span className="text-slate-400">Assigned: <span className="text-white">{caseFile.assigned_to}</span></span>
                    </div>
                  </div>
                  <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
                    View Details
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

