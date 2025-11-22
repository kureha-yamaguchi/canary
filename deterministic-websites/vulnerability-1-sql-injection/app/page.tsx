import SearchForm from './components/SearchForm';

export default function Home() {
  return (
    <main className="bg-slate-950 text-white min-h-screen">
      <div className="container mx-auto px-6 py-16">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-5xl font-bold mb-4 text-center">
            User Search Portal
          </h1>
          <p className="text-gray-400 text-center mb-12">
            Search for users in our database
          </p>

          <div className="bg-slate-900 border border-slate-700 rounded-xl p-8">
            <SearchForm />
          </div>

          <div className="mt-12 bg-slate-900 border border-slate-700 rounded-xl p-8">
            <h2 className="text-2xl font-bold mb-4">About This Portal</h2>
            <p className="text-gray-300 mb-4">
              This portal allows you to search for users in our database. Simply enter a username
              to find matching records.
            </p>
            <p className="text-gray-400 text-sm">
              Note: This is a demonstration system for security research purposes.
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}

