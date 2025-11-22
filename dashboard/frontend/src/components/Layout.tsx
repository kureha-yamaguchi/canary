import { Link, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation()

  const isActive = (path: string) => {
    return location.pathname === path ? 'bg-slate-700 text-white' : 'text-slate-300 hover:bg-slate-700/50'
  }

  return (
    <div className="min-h-screen bg-slate-900">
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white">
                AI Cyber Attack Monitoring Dashboard
              </h1>
              <p className="text-slate-400 mt-1">
                Real-time threat detection and risk analysis
              </p>
            </div>
          </div>
          
          {/* Navigation */}
          <nav className="mt-4 flex gap-4 border-t border-slate-700 pt-4">
            <Link
              to="/"
              className={`px-4 py-2 rounded-lg transition-colors ${isActive('/')}`}
            >
              Live Attacks
            </Link>
            <Link
              to="/risk-analysis"
              className={`px-4 py-2 rounded-lg transition-colors ${isActive('/risk-analysis')}`}
            >
              Risk Analysis
            </Link>
          </nav>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>
    </div>
  )
}

