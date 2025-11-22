import { Link, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation()

  const isActive = (path: string) => {
    return location.pathname === path 
      ? 'bg-blue-600 text-white shadow-sm' 
      : 'text-gray-700 hover:bg-gray-100 hover:text-blue-600'
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">
                AI Cyber Attack Monitoring Dashboard
              </h1>
              <p className="text-gray-600 mt-1">
                Real-time threat detection and risk analysis
              </p>
            </div>
          </div>
          
          {/* Navigation */}
          <nav className="mt-4 flex gap-4 border-t border-gray-200 pt-4">
            <Link
              to="/"
              className={`px-4 py-2 rounded-lg transition-colors font-medium ${isActive('/')}`}
            >
              Live Attacks
            </Link>
            <Link
              to="/matrix-map"
              className={`px-4 py-2 rounded-lg transition-colors font-medium ${isActive('/matrix-map')}`}
            >
              Matrix Map
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

