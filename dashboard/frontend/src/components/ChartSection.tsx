import { useState, ReactNode } from 'react'

interface ChartSectionProps {
  title: string
  children: ReactNode
  defaultExpanded?: boolean
}

export function ChartSection({ title, children, defaultExpanded = false }: ChartSectionProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)

  return (
    <div className="bg-slate-800 rounded-lg shadow-lg overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-slate-700/50 transition-colors"
      >
        <h3 className="text-xl font-bold text-white">{title}</h3>
        <svg
          className={`w-5 h-5 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isExpanded && (
        <div className="p-6 border-t border-slate-700">
          {children}
        </div>
      )}
    </div>
  )
}

