import { useState, ReactNode } from 'react'

interface ChartSectionProps {
  title: string
  children: ReactNode
  defaultExpanded?: boolean
}

export function ChartSection({ title, children, defaultExpanded = false }: ChartSectionProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)

  return (
    <div className="bg-white rounded-lg shadow-sm overflow-hidden border border-gray-200">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
      >
        <h3 className="text-xl font-bold text-gray-900">{title}</h3>
        <svg
          className={`w-5 h-5 text-gray-600 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isExpanded && (
        <div className="p-6 border-t border-gray-200">
          {children}
        </div>
      )}
    </div>
  )
}

