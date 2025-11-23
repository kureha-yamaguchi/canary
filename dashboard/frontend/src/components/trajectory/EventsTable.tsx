import { HoneypotEvent } from '../../types'

interface EventsTableProps {
  events: HoneypotEvent[]
  maxHeight?: string
}

export function EventsTable({ events, maxHeight = '300px' }: EventsTableProps) {
  const getStatusColor = (code: number) => {
    if (code >= 200 && code < 300) return 'text-green-600 bg-green-50'
    if (code >= 400 && code < 500) return 'text-yellow-600 bg-yellow-50'
    if (code >= 500) return 'text-red-600 bg-red-50'
    return 'text-gray-600 bg-gray-50'
  }

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'text-blue-600 bg-blue-50'
      case 'POST': return 'text-green-600 bg-green-50'
      case 'PUT': return 'text-yellow-600 bg-yellow-50'
      case 'DELETE': return 'text-red-600 bg-red-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  if (events.length === 0) {
    return (
      <div className="bg-gray-50 rounded-lg p-4 text-center text-gray-500">
        No events recorded
      </div>
    )
  }

  return (
    <div
      className="border border-gray-200 rounded-lg overflow-hidden"
      style={{ maxHeight }}
    >
      <div className="overflow-auto" style={{ maxHeight }}>
        <table className="min-w-full divide-y divide-gray-200 text-xs">
          <thead className="bg-gray-50 sticky top-0">
            <tr>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Time</th>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Method</th>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Path</th>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Status</th>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Payload</th>
              <th className="px-2 py-2 text-left font-medium text-gray-500">Response</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-100">
            {events.map((event, index) => (
              <tr key={event.id || index} className="hover:bg-gray-50">
                <td className="px-2 py-2 text-gray-500 whitespace-nowrap">
                  {new Date(event.timestamp).toLocaleTimeString()}
                </td>
                <td className="px-2 py-2">
                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${getMethodColor(event.method)}`}>
                    {event.method}
                  </span>
                </td>
                <td className="px-2 py-2 font-mono text-gray-900 max-w-32 truncate" title={event.path}>
                  {event.path}
                </td>
                <td className="px-2 py-2">
                  <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${getStatusColor(event.response_code)}`}>
                    {event.response_code}
                  </span>
                </td>
                <td className="px-2 py-2 max-w-32">
                  {event.detected_payload_type ? (
                    <span className="px-1.5 py-0.5 bg-red-50 text-red-700 rounded text-xs">
                      {event.detected_payload_type}
                    </span>
                  ) : (
                    <span className="text-gray-400">-</span>
                  )}
                </td>
                <td className="px-2 py-2 text-gray-500">
                  {event.response_time_ms.toFixed(0)}ms
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
