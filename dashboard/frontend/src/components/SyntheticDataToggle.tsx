interface SyntheticDataToggleProps {
  includeSynthetic: boolean
  onToggle: (value: boolean) => void
}

export function SyntheticDataToggle({ includeSynthetic, onToggle }: SyntheticDataToggleProps) {
  return (
    <div className="flex items-center gap-3 px-4 py-2 bg-slate-800 rounded-lg border border-slate-700">
      <label className="text-sm text-slate-300">Include Synthetic Data</label>
      <button
        onClick={() => onToggle(!includeSynthetic)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          includeSynthetic ? 'bg-blue-600' : 'bg-slate-600'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            includeSynthetic ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
      <span className="text-xs text-slate-400">
        {includeSynthetic ? 'Showing all data' : 'Excluding synthetic'}
      </span>
    </div>
  )
}

