import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen relative bg-[#F5F5F7] dark:bg-charcoal">
      {/* Header */}
      <div className="border-b border-charcoal dark:border-cream bg-white dark:bg-charcoal">
        <div className="px-6 py-4">
          <h1 className="text-4xl font-bold tracking-tighter font-[family-name:var(--font-ibm-plex-mono)]">
            ERROR_404
          </h1>
          <div className="text-xs text-ghost">/system/error/not_found</div>
        </div>
      </div>

      <div className="px-6 py-6">
        <div className="border border-charcoal dark:border-cream bg-white dark:bg-charcoal p-12 text-center">
          <div className="text-6xl font-bold mb-4 text-crimson font-mono">[404]</div>
          <h2 className="text-2xl font-bold mb-4 font-[family-name:var(--font-ibm-plex-mono)]">
            SESSION_NOT_FOUND
          </h2>
          <p className="text-ghost mb-6 font-mono text-sm">
            The requested session does not exist or contains no attacks.
          </p>
          <Link
            href="/dashboard"
            className="border border-charcoal dark:border-cream bg-cyan text-charcoal px-6 py-3 text-sm font-mono hover:bg-amber transition-colors inline-block"
          >
            [← RETURN_TO_DASHBOARD]
          </Link>
        </div>
      </div>
    </div>
  );
}
