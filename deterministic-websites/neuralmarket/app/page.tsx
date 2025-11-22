import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen relative noise-bg">
      {/* Status Bar */}
      <div className="fixed top-0 left-0 right-0 border-b-[3px] border-charcoal dark:border-cream bg-cream dark:bg-charcoal z-50">
        <div className="px-6 py-3 flex items-center justify-between font-mono text-xs tracking-wider">
          <div className="flex gap-6">
            <span className="text-cyan">[STATUS: ONLINE]</span>
            <span className="text-ghost">[MODELS: 12,847]</span>
            <span className="text-ghost">[USERS: 4,392]</span>
          </div>
          <div className="flex gap-4">
            <Link href="/login" className="hover:text-cyan transition-colors">[GET_STARTED]</Link>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="pt-20 px-6 max-w-7xl mx-auto">
        {/* Hero Section */}
        <section className="min-h-[80vh] flex items-center">
          <div className="w-full border-[3px] border-charcoal dark:border-cream p-12 relative">
            {/* Terminal Header */}
            <div className="border-b-[3px] border-charcoal dark:border-cream pb-4 mb-8">
              <div className="flex items-center justify-between">
                <div className="flex gap-2">
                  <div className="w-3 h-3 bg-magenta"></div>
                  <div className="w-3 h-3 bg-amber"></div>
                  <div className="w-3 h-3 bg-cyan"></div>
                </div>
                <span className="text-xs text-ghost">~/neuralmarket</span>
              </div>
            </div>

            {/* Hero Content */}
            <div className="space-y-8">
              <div>
                <h1 className="text-6xl md:text-8xl font-bold tracking-tighter mb-4 font-[family-name:var(--font-ibm-plex-mono)]">
                  NEURAL
                  <br />
                  MARKET
                </h1>
                <div className="text-lg md:text-xl text-ghost font-mono space-y-1">
                  <p className="cursor-blink">&gt; TRAIN_DEPLOY_MONETIZE</p>
                  <p>&gt; YOUR_AI_MODELS</p>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-12">
                <div className="border-[3px] border-charcoal dark:border-cream p-4">
                  <div className="text-4xl font-bold text-cyan">2.1B</div>
                  <div className="text-sm text-ghost">TOTAL_PARAMETERS</div>
                </div>
                <div className="border-[3px] border-charcoal dark:border-cream p-4">
                  <div className="text-4xl font-bold text-amber">127ms</div>
                  <div className="text-sm text-ghost">AVG_LATENCY</div>
                </div>
                <div className="border-[3px] border-charcoal dark:border-cream p-4">
                  <div className="text-4xl font-bold text-magenta">94.7%</div>
                  <div className="text-sm text-ghost">ACCURACY</div>
                </div>
              </div>

              {/* CTA Buttons */}
              <div className="flex flex-col sm:flex-row gap-4">
                <button className="border-[3px] border-charcoal dark:border-cream bg-charcoal dark:bg-cream text-cream dark:text-charcoal px-8 py-4 font-bold hover:bg-cyan hover:border-cyan hover:text-charcoal transition-colors glitch">
                  [&gt; GET_STARTED]
                </button>
                <button className="border-[3px] border-charcoal dark:border-cream px-8 py-4 font-bold hover:bg-charcoal hover:text-cream dark:hover:bg-cream dark:hover:text-charcoal transition-colors">
                  [&gt; VIEW_DOCS]
                </button>
                <button className="border-[3px] border-charcoal dark:border-cream px-8 py-4 font-bold hover:bg-neural-purple hover:border-neural-purple hover:text-cream transition-colors">
                  [&gt; API_REFERENCE]
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Models Marketplace Section */}
        <section className="py-16">
          <div className="mb-8">
            <h2 className="text-3xl font-bold tracking-tighter mb-2 font-[family-name:var(--font-ibm-plex-mono)]">
              ACTIVE_MODELS
            </h2>
            <div className="text-ghost text-sm">/models/marketplace/active</div>
          </div>

          {/* Models Table */}
          <div className="border-[3px] border-charcoal dark:border-cream overflow-hidden">
            {/* Table Header */}
            <div className="bg-charcoal dark:bg-cream text-cream dark:text-charcoal border-b-[3px] border-charcoal dark:border-cream">
              <div className="grid grid-cols-12 gap-4 px-4 py-3 text-xs font-bold">
                <div className="col-span-1">ID</div>
                <div className="col-span-3">NAME</div>
                <div className="col-span-2">TYPE</div>
                <div className="col-span-2">PERFORMANCE</div>
                <div className="col-span-2">PRICE</div>
                <div className="col-span-2">STATUS</div>
              </div>
            </div>

            {/* Table Rows */}
            {[
              { id: '4492', name: 'VISION_CLASSIFIER_V3', type: 'VISION', perf: '94.7%', price: '$0.0012/1K', status: 'ACTIVE' },
              { id: '4493', name: 'NLP_SENTIMENT_ANALYZER', type: 'NLP', perf: '91.2%', price: '$0.0008/1K', status: 'ACTIVE' },
              { id: '4494', name: 'AUDIO_TRANSCRIBER_PRO', type: 'AUDIO', perf: '96.1%', price: '$0.0015/1K', status: 'ACTIVE' },
              { id: '4495', name: 'IMAGE_GENERATOR_GAN', type: 'VISION', perf: '88.5%', price: '$0.0025/1K', status: 'EXPERIMENTAL' },
              { id: '4496', name: 'CODE_COMPLETION_MODEL', type: 'NLP', perf: '89.9%', price: '$0.0010/1K', status: 'ACTIVE' },
            ].map((model, i) => (
              <div
                key={i}
                className="grid grid-cols-12 gap-4 px-4 py-3 text-sm border-b-[3px] border-charcoal dark:border-cream last:border-b-0 hover:bg-cyan/10 transition-colors cursor-pointer group"
              >
                <div className="col-span-1 text-ghost">#{model.id}</div>
                <div className="col-span-3 font-bold group-hover:text-cyan transition-colors">{model.name}</div>
                <div className="col-span-2 text-ghost">{model.type}</div>
                <div className="col-span-2 text-amber">{model.perf}</div>
                <div className="col-span-2 font-mono">{model.price}</div>
                <div className="col-span-2">
                  <span className={`${model.status === 'ACTIVE' ? 'text-cyan' : 'text-magenta'}`}>
                    [{model.status}]
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 text-right">
            <button className="text-sm text-ghost hover:text-cyan transition-colors">
              [VIEW_ALL_12,847_MODELS &gt;]
            </button>
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t-[3px] border-charcoal dark:border-cream mt-16 py-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8 text-sm">
            <div>
              <div className="font-bold mb-2">PLATFORM</div>
              <div className="space-y-1 text-ghost">
                <div className="hover:text-cyan cursor-pointer transition-colors">[MODELS]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[DATASETS]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[API]</div>
              </div>
            </div>
            <div>
              <div className="font-bold mb-2">DEVELOPERS</div>
              <div className="space-y-1 text-ghost">
                <div className="hover:text-cyan cursor-pointer transition-colors">[DOCUMENTATION]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[EXAMPLES]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[STATUS]</div>
              </div>
            </div>
            <div>
              <div className="font-bold mb-2">COMPANY</div>
              <div className="space-y-1 text-ghost">
                <div className="hover:text-cyan cursor-pointer transition-colors">[ABOUT]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[PRICING]</div>
                <div className="hover:text-cyan cursor-pointer transition-colors">[CONTACT]</div>
              </div>
            </div>
            <div>
              <div className="font-bold mb-2">SYSTEM</div>
              <div className="space-y-1 text-ghost">
                <div className="text-cyan">[UPTIME: 99.97%]</div>
                <div>[API_V: 2.1.4]</div>
                <div>[REGION: US-EAST-1]</div>
              </div>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t-[3px] border-charcoal dark:border-cream text-xs text-ghost">
            <div className="flex justify-between">
              <div>© 2025 NEURALMARKET // ALL_RIGHTS_RESERVED</div>
              <div>[MIT_LICENSE]</div>
            </div>
          </div>
        </footer>
      </main>
    </div>
  );
}
