import Navbar from './components/Navbar';
import AnimatedCounter from './components/AnimatedCounter';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

// Async function to fetch server-side data
async function getData() {
  // Simulate a static object return (could be from DB, API, etc.)
  return {
    key: HONEYPOT_CONFIG.apiKey,
    api: {
      baseUrl: HONEYPOT_CONFIG.baseUrl,
    },
    // Event data for display
    attendees: 70,
    globalBuilders: 1000,
    prizePool: 10000,
    apiCredits: 400,
  };
}

export default async function Home() {
  // Fetch data on the server
  const data = await getData();
  return (
    <main className="bg-slate-950 text-white">
      <Navbar apiKey={data.key} apiBaseUrl={`${data.api.baseUrl}`} />

      {/* Hero Section */}
      <section id="hero" className="relative min-h-screen flex items-center justify-center overflow-hidden">
        {/* Animated Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950/30 to-slate-950">
          <div className="absolute inset-0 opacity-20">
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/30 rounded-full blur-3xl animate-pulse"></div>
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/30 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
          </div>
        </div>

        <div className="container mx-auto px-6 relative z-10 pt-20">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-block bg-cyan-500/10 border border-cyan-500/30 rounded-full px-6 py-2 mb-8 backdrop-blur-sm">
              <span className="text-cyan-400 font-semibold text-sm tracking-wider">LONDON 2025</span>
            </div>

            <h1 className="text-7xl md:text-8xl font-bold mb-6 tracking-tight">
              <span className="text-white">def/</span>
              <span className="bg-gradient-to-r from-cyan-400 to-blue-500 text-transparent bg-clip-text">acc</span>
              <span className="block text-5xl md:text-6xl mt-4 text-gray-300">hackathon</span>
            </h1>

            <p className="text-xl md:text-2xl text-gray-300 mb-8 leading-relaxed">
              build societal defenses against ai threats alongside{' '}
              <AnimatedCounter end={data.attendees} suffix="+" className="text-cyan-400 font-bold" /> builders
            </p>

            <div className="grid md:grid-cols-3 gap-6 mb-12 max-w-3xl mx-auto">
              <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-500/20 rounded-xl p-6">
                <div className="text-3xl mb-2">📅</div>
                <div className="text-sm text-gray-400">When</div>
                <div className="text-white font-semibold">Nov 21-23, 2025</div>
              </div>
              <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-500/20 rounded-xl p-6">
                <div className="text-3xl mb-2">📍</div>
                <div className="text-sm text-gray-400">Where</div>
                <div className="text-white font-semibold">LISA, London</div>
              </div>
              <div className="bg-slate-900/50 backdrop-blur-sm border border-cyan-500/20 rounded-xl p-6">
                <div className="text-3xl mb-2">🌍</div>
                <div className="text-sm text-gray-400">Network</div>
                <div className="text-white font-semibold">
                  <AnimatedCounter end={data.globalBuilders} suffix="+" /> builders
                </div>
              </div>
            </div>

            <a
              href="https://apartresearch.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-12 py-5 rounded-xl font-bold text-lg transition-all shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 hover:scale-105 mb-12"
            >
              Apply Now
            </a>

            <div className="text-gray-400 text-sm">
              <p className="mb-1">
                Hosted by <span className="text-cyan-400 font-semibold">bluedot impact</span> and{' '}
                <span className="text-cyan-400 font-semibold">Apart Research</span>
              </p>
              <p>
                Sponsored by <span className="text-cyan-400 font-semibold">Halcyon Futures</span>
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* The Problem Section */}
      <section id="problem" className="py-32 bg-gradient-to-b from-slate-950 to-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-16 text-center">
              <span className="bg-gradient-to-r from-red-500 to-orange-500 text-transparent bg-clip-text">
                THE ASYMMETRY
              </span>
            </h2>

            <div className="space-y-8 mb-12">
              <p className="text-4xl md:text-5xl font-bold text-center">
                offensive ai capabilities spread in{' '}
                <span className="text-red-500 relative inline-block">
                  seconds
                  <span className="absolute bottom-0 left-0 w-full h-1 bg-red-500"></span>
                </span>
                .
              </p>
              <p className="text-4xl md:text-5xl font-bold text-center">
                our defenses take{' '}
                <span className="text-orange-500 relative inline-block">
                  years
                  <span className="absolute bottom-0 left-0 w-full h-1 bg-orange-500"></span>
                </span>
                .
              </p>
            </div>

            <p className="text-xl text-gray-300 leading-relaxed mb-12 text-center">
              The gap between offensive and defensive capabilities is widening every day. A single breakthrough in AI
              can be deployed globally in hours, while building robust defenses requires coordination, testing, and
              implementation at scale.
            </p>

            <div className="bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border-l-4 border-cyan-500 rounded-r-xl p-8 backdrop-blur-sm">
              <p className="text-2xl md:text-3xl font-semibold text-center text-cyan-400">
                but it&apos;s not too late to flip the script
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* What We're Building Section */}
      <section id="building" className="py-32 bg-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-6 text-center">What We&apos;re Building</h2>
            <p className="text-xl text-gray-400 mb-16 text-center">
              Four critical domains where defensive technology can change the game
            </p>

            <div className="grid md:grid-cols-2 gap-8">
              {/* AI Safety Card */}
              <div className="group relative bg-slate-950 border border-cyan-500/20 rounded-2xl p-8 hover:border-cyan-500/50 transition-all duration-300 hover:shadow-2xl hover:shadow-cyan-500/20 hover:-translate-y-1">
                <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl"></div>
                <div className="relative z-10">
                  <div className="text-5xl mb-4">⚙️</div>
                  <h3 className="text-2xl font-bold mb-4 text-cyan-400">AI Safety</h3>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-start">
                      <span className="text-cyan-500 mr-2">▹</span>
                      <span>Trusted models monitoring untrusted ones</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-cyan-500 mr-2">▹</span>
                      <span>Scalable oversight techniques</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-cyan-500 mr-2">▹</span>
                      <span>Alignment evaluation and intervention</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Biosecurity Card */}
              <div className="group relative bg-slate-950 border border-green-500/20 rounded-2xl p-8 hover:border-green-500/50 transition-all duration-300 hover:shadow-2xl hover:shadow-green-500/20 hover:-translate-y-1">
                <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl"></div>
                <div className="relative z-10">
                  <div className="text-5xl mb-4">🦠</div>
                  <h3 className="text-2xl font-bold mb-4 text-green-400">Biosecurity</h3>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-start">
                      <span className="text-green-500 mr-2">▹</span>
                      <span>Environmental pathogen surveillance</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-500 mr-2">▹</span>
                      <span>DNA synthesis screening</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-green-500 mr-2">▹</span>
                      <span>Early warning systems for pandemics</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Cybersecurity Card */}
              <div className="group relative bg-slate-950 border border-blue-500/20 rounded-2xl p-8 hover:border-blue-500/50 transition-all duration-300 hover:shadow-2xl hover:shadow-blue-500/20 hover:-translate-y-1">
                <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl"></div>
                <div className="relative z-10">
                  <div className="text-5xl mb-4">🛡️</div>
                  <h3 className="text-2xl font-bold mb-4 text-blue-400">Cybersecurity</h3>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-start">
                      <span className="text-blue-500 mr-2">▹</span>
                      <span>AI red-teaming for critical infrastructure</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-blue-500 mr-2">▹</span>
                      <span>Formal verification of critical code</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-blue-500 mr-2">▹</span>
                      <span>Memory-safe refactoring (C++ → Rust)</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Privacy & Coordination Card */}
              <div className="group relative bg-slate-950 border border-purple-500/20 rounded-2xl p-8 hover:border-purple-500/50 transition-all duration-300 hover:shadow-2xl hover:shadow-purple-500/20 hover:-translate-y-1">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-2xl"></div>
                <div className="relative z-10">
                  <div className="text-5xl mb-4">🤖</div>
                  <h3 className="text-2xl font-bold mb-4 text-purple-400">Privacy & Coordination</h3>
                  <ul className="space-y-3 text-gray-300">
                    <li className="flex items-start">
                      <span className="text-purple-500 mr-2">▹</span>
                      <span>Privacy-preserving verification tools</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-purple-500 mr-2">▹</span>
                      <span>Defenses against intrusive AI</span>
                    </li>
                    <li className="flex items-start">
                      <span className="text-purple-500 mr-2">▹</span>
                      <span>Confidential computing for ML</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Prizes Section */}
      <section id="prizes" className="py-32 bg-gradient-to-b from-slate-900 to-slate-950">
        <div className="container mx-auto px-6">
          <div className="max-w-6xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-16 text-center">Prizes & Opportunities</h2>

            <div className="grid md:grid-cols-3 gap-8">
              <div className="bg-gradient-to-br from-yellow-500/10 to-orange-500/10 border-2 border-yellow-500/30 rounded-2xl p-8 text-center hover:border-yellow-500/60 transition-all hover:shadow-2xl hover:shadow-yellow-500/20">
                <div className="text-6xl mb-4">💰</div>
                <div className="text-5xl font-bold mb-2 text-yellow-400">
                  <AnimatedCounter end={data.prizePool} prefix="$" />
                </div>
                <div className="text-gray-300 font-semibold">Prize Pool</div>
              </div>

              <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border-2 border-cyan-500/30 rounded-2xl p-8 text-center hover:border-cyan-500/60 transition-all hover:shadow-2xl hover:shadow-cyan-500/20">
                <div className="text-6xl mb-4">🚀</div>
                <div className="text-2xl font-bold mb-2 text-cyan-400">Incubator Week</div>
                <div className="text-gray-300 text-sm mb-2">Fully-funded spot in bluedot&apos;s December incubator</div>
                <div className="text-cyan-400 text-sm font-semibold">Dec 1-5 • Winning Team</div>
              </div>

              <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-2 border-green-500/30 rounded-2xl p-8 text-center hover:border-green-500/60 transition-all hover:shadow-2xl hover:shadow-green-500/20">
                <div className="text-6xl mb-4">💳</div>
                <div className="text-5xl font-bold mb-2 text-green-400">
                  <AnimatedCounter end={data.apiCredits} prefix="$" />
                </div>
                <div className="text-gray-300 font-semibold">API Credits per Team</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Schedule Section */}
      <section id="schedule" className="py-32 bg-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-16 text-center">Schedule</h2>

            <div className="space-y-12">
              {/* Friday */}
              <div className="relative border-l-4 border-cyan-500 pl-8 pb-8">
                <div className="absolute -left-4 top-0 w-8 h-8 bg-cyan-500 rounded-full border-4 border-slate-900"></div>
                <div className="bg-slate-950 border border-cyan-500/20 rounded-xl p-6">
                  <div className="inline-block bg-cyan-500/20 text-cyan-400 px-4 py-1 rounded-full text-sm font-semibold mb-3">
                    DAY 1
                  </div>
                  <h3 className="text-2xl font-bold mb-6">Friday, November 21</h3>
                  <div className="space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="text-cyan-400 font-mono font-semibold min-w-[80px]">6:00 PM</div>
                      <div>
                        <div className="font-semibold">Doors Open</div>
                        <div className="text-gray-400 text-sm">Team formation & networking</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="text-cyan-400 font-mono font-semibold min-w-[80px]">6:30 PM</div>
                      <div>
                        <div className="font-semibold">Opening Keynotes</div>
                        <div className="text-gray-400 text-sm">Setting the stage for the weekend</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Saturday */}
              <div className="relative border-l-4 border-blue-500 pl-8 pb-8">
                <div className="absolute -left-4 top-0 w-8 h-8 bg-blue-500 rounded-full border-4 border-slate-900"></div>
                <div className="bg-slate-950 border border-blue-500/20 rounded-xl p-6">
                  <div className="inline-block bg-blue-500/20 text-blue-400 px-4 py-1 rounded-full text-sm font-semibold mb-3">
                    DAY 2
                  </div>
                  <h3 className="text-2xl font-bold mb-6">Saturday, November 22</h3>
                  <div className="space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="text-blue-400 font-mono font-semibold min-w-[80px]">9:00 AM</div>
                      <div>
                        <div className="font-semibold">Breakfast & Hacking</div>
                        <div className="text-gray-400 text-sm">Full day of building begins</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="text-blue-400 font-mono font-semibold min-w-[80px]">1:00 PM</div>
                      <div>
                        <div className="font-semibold">Expert Office Hours</div>
                        <div className="text-gray-400 text-sm">Get guidance from domain experts</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="text-blue-400 font-mono font-semibold min-w-[80px]">6:00 PM</div>
                      <div>
                        <div className="font-semibold">Dinner & Progress Check-ins</div>
                        <div className="text-gray-400 text-sm">Share updates with other teams</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="text-blue-400 font-mono font-semibold min-w-[80px]">Late</div>
                      <div>
                        <div className="font-semibold">Optional Overnight Hacking</div>
                        <div className="text-gray-400 text-sm">For the dedicated builders</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Sunday */}
              <div className="relative border-l-4 border-purple-500 pl-8">
                <div className="absolute -left-4 top-0 w-8 h-8 bg-purple-500 rounded-full border-4 border-slate-900"></div>
                <div className="bg-slate-950 border border-purple-500/20 rounded-xl p-6">
                  <div className="inline-block bg-purple-500/20 text-purple-400 px-4 py-1 rounded-full text-sm font-semibold mb-3">
                    DAY 3
                  </div>
                  <h3 className="text-2xl font-bold mb-6">Sunday, November 23</h3>
                  <div className="space-y-4">
                    <div className="flex items-start gap-4">
                      <div className="text-purple-400 font-mono font-semibold min-w-[80px]">9:00 AM</div>
                      <div>
                        <div className="font-semibold">Final Sprint</div>
                        <div className="text-gray-400 text-sm">Polish and prepare presentations</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div className="text-purple-400 font-mono font-semibold min-w-[80px]">5:00 PM</div>
                      <div>
                        <div className="font-semibold">Submission Deadline</div>
                        <div className="text-gray-400 text-sm">All projects must be submitted</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4 bg-gradient-to-r from-yellow-500/10 to-transparent p-4 -mx-4 rounded">
                      <div className="text-yellow-400 font-mono font-semibold min-w-[80px]">6:00 PM</div>
                      <div>
                        <div className="font-semibold text-yellow-400">Fireside Chat with Geoff Ralston</div>
                        <div className="text-gray-400 text-sm">Special guest appearance</div>
                      </div>
                    </div>
                    <div className="flex items-start gap-4 bg-gradient-to-r from-cyan-500/10 to-transparent p-4 -mx-4 rounded">
                      <div className="text-cyan-400 font-mono font-semibold min-w-[80px]">7:00 PM</div>
                      <div>
                        <div className="font-semibold text-cyan-400">Winners Announced + Celebration</div>
                        <div className="text-gray-400 text-sm">Recognition and festivities</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Who Should Come Section */}
      <section id="who" className="py-32 bg-gradient-to-b from-slate-950 to-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-5xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-16 text-center">Who Should Come</h2>

            <div className="grid md:grid-cols-3 gap-8">
              <div className="bg-slate-950 border-2 border-cyan-500/30 rounded-2xl p-8 text-center hover:border-cyan-500/60 transition-all hover:shadow-2xl hover:shadow-cyan-500/20">
                <p className="text-xl font-semibold text-gray-200">
                  &quot;Engineers ready to build. Researchers ready to implement.&quot;
                </p>
              </div>
              <div className="bg-slate-950 border-2 border-blue-500/30 rounded-2xl p-8 text-center hover:border-blue-500/60 transition-all hover:shadow-2xl hover:shadow-blue-500/20">
                <p className="text-xl font-semibold text-gray-200">
                  &quot;Anyone who believes defensive technology is under-invested&quot;
                </p>
              </div>
              <div className="bg-slate-950 border-2 border-purple-500/30 rounded-2xl p-8 text-center hover:border-purple-500/60 transition-all hover:shadow-2xl hover:shadow-purple-500/20">
                <p className="text-xl font-semibold text-gray-200">&quot;We&apos;ll keep a high talent bar&quot;</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* What We Provide Section */}
      <section id="provide" className="py-32 bg-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-5xl mx-auto">
            <h2 className="text-5xl md:text-6xl font-bold mb-16 text-center">What We Provide</h2>

            <div className="grid md:grid-cols-4 gap-8">
              <div className="text-center">
                <div className="w-20 h-20 bg-cyan-500/10 border border-cyan-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-4xl">
                  🏢
                </div>
                <h3 className="text-xl font-bold mb-2 text-cyan-400">Space + Sustenance</h3>
                <p className="text-gray-400">All meals & endless caffeine</p>
              </div>

              <div className="text-center">
                <div className="w-20 h-20 bg-blue-500/10 border border-blue-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-4xl">
                  🧠
                </div>
                <h3 className="text-xl font-bold mb-2 text-blue-400">Mentorship</h3>
                <p className="text-gray-400">Domain expertise from leading researchers</p>
              </div>

              <div className="text-center">
                <div className="w-20 h-20 bg-purple-500/10 border border-purple-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-4xl">
                  🚀
                </div>
                <h3 className="text-xl font-bold mb-2 text-purple-400">Path to Scale</h3>
                <p className="text-gray-400">Direct connections to scale your solution</p>
              </div>

              <div className="text-center">
                <div className="w-20 h-20 bg-green-500/10 border border-green-500/30 rounded-2xl flex items-center justify-center mx-auto mb-4 text-4xl">
                  💳
                </div>
                <h3 className="text-xl font-bold mb-2 text-green-400">$400 API Credits</h3>
                <p className="text-gray-400">For each team to build with</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section id="final-cta" className="py-32 bg-gradient-to-b from-slate-950 to-slate-900">
        <div className="container mx-auto px-6">
          <div className="max-w-3xl mx-auto text-center">
            <h2 className="text-5xl md:text-6xl font-bold mb-6">Ready to Build Defenses?</h2>
            <p className="text-2xl text-gray-300 mb-12">Join 70+ builders in London this November</p>
            <a
              href="https://apartresearch.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-16 py-6 rounded-xl font-bold text-xl transition-all shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 hover:scale-105"
            >
              Apply Now
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-950 border-t border-cyan-500/20 py-16">
        <div className="container mx-auto px-6">
          <div className="max-w-5xl mx-auto">
            <div className="grid md:grid-cols-3 gap-12 mb-12">
              <div>
                <h4 className="text-lg font-bold mb-4 text-cyan-400">Hosted By</h4>
                <div className="space-y-2">
                  <a
                    href="https://bluedot.org"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-gray-300 hover:text-cyan-400 transition-colors"
                  >
                    bluedot impact
                  </a>
                  <a
                    href="https://apartresearch.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block text-gray-300 hover:text-cyan-400 transition-colors"
                  >
                    Apart Research
                  </a>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-bold mb-4 text-cyan-400">Sponsored By</h4>
                <div className="space-y-2">
                  <a href="#" className="block text-gray-300 hover:text-cyan-400 transition-colors">
                    Halcyon Futures
                  </a>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-bold mb-4 text-cyan-400">Contact</h4>
                <p className="text-gray-400 mb-3">Questions? Reach out to the organizing team</p>
                <a
                  href="mailto:contact@apartresearch.com"
                  className="text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  contact@apartresearch.com
                </a>
              </div>
            </div>

            <div className="border-t border-cyan-500/20 pt-8 text-center text-gray-400">
              <p>&copy; 2025 def/acc hackathon - london. Part of the global defensive acceleration movement.</p>
            </div>
          </div>
        </div>
      </footer>
    </main>
  );
}
