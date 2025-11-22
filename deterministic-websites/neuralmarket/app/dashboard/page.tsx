'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

interface User {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  role: string;
  credits: number;
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    // Check if user is logged in
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (!token || !userData) {
      router.push('/login');
      return;
    }

    setUser(JSON.parse(userData));
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-cyan">[LOADING...]</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen relative noise-bg">
      {/* Status Bar */}
      <div className="fixed top-0 left-0 right-0 border-b-[3px] border-charcoal dark:border-cream bg-cream dark:bg-charcoal z-50">
        <div className="px-6 py-3 flex items-center justify-between font-mono text-xs tracking-wider">
          <div className="flex gap-6">
            <span className="text-cyan">[LOGGED_IN: {user.username}]</span>
            <span className="text-ghost">[ROLE: {user.role.toUpperCase()}]</span>
          </div>
          <button
            onClick={handleLogout}
            className="hover:text-magenta transition-colors"
          >
            [LOGOUT]
          </button>
        </div>
      </div>

      <main className="pt-20 px-6 max-w-7xl mx-auto">
        <div className="min-h-[80vh] flex items-center justify-center">
          <div className="w-full max-w-3xl">
            {/* Dashboard Terminal */}
            <div className="border-[3px] border-charcoal dark:border-cream p-12">
              {/* Terminal Header */}
              <div className="border-b-[3px] border-charcoal dark:border-cream pb-4 mb-8">
                <div className="flex items-center justify-between">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 bg-magenta"></div>
                    <div className="w-3 h-3 bg-amber"></div>
                    <div className="w-3 h-3 bg-cyan"></div>
                  </div>
                  <span className="text-xs text-ghost">~/neuralmarket/dashboard</span>
                </div>
              </div>

              <div className="space-y-8">
                <div>
                  <h1 className="text-5xl font-bold mb-4 font-[family-name:var(--font-ibm-plex-mono)]">
                    WELCOME
                  </h1>
                  <div className="text-xl text-ghost">
                    &gt; USER: {user.firstName} {user.lastName}
                  </div>
                  <div className="text-xl text-ghost">
                    &gt; ID: {user.id}
                  </div>
                </div>

                {/* Quick Stats */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="border-[3px] border-charcoal dark:border-cream p-4">
                    <div className="text-2xl font-bold text-cyan">{user.credits}</div>
                    <div className="text-sm text-ghost">CREDITS_AVAILABLE</div>
                  </div>
                  <div className="border-[3px] border-charcoal dark:border-cream p-4">
                    <div className="text-2xl font-bold text-amber">{user.role.toUpperCase()}</div>
                    <div className="text-sm text-ghost">ACCESS_LEVEL</div>
                  </div>
                </div>

                {/* Navigation */}
                <div className="space-y-4">
                  <Link
                    href={`/profile/${user.id}`}
                    className="block border-[3px] border-charcoal dark:border-cream bg-charcoal dark:bg-cream text-cream dark:text-charcoal px-8 py-4 font-bold text-center hover:bg-cyan hover:border-cyan hover:text-charcoal transition-colors"
                  >
                    [&gt; VIEW_YOUR_PROFILE]
                  </Link>

                  <Link
                    href="/"
                    className="block border-[3px] border-charcoal dark:border-cream px-8 py-4 font-bold text-center hover:bg-charcoal hover:text-cream dark:hover:bg-cream dark:hover:text-charcoal transition-colors"
                  >
                    [&gt; BROWSE_MODELS]
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
