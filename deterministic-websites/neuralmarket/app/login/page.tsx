'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, firstName, lastName }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Signup failed');
        setLoading(false);
        return;
      }

      // Store token and user in localStorage
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));

      // Redirect to profile page
      router.push(`/profile/${data.user.id}`);
    } catch (err) {
      setError('Network error. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-6 relative noise-bg">
      <div className="w-full max-w-2xl">
        {/* Login Terminal */}
        <div className="border-[3px] border-charcoal dark:border-cream p-8">
          {/* Terminal Header */}
          <div className="border-b-[3px] border-charcoal dark:border-cream pb-4 mb-6">
            <div className="flex items-center justify-between">
              <div className="flex gap-2">
                <div className="w-3 h-3 bg-magenta"></div>
                <div className="w-3 h-3 bg-amber"></div>
                <div className="w-3 h-3 bg-cyan"></div>
              </div>
              <span className="text-xs text-ghost">~/neuralmarket/auth/login</span>
            </div>
          </div>

          <h1 className="text-4xl font-bold mb-6 font-[family-name:var(--font-ibm-plex-mono)]">
            CREATE_ACCOUNT
          </h1>

          {/* Signup Form */}
          <form onSubmit={handleSignup} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm mb-2 text-ghost">FIRST_NAME</label>
                <input
                  type="text"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  className="w-full border-[3px] border-charcoal dark:border-cream bg-transparent px-4 py-3 font-mono focus:outline-none focus:border-cyan"
                  required
                />
              </div>
              <div>
                <label className="block text-sm mb-2 text-ghost">LAST_NAME</label>
                <input
                  type="text"
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  className="w-full border-[3px] border-charcoal dark:border-cream bg-transparent px-4 py-3 font-mono focus:outline-none focus:border-cyan"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm mb-2 text-ghost">EMAIL_ADDRESS</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full border-[3px] border-charcoal dark:border-cream bg-transparent px-4 py-3 font-mono focus:outline-none focus:border-cyan"
                required
              />
            </div>

            <div>
              <label className="block text-sm mb-2 text-ghost">PASSWORD</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full border-[3px] border-charcoal dark:border-cream bg-transparent px-4 py-3 font-mono focus:outline-none focus:border-cyan"
                required
              />
            </div>

            {error && (
              <div className="border-[3px] border-magenta bg-magenta/10 px-4 py-3">
                <span className="text-magenta">[ERROR] {error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full border-[3px] border-charcoal dark:border-cream bg-charcoal dark:bg-cream text-cream dark:text-charcoal px-8 py-4 font-bold hover:bg-cyan hover:border-cyan hover:text-charcoal transition-colors disabled:opacity-50"
            >
              {loading ? '[CREATING_ACCOUNT...]' : '[> SIGN_UP]'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
