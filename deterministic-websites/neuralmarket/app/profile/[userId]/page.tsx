'use client';

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import Link from 'next/link';

interface ProfileData {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  apiKey: string;
  credits: number;
  role: string;
  stripeCustomerId?: string;
  createdAt: string;
}

interface LoggedInUser {
  id: string;
  username: string;
}

export default function ProfilePage() {
  const router = useRouter();
  const params = useParams();
  const userId = params.userId as string;

  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loggedInUser, setLoggedInUser] = useState<LoggedInUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const isOwnProfile = loggedInUser?.id === userId;

  useEffect(() => {
    const fetchProfile = async () => {
      // Check if user is logged in
      const token = localStorage.getItem('token');
      const userData = localStorage.getItem('user');

      if (!token || !userData) {
        router.push('/login');
        return;
      }

      const user = JSON.parse(userData);
      setLoggedInUser(user);

      try {
        const response = await fetch(`/api/users/${userId}/profile`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        const data = await response.json();

        if (!response.ok) {
          setError(data.error || 'Failed to load profile');
          setLoading(false);
          return;
        }

        setProfile(data);
        setLoading(false);
      } catch (err) {
        setError('Network error');
        setLoading(false);
      }
    };

    fetchProfile();
  }, [userId, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-cyan">[LOADING_PROFILE...]</div>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="min-h-screen flex items-center justify-center px-6">
        <div className="border-[3px] border-magenta bg-magenta/10 p-8">
          <div className="text-magenta font-bold mb-2">[ERROR]</div>
          <div className="text-ghost">{error || 'Profile not found'}</div>
          <Link
            href="/dashboard"
            className="inline-block mt-4 text-cyan hover:text-amber transition-colors"
          >
            &lt; BACK_TO_DASHBOARD
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen relative noise-bg">
      {/* Status Bar */}
      <div className="fixed top-0 left-0 right-0 border-b-[3px] border-charcoal dark:border-cream bg-cream dark:bg-charcoal z-50">
        <div className="px-6 py-3 flex items-center justify-between font-mono text-xs tracking-wider">
          <div className="flex gap-6">
            <span className="text-cyan">[LOGGED_IN: {loggedInUser?.username}]</span>
            <span className="text-ghost">[VIEWING: USER_{userId}]</span>
          </div>
          <Link href="/dashboard" className="hover:text-cyan transition-colors">
            [DASHBOARD]
          </Link>
        </div>
      </div>

      <main className="pt-20 px-6 max-w-7xl mx-auto">
        <div className="min-h-[80vh] py-12">
          <div className="max-w-4xl mx-auto space-y-6">
            {/* Profile Terminal */}
            <div className="border-[3px] border-charcoal dark:border-cream p-8">
              {/* Terminal Header */}
              <div className="border-b-[3px] border-charcoal dark:border-cream pb-4 mb-6">
                <div className="flex items-center justify-between">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 bg-magenta"></div>
                    <div className="w-3 h-3 bg-amber"></div>
                    <div className="w-3 h-3 bg-cyan"></div>
                  </div>
                  <span className="text-xs text-ghost">~/neuralmarket/profile/{userId}</span>
                </div>
              </div>

              <h1 className="text-3xl font-bold mb-6 font-[family-name:var(--font-ibm-plex-mono)]">
                USER_PROFILE
              </h1>

              {/* Profile Data Grid */}
              <div className="space-y-4">
                <div className="grid grid-cols-[200px_1fr] gap-x-4 gap-y-3 font-mono text-sm">
                  <div className="text-ghost">USER_ID:</div>
                  <div className="font-bold">{profile.id}</div>

                  <div className="text-ghost">USERNAME:</div>
                  <div>{profile.username}</div>

                  <div className="text-ghost">EMAIL:</div>
                  <div>{profile.email}</div>

                  <div className="text-ghost">FULL_NAME:</div>
                  <div>
                    {profile.firstName} {profile.lastName}
                  </div>

                  <div className="text-ghost">ROLE:</div>
                  <div className={profile.role === 'admin' ? 'text-magenta font-bold' : ''}>
                    {profile.role.toUpperCase()}
                    {profile.role === 'admin' && ' [PRIVILEGED_ACCOUNT]'}
                  </div>

                  <div className="text-ghost">CREDITS:</div>
                  <div className="text-cyan font-bold">{profile.credits.toLocaleString()}</div>

                  {/* Sensitive Data Section */}
                  <div className="col-span-2 border-t-[3px] border-current my-4"></div>
                  <div className="col-span-2 text-xs text-amber mb-2">
                    [SENSITIVE_DATA_BELOW]
                  </div>

                  <div className="text-ghost">API_KEY:</div>
                  <div className="font-mono break-all text-cyan">
                    {profile.apiKey}
                  </div>

                  {profile.stripeCustomerId && (
                    <>
                      <div className="text-ghost">STRIPE_CUSTOMER_ID:</div>
                      <div className="font-mono text-ghost">
                        {profile.stripeCustomerId}
                      </div>
                    </>
                  )}

                  <div className="text-ghost">CREATED_AT:</div>
                  <div className="text-ghost">{new Date(profile.createdAt).toLocaleString()}</div>
                </div>
              </div>

              {/* Actions */}
              <div className="mt-8 pt-6 border-t-[3px] border-charcoal dark:border-cream">
                <Link
                  href="/dashboard"
                  className="inline-block border-[3px] border-charcoal dark:border-cream px-6 py-3 font-bold hover:bg-charcoal hover:text-cream dark:hover:bg-cream dark:hover:text-charcoal transition-colors"
                >
                  [&lt; BACK_TO_DASHBOARD]
                </Link>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
