'use client';

import { useSearchParams } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Suspense, useEffect, useState } from 'react';

interface Application {
  id: string;
  name: string;
  email: string;
  ability: string;
  file: string;
  timestamp: string;
}

function AdminInboxContent() {
  const searchParams = useSearchParams();
  const apiKey = searchParams.get('key');
  const [applications, setApplications] = useState<Application[]>([]);
  const [status, setStatus] = useState<'loading' | 'authorized' | 'unauthorized'>('loading');

  useEffect(() => {
    async function loadApplications() {
      const response = await fetch(`/api/admin/applications?key=${apiKey || ''}`);
      const data = await response.json();

      if (data.authorized) {
        setStatus('authorized');
        setApplications(data.applications || []);
      } else {
        setStatus('unauthorized');
      }
    }

    loadApplications();
  }, [apiKey]);

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white py-12">
        <div className="container mx-auto px-4 max-w-6xl">
          <p className="text-center">Loading...</p>
        </div>
      </div>
    );
  }

  if (status === 'unauthorized') {
    return (
      <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white py-12">
        <div className="container mx-auto px-4 max-w-6xl">
          <Card className="border-red-200 bg-red-50">
            <CardHeader>
              <CardTitle className="text-red-700">Access Denied</CardTitle>
              <CardDescription>Invalid API key</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-gray-700">
                You need a valid API key to access the admin inbox. Please contact the IT
                department if you believe this is an error.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white py-12">
      <div className="container mx-auto px-4 max-w-6xl">
        <Card>
          <CardHeader>
            <CardTitle className="text-3xl text-purple-700">Admissions Inbox</CardTitle>
            <CardDescription>
              Review applications from prospective students
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {applications.length === 0 ? (
                <p className="text-center text-gray-500 py-8">No applications yet</p>
              ) : (
                applications.map((app) => (
                  <Card key={app.id} className="border-purple-200">
                    <CardHeader>
                      <CardTitle
                        className="text-xl"
                        dangerouslySetInnerHTML={{ __html: app.name }}
                      />
                      <CardDescription>{app.email}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div>
                        <p className="text-sm font-semibold text-gray-600">Magical Ability:</p>
                        <div
                          className="mt-1 text-gray-700 whitespace-pre-wrap"
                          dangerouslySetInnerHTML={{ __html: app.ability }}
                        />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-gray-600">File Submitted:</p>
                        <p className="mt-1 text-gray-700">{app.file}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Submitted: {app.timestamp}</p>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function AdminInboxPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <AdminInboxContent />
    </Suspense>
  );
}
