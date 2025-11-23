'use client';

import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Suspense } from 'react';

function ThankYouContent() {
  const searchParams = useSearchParams();
  const name = searchParams.get('name') || '';
  const email = searchParams.get('email') || '';
  const ability = searchParams.get('ability') || '';
  const file = searchParams.get('file') || '';

  return (
    <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white py-12">
      <div className="container mx-auto px-4 max-w-3xl">
        <Card>
          <CardHeader>
            <CardTitle className="text-3xl text-purple-700">Application Received!</CardTitle>
            <CardDescription>
              Thank you for applying to Mediocre Magic Academy
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="bg-purple-50 p-6 rounded-lg">
              <h3 className="font-semibold text-lg mb-4">Application Summary</h3>

              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600">Applicant Name</p>
                  <div
                    className="text-lg font-medium mt-1"
                    dangerouslySetInnerHTML={{ __html: name }}
                  />
                </div>

                <div>
                  <p className="text-sm text-gray-600">Email Address</p>
                  <p className="text-lg font-medium mt-1">{email}</p>
                </div>

                <div>
                  <p className="text-sm text-gray-600">Magical Ability Description</p>
                  <div
                    className="text-base mt-1 whitespace-pre-wrap"
                    dangerouslySetInnerHTML={{ __html: ability }}
                  />
                </div>

                <div>
                  <p className="text-sm text-gray-600">Uploaded File</p>
                  <p className="text-base mt-1">{file}</p>
                </div>
              </div>
            </div>

            <div className="bg-blue-50 p-4 rounded-lg">
              <h4 className="font-semibold mb-2">What Happens Next?</h4>
              <ul className="list-disc list-inside space-y-1 text-gray-700">
                <li>Our admissions team will review your application within 3-5 business days</li>
                <li>You&apos;ll receive an email notification of our decision</li>
                <li>If accepted, you&apos;ll get access to our student portal</li>
                <li>Orientation begins on the first Monday of each month</li>
              </ul>
            </div>

            <div className="flex gap-4">
              <Link href="/">
                <Button variant="outline">Return Home</Button>
              </Link>
              <Link href="/contact">
                <Button variant="secondary">Submit Another Application</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default function ThankYouPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ThankYouContent />
    </Suspense>
  );
}
