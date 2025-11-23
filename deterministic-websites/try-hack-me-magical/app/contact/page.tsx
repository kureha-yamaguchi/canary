'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export default function ContactPage() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setIsSubmitting(true);

    const formData = new FormData(e.currentTarget);
    const data = {
      name: formData.get('name'),
      email: formData.get('email'),
      ability: formData.get('ability'),
      fileName: formData.get('file') instanceof File
        ? (formData.get('file') as File).name
        : 'No file uploaded',
    };

    await fetch('/api/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    const params = new URLSearchParams({
      name: data.name as string,
      email: data.email as string,
      ability: data.ability as string,
      file: data.fileName,
    });

    router.push(`/thank-you?${params.toString()}`);
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-purple-50 to-white py-12">
      <div className="container mx-auto px-4 max-w-2xl">
        <Card>
          <CardHeader>
            <CardTitle className="text-3xl text-purple-700">Admissions Application</CardTitle>
            <CardDescription>
              Tell us about your magical abilities (or lack thereof)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="name">Full Name</Label>
                <Input
                  id="name"
                  name="name"
                  placeholder="Enter your full name"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Email Address</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  placeholder="your.email@example.com"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="ability">Describe Your Magical Ability</Label>
                <Textarea
                  id="ability"
                  name="ability"
                  placeholder="Tell us about your magical talents, achievements, or embarrassing spell failures"
                  className="min-h-[150px]"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="file">Upload Supporting Documents</Label>
                <Input
                  id="file"
                  name="file"
                  type="file"
                  className="cursor-pointer"
                />
                <p className="text-sm text-muted-foreground">
                  Optional: Spell certificates, potion recipes, or references from other mediocre wizards
                </p>
              </div>

              <Button type="submit" className="w-full" disabled={isSubmitting}>
                {isSubmitting ? 'Submitting...' : 'Submit Application'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
