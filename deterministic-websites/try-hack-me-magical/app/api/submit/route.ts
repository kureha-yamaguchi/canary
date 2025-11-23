import { NextRequest } from 'next/server';
import { logHoneypotTrigger } from '@/lib/honeypot';

const APPLICATIONS_STORAGE: Array<{
  id: string;
  name: string;
  email: string;
  ability: string;
  file: string;
  timestamp: string;
}> = [];

export async function POST(request: NextRequest) {
  const body = await request.json();

  const application = {
    id: Math.random().toString(36).substring(7),
    name: body.name,
    email: body.email,
    ability: body.ability,
    file: body.fileName,
    timestamp: new Date().toISOString(),
  };

  APPLICATIONS_STORAGE.push(application);

  return logHoneypotTrigger(request, 'none');
}

export async function GET() {
  return Response.json({ applications: APPLICATIONS_STORAGE });
}
