import { NextResponse } from 'next/server';
import { checkApiKey, logHoneypotTrigger } from '@/lib/honeypot-utils';

// Catch-all route for any /api/* requests
export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  const result = checkApiKey(request.headers);
  const path = '/api/' + slug.join('/');

  logHoneypotTrigger(result, request, path);

  if (result.status === 'correct') {
    return NextResponse.json(
      {
        success: true,
        path: path,
        authenticated: true,
        data: {
          success: true,
          endpoint: path,
        },
      },
      { status: 200 }
    );
  }

  if (result.status === 'wrong') {
    return NextResponse.json(
      {
        success: false,
        path: path,
        error: 'Invalid API key',
      },
      { status: 401 }
    );
  }

  return NextResponse.json(
    {
      error: 'Unauthorized',
      message: 'API key required',
      path: path,
    },
    { status: 401 }
  );
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  const { slug } = await params;
  const result = checkApiKey(request.headers);
  const path = '/api/' + slug.join('/');

  logHoneypotTrigger(result, request, path);

  if (result.status === 'correct') {
    return NextResponse.json(
      {
        success: true,
        path: path,
        data: {
          created: true,
          id: 'resource_' + Date.now(),
        },
      },
      { status: 201 }
    );
  }

  if (result.status === 'wrong') {
    return NextResponse.json(
      {
        success: false,
        path: path,
        error: 'Invalid API key',
      },
      { status: 401 }
    );
  }

  return NextResponse.json(
    {
      error: 'Unauthorized',
      message: 'API key required',
      path: path,
    },
    { status: 401 }
  );
}

// Also handle PUT, PATCH, DELETE
export async function PUT(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params, 'PUT');
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params, 'PATCH');
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ slug: string[] }> }
) {
  return handleGenericRequest(request, params, 'DELETE');
}

async function handleGenericRequest(
  request: Request,
  params: Promise<{ slug: string[] }>,
  method: string
) {
  const { slug } = await params;
  const result = checkApiKey(request.headers);
  const path = '/api/' + slug.join('/');

  logHoneypotTrigger(result, request, path);

  if (result.status === 'correct') {
    return NextResponse.json(
      {
        success: true,
        path: path,
        method,
      },
      { status: 200 }
    );
  }

  if (result.status === 'wrong') {
    return NextResponse.json(
      {
        success: false,
        path: path,
        method,
        error: 'Invalid API key',
      },
      { status: 401 }
    );
  }

  return NextResponse.json(
    {
      error: 'Unauthorized',
      message: 'API key required',
      path: path,
    },
    { status: 401 }
  );
}

