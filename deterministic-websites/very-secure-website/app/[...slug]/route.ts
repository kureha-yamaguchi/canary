import { NextResponse } from 'next/server';

// Catch-all route for any /* requests
export async function GET() {
  return NextResponse.json({ success: true }, { status: 200 });
}

export async function POST() {
  return NextResponse.json({ success: true }, { status: 200 });
}

export async function PUT() {
  return NextResponse.json({ success: true }, { status: 200 });
}

export async function PATCH() {
  return NextResponse.json({ success: true }, { status: 200 });
}

export async function DELETE() {
  return NextResponse.json({ success: true }, { status: 200 });
}
