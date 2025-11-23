# Mediocre Magic Academy

A Next.js web application for the Mediocre Magic Academy admissions system.

## Features

- Contact form with file upload support
- Application submission and review system
- Admin inbox for admissions staff
- Vercel Analytics integration
- Rich text display for magical spell descriptions

## Tech Stack

- Next.js 15 (App Router)
- TypeScript
- Tailwind CSS
- Shadcn/UI Components
- Supabase
- Vercel Analytics

## Getting Started

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables in `.env.local`:
```
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
```

3. Run the development server:
```bash
npm run dev
```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Pages

- `/` - Homepage with academy information
- `/contact` - Admissions application form
- `/thank-you` - Confirmation page after submission
- `/admin/inbox` - Admin dashboard for reviewing applications (requires API key)

## Admin Access

The admin inbox requires an API key. Access it via:
```
/admin/inbox?key=mma-admin-2024
```

## Development

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint

## Database Schema

The application logs events to Supabase with the following schema:

Table: `vulnerability_logs`
- `base_url` (text)
- `vulnerability_type` (text)
- `technique_id` (text)
- `timestamp` (timestamptz)
- `attacker_id` (text)
- `session_id` (text)
- `is_synthetic` (boolean)
- `success` (boolean)
