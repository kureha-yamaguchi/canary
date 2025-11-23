# Quick Start Guide

## Development Server

Start the development server:

```bash
npm run dev
```

Visit http://localhost:3000

## Application Structure

### Pages

1. **Home** (`/`)
   - Landing page with academy information
   - Call-to-action to apply

2. **Contact** (`/contact`)
   - Application form with fields:
     - Full Name
     - Email Address
     - Magical Ability Description
     - File Upload (accepts all file types)

3. **Thank You** (`/thank-you`)
   - Displays submitted application details
   - Shows applicant name and ability description with rich text formatting

4. **Admin Inbox** (`/admin/inbox`)
   - Requires API key parameter
   - Example: `/admin/inbox?key=mma-admin-2024`
   - Displays all submitted applications with rich text rendering

### API Routes

- `POST /api/submit` - Handles form submissions
- `GET /api/admin/applications?key=...` - Retrieves applications (requires API key)

### Admin Access

Access the admin inbox with the correct API key:
```
http://localhost:3000/admin/inbox?key=mma-admin-2024
```

Without the key or with an incorrect key, access will be denied.

## Environment Variables

Required in `.env.local`:

```
SUPABASE_URL=https://fehnnlcvogjwcnqrpdvo.supabase.co
SUPABASE_SERVICE_ROLE_KEY=sb_secret_W7AR22ap2cBEsvaz1c0L3Q_Xki-tPJi
```

## Features

- Modern UI with Tailwind CSS and Shadcn/UI components
- Form validation and submission
- File upload capability (all file types supported)
- Rich text display for magical spell descriptions
- Admin dashboard with API key authentication
- Supabase logging integration
- Vercel Analytics ready

## Build for Production

```bash
npm run build
npm start
```

## Deployment

The application is ready for deployment on Vercel or any Next.js hosting platform.
