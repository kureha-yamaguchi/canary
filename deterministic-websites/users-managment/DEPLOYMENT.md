# Vercel Deployment Guide

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
2. **Supabase Setup**: You need Supabase credentials:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`

## Deployment Methods

### Method 1: Deploy via Vercel Dashboard (Recommended)

1. **Push your code to GitHub** (if not already):
   ```bash
   git add .
   git commit -m "Prepare for Vercel deployment"
   git push origin main
   ```

2. **Import Project in Vercel**:
   - Go to [vercel.com/new](https://vercel.com/new)
   - Click "Import Git Repository"
   - Select your repository
   - Choose the `deterministic-websites/vulnerability-1-sql-injection` directory

3. **Configure Project**:
   - **Framework Preset**: Next.js (auto-detected)
   - **Root Directory**: `deterministic-websites/vulnerability-1-sql-injection`
   - **Build Command**: `npm run build` (default)
   - **Output Directory**: `.next` (default)
   - **Install Command**: `npm install` (default)

4. **Set Environment Variables**:
   - In the Vercel project settings, go to "Environment Variables"
   - Add the following:
     ```
     SUPABASE_URL=your_supabase_url_here
     SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here
     ```
   - Make sure to add them for **Production**, **Preview**, and **Development** environments

5. **Deploy**:
   - Click "Deploy"
   - Wait for the build to complete
   - Your site will be live at `https://your-project.vercel.app`

### Method 2: Deploy via Vercel CLI

1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```

2. **Login to Vercel**:
   ```bash
   vercel login
   ```

3. **Navigate to project directory**:
   ```bash
   cd /Users/shayyahal/canary/deterministic-websites/vulnerability-1-sql-injection
   ```

4. **Deploy**:
   ```bash
   vercel
   ```
   - Follow the prompts
   - When asked for environment variables, add:
     - `SUPABASE_URL`
     - `SUPABASE_SERVICE_ROLE_KEY`

5. **Deploy to Production**:
   ```bash
   vercel --prod
   ```

## Environment Variables Setup

In Vercel Dashboard:
1. Go to your project → Settings → Environment Variables
2. Add:
   - **Name**: `SUPABASE_URL`
   - **Value**: Your Supabase project URL
   - **Environment**: Production, Preview, Development (select all)

3. Add:
   - **Name**: `SUPABASE_SERVICE_ROLE_KEY`
   - **Value**: Your Supabase service role key (keep this secret!)
   - **Environment**: Production, Preview, Development (select all)

## Post-Deployment

1. **Verify Deployment**:
   - Visit your Vercel URL
   - Test the search functionality
   - Try a SQL injection payload: `' OR '1'='1`

2. **Check Logs**:
   - In Vercel Dashboard → Deployments → Click on deployment → View Function Logs
   - Check for any errors

3. **Update Supabase** (if needed):
   - Make sure your Supabase project has the `mock_1_users` table
   - The table should have columns: `username`, `email`, `active`

## Troubleshooting

- **Build Fails**: Check build logs in Vercel dashboard
- **Environment Variables Not Working**: Make sure they're set for the correct environment (Production/Preview/Development)
- **Database Errors**: Verify Supabase credentials and table structure
- **Function Timeout**: Check Vercel function timeout settings (default is 10s for Hobby plan)

## Notes

- The website will work without Supabase (it has fallback data), but logging won't work
- Make sure your Supabase project allows connections from Vercel's IPs
- The service role key has admin access - keep it secure!

