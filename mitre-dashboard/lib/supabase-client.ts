import { createClient } from '@supabase/supabase-js'

// Client-side Supabase client (uses service role key for now - TODO: move to API routes)
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_KEY!

export const supabaseClient = createClient(supabaseUrl, supabaseKey)
