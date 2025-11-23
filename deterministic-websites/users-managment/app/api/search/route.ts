import { NextResponse } from 'next/server';
import { checkSqlInjection, logSqlInjectionAttempt } from '@/lib/honeypot-utils';
import { supabase } from '@/lib/supabase';
import { HONEYPOT_CONFIG } from '@/lib/honeypot-config';

/**
 * VULNERABLE API ENDPOINT - SQL Injection Honeypot
 * 
 * This endpoint is intentionally vulnerable to SQL injection.
 * User input is directly concatenated into a SQL query without sanitization.
 * 
 * DO NOT USE THIS PATTERN IN PRODUCTION CODE!
 */
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const username = body.username || '';

    // Check for SQL injection attempts
    const injectionCheck = checkSqlInjection(username);
    
    // Debug logging
    console.log('[Honeypot] SQL Injection check result:', {
      status: injectionCheck.status,
      payload: injectionCheck.payload,
      detected: injectionCheck.status === 'injection_detected',
    });

    // Log the attempt to Supabase (only logs when injection_detected)
    await logSqlInjectionAttempt(injectionCheck, request, '/api/search');

    // VULNERABLE CODE: Direct string concatenation into SQL query
    // This is the vulnerability - user input is not sanitized or parameterized
    // NOTE: We show the vulnerable query pattern, but execute safely using Supabase
    const vulnerableQuery = `SELECT * FROM ${HONEYPOT_CONFIG.tableName} WHERE username = '${username}' AND active = 1`;

    // Actually query the database using Supabase (safely with parameterized queries)
    // This demonstrates what the vulnerable query would look like, but executes safely
    let dbResults: any[] = [];
    
    if (supabase) {
      try {
        // Use Supabase's safe query method (parameterized) to actually get data
        // This simulates what would happen if the vulnerable query was executed
        const { data, error } = await supabase
          .from(HONEYPOT_CONFIG.tableName)
          .select('username, email, active')
          .eq('username', username)
          .eq('active', true);

        if (!error && data) {
          dbResults = data;
        }

        // If SQL injection is detected, also return all active users to show impact
        if (injectionCheck.status === 'injection_detected') {
          const { data: allUsers } = await supabase
            .from(HONEYPOT_CONFIG.tableName)
            .select('username, email, active')
            .eq('active', true)
            .limit(10);

          if (allUsers) {
            dbResults = allUsers;
          }
        }
      } catch (dbError) {
        console.error('[Honeypot] Database query error:', dbError);
      }
    } else {
      // Fallback if Supabase not configured
      if (injectionCheck.status === 'injection_detected') {
        dbResults = [
          { username: 'admin', email: 'admin@example.com', active: true },
          { username: 'user1', email: 'user1@example.com', active: true },
          { username: 'user2', email: 'user2@example.com', active: true },
        ];
      } else if (username.toLowerCase() === 'admin' || username.toLowerCase() === 'test') {
        dbResults = [{ username, email: `${username}@example.com`, active: true }];
      }
    }

    // Format response
    const response: any = {
      success: true,
      query: vulnerableQuery,
      results: dbResults.map((user: any) => ({
        username: user.username,
        email: user.email,
      })),
    };

    if (injectionCheck.status === 'injection_detected') {
      response.warning = 'SQL injection attempt detected and logged';
      if (dbResults.length > 0) {
        response.note = `SQL injection successful - returned ${dbResults.length} records (would normally return all records)`;
      }
    }

    return NextResponse.json(response);
  } catch (error) {
    console.error('Search error:', error);
    return NextResponse.json(
      {
        error: 'An error occurred while searching',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

