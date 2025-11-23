module.exports = [
"[externals]/next/dist/compiled/next-server/app-route-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-route-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-route-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/@opentelemetry/api [external] (next/dist/compiled/@opentelemetry/api, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/@opentelemetry/api", () => require("next/dist/compiled/@opentelemetry/api"));

module.exports = mod;
}),
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-unit-async-storage.external.js [external] (next/dist/server/app-render/work-unit-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-unit-async-storage.external.js", () => require("next/dist/server/app-render/work-unit-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/work-async-storage.external.js [external] (next/dist/server/app-render/work-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/work-async-storage.external.js", () => require("next/dist/server/app-render/work-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/shared/lib/no-fallback-error.external.js [external] (next/dist/shared/lib/no-fallback-error.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/shared/lib/no-fallback-error.external.js", () => require("next/dist/shared/lib/no-fallback-error.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}),
"[project]/lib/honeypot-config.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

// Honeypot configuration
__turbopack_context__.s([
    "HONEYPOT_CONFIG",
    ()=>HONEYPOT_CONFIG
]);
const HONEYPOT_CONFIG = {
    // Table name in Supabase for SQL Injection Honeypot (Vulnerability ID 1)
    tableName: 'mock_1_users'
};
}),
"[project]/lib/supabase.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "supabase",
    ()=>supabase
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$supabase$2f$supabase$2d$js$2f$dist$2f$module$2f$index$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__$3c$locals$3e$__ = __turbopack_context__.i("[project]/node_modules/@supabase/supabase-js/dist/module/index.js [app-route] (ecmascript) <locals>");
;
// Server-side only - no NEXT_PUBLIC prefix
// Use service role key for server-side operations that bypass RLS
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = supabaseUrl && supabaseServiceKey ? (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f40$supabase$2f$supabase$2d$js$2f$dist$2f$module$2f$index$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__$3c$locals$3e$__["createClient"])(supabaseUrl, supabaseServiceKey) : null;
}),
"[project]/lib/honeypot-utils.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "checkSqlInjection",
    ()=>checkSqlInjection,
    "logSqlInjectionAttempt",
    ()=>logSqlInjectionAttempt
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/lib/honeypot-config.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/lib/supabase.ts [app-route] (ecmascript)");
;
;
function checkSqlInjection(input) {
    const payload = input.trim();
    // SQL injection patterns to detect
    const sqlInjectionPatterns = [
        /(['"`])\s*(OR|AND)\s*\1\s*=\s*\1/i,
        /(['"`])\s*(OR|AND)\s*\1\s*=\s*\1\s*--/i,
        /(['"`])\s*;\s*DROP\s+TABLE/i,
        /UNION\s+SELECT/i,
        /OR\s+1\s*=\s*1/i,
        /OR\s+1\s*=\s*1\s*--/i,
        /'\s*OR\s*'1'\s*=\s*'1/i,
        /'\s*OR\s*'1'\s*=\s*'1'\s*--/i,
        /\/\*.*\*\//,
        /--\s/,
        /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i,
        /xp_\w+/i,
        /EXEC\s*\(/i,
        /sp_\w+/i
    ];
    // Check for SQL injection patterns
    for (const pattern of sqlInjectionPatterns){
        if (pattern.test(payload)) {
            // Simulate the vulnerable SQL query (for logging purposes)
            const vulnerableQuery = `SELECT * FROM ${__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["HONEYPOT_CONFIG"].tableName} WHERE username = '${payload}' AND password = '...'`;
            return {
                status: 'injection_detected',
                payload,
                query: vulnerableQuery
            };
        }
    }
    // Check for suspicious patterns (less definitive)
    const suspiciousPatterns = [
        /['"`]/,
        /[;|&]/,
        /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i
    ];
    let suspiciousCount = 0;
    for (const pattern of suspiciousPatterns){
        if (pattern.test(payload)) {
            suspiciousCount++;
        }
    }
    if (suspiciousCount >= 2) {
        return {
            status: 'suspicious',
            payload,
            reason: 'Multiple suspicious patterns detected'
        };
    }
    return {
        status: 'normal',
        payload
    };
}
/**
 * Map vulnerability types to MITRE ATT&CK technique IDs
 * 
 * This honeypot exposes Vulnerability ID 1: "SQL Injection"
 * See docs/vulnerability-mapping.txt for complete mapping details.
 * 
 * MITRE ATT&CK Technique Mappings:
 * - T1190: Exploit Public-Facing Application - SQL injection attacks
 */ function getTechniqueId(vulnerabilityType) {
    // T1190: Exploit Public-Facing Application - SQL injection through user input
    return 'T1190';
}
/**
 * Generate a session ID from request headers
 */ function getSessionId(request) {
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    const timestamp = Date.now();
    return `${ip.split(',')[0]}_${timestamp}`;
}
async function logSqlInjectionAttempt(result, request, route) {
    // Only log when SQL injection is actually detected
    if (result.status !== 'injection_detected') {
        console.log(`[Honeypot] Skipping log for status: ${result.status} (only logging injection_detected)`);
        return;
    }
    const url = new URL(request.url);
    // Use consistent vulnerability type for SQL injection
    const vulnerabilityType = 'SQL_INJECTION';
    // Extract attacker_id (IP address or other identifier)
    const attackerId = request.headers.get('x-forwarded-for')?.split(',')[0] || request.headers.get('x-real-ip') || 'unknown';
    // Get session ID for tracking
    const sessionId = getSessionId(request);
    // Get appropriate MITRE ATT&CK technique ID
    const techniqueId = getTechniqueId(vulnerabilityType);
    // Build the path (include route if provided, otherwise use URL pathname)
    const path = route || url.pathname;
    const payload = {
        base_url: url.origin,
        path: path,
        vulnerability_type: vulnerabilityType,
        technique_id: techniqueId,
        attacker_id: attackerId,
        session_id: sessionId
    };
    console.log('[Honeypot] Attempting to log SQL injection to vulnerability_logs:', {
        ...payload,
        sql_payload: result.payload,
        vulnerable_query: result.query
    });
    // Check if Supabase is configured
    if (!__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"]) {
        console.warn('[Honeypot] Supabase not configured - skipping database log. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.local');
        return;
    }
    try {
        // First, ensure the technique exists in the techniques table
        // This handles the foreign key constraint requirement
        const { error: techniqueError } = await __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('techniques').upsert({
            technique_id: techniqueId,
            name: 'Exploit Public-Facing Application',
            description: 'Attackers exploit vulnerabilities in internet-facing web servers, including SQL injection attacks',
            domain: 'enterprise'
        }, {
            onConflict: 'technique_id',
            ignoreDuplicates: false
        });
        if (techniqueError) {
            console.warn('[Honeypot] Could not ensure technique exists (may already exist):', techniqueError);
        // Continue anyway - the technique might already exist
        }
        // Try inserting with path first
        let insertPayload = payload;
        let { data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('vulnerability_logs').insert(insertPayload);
        // If error is due to path column not existing, try without it
        if (error && (error.code === 'PGRST116' || error.message?.includes('column') || error.message?.includes('path'))) {
            console.warn('[Honeypot] Retrying insert without path field (column may not exist)');
            const { path, ...payloadWithoutPath } = payload;
            insertPayload = payloadWithoutPath;
            ({ data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from('vulnerability_logs').insert(insertPayload));
        }
        if (error) {
            console.error('[Honeypot] Failed to log SQL injection to Supabase:');
            console.error('[Honeypot] Error code:', error.code);
            console.error('[Honeypot] Error message:', error.message);
            console.error('[Honeypot] Error details:', error.details);
            console.error('[Honeypot] Error hint:', error.hint);
            console.error('[Honeypot] Payload attempted:', JSON.stringify(insertPayload, null, 2));
            console.error('[Honeypot] Full error:', JSON.stringify(error, null, 2));
        } else {
            console.log('[Honeypot] ✅ Successfully logged SQL injection to vulnerability_logs table');
            console.log('[Honeypot] Log ID:', data?.[0]?.id || 'unknown');
            console.log('[Honeypot] Logged data:', JSON.stringify(data, null, 2));
        }
    } catch (err) {
        console.error('[Honeypot] Exception while logging SQL injection:', err);
        if (err instanceof Error) {
            console.error('[Honeypot] Exception message:', err.message);
            console.error('[Honeypot] Exception stack:', err.stack);
        }
    }
}
}),
"[project]/app/api/search/route.ts [app-route] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "POST",
    ()=>POST
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/server.js [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$utils$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/lib/honeypot-utils.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/lib/supabase.ts [app-route] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/lib/honeypot-config.ts [app-route] (ecmascript)");
;
;
;
;
async function POST(request) {
    try {
        const body = await request.json();
        const username = body.username || '';
        // Check for SQL injection attempts
        const injectionCheck = (0, __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$utils$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["checkSqlInjection"])(username);
        // Debug logging
        console.log('[Honeypot] SQL Injection check result:', {
            status: injectionCheck.status,
            payload: injectionCheck.payload,
            detected: injectionCheck.status === 'injection_detected'
        });
        // Log the attempt to Supabase (only logs when injection_detected)
        await (0, __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$utils$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["logSqlInjectionAttempt"])(injectionCheck, request, '/api/search');
        // VULNERABLE CODE: Direct string concatenation into SQL query
        // This is the vulnerability - user input is not sanitized or parameterized
        // NOTE: We show the vulnerable query pattern, but execute safely using Supabase
        const vulnerableQuery = `SELECT * FROM ${__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["HONEYPOT_CONFIG"].tableName} WHERE username = '${username}' AND active = 1`;
        // Actually query the database using Supabase (safely with parameterized queries)
        // This demonstrates what the vulnerable query would look like, but executes safely
        let dbResults = [];
        if (__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"]) {
            try {
                // Use Supabase's safe query method (parameterized) to actually get data
                // This simulates what would happen if the vulnerable query was executed
                const { data, error } = await __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from(__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["HONEYPOT_CONFIG"].tableName).select('username, email, active').eq('username', username).eq('active', true);
                if (!error && data) {
                    dbResults = data;
                }
                // If SQL injection is detected, also return all active users to show impact
                if (injectionCheck.status === 'injection_detected') {
                    const { data: allUsers } = await __TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$supabase$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["supabase"].from(__TURBOPACK__imported__module__$5b$project$5d2f$lib$2f$honeypot$2d$config$2e$ts__$5b$app$2d$route$5d$__$28$ecmascript$29$__["HONEYPOT_CONFIG"].tableName).select('username, email, active').eq('active', true).limit(10);
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
                    {
                        username: 'admin',
                        email: 'admin@example.com',
                        active: true
                    },
                    {
                        username: 'user1',
                        email: 'user1@example.com',
                        active: true
                    },
                    {
                        username: 'user2',
                        email: 'user2@example.com',
                        active: true
                    }
                ];
            } else if (username.toLowerCase() === 'admin' || username.toLowerCase() === 'test') {
                dbResults = [
                    {
                        username,
                        email: `${username}@example.com`,
                        active: true
                    }
                ];
            }
        }
        // Format response
        const response = {
            success: true,
            query: vulnerableQuery,
            results: dbResults.map((user)=>({
                    username: user.username,
                    email: user.email
                }))
        };
        if (injectionCheck.status === 'injection_detected') {
            response.warning = 'SQL injection attempt detected and logged';
            if (dbResults.length > 0) {
                response.note = `SQL injection successful - returned ${dbResults.length} records (would normally return all records)`;
            }
        }
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json(response);
    } catch (error) {
        console.error('Search error:', error);
        return __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$server$2e$js__$5b$app$2d$route$5d$__$28$ecmascript$29$__["NextResponse"].json({
            error: 'An error occurred while searching',
            details: error instanceof Error ? error.message : 'Unknown error'
        }, {
            status: 500
        });
    }
}
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__6fe1e3f8._.js.map