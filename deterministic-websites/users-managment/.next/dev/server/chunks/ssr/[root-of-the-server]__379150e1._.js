module.exports = [
"[externals]/next/dist/compiled/next-server/app-page-turbo.runtime.dev.js [external] (next/dist/compiled/next-server/app-page-turbo.runtime.dev.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js", () => require("next/dist/compiled/next-server/app-page-turbo.runtime.dev.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/action-async-storage.external.js [external] (next/dist/server/app-render/action-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/action-async-storage.external.js", () => require("next/dist/server/app-render/action-async-storage.external.js"));

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
"[project]/components/UserTracker.tsx [app-ssr] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>UserTracker
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/server/route-modules/app-page/vendored/ssr/react.js [app-ssr] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/navigation.js [app-ssr] (ecmascript)");
'use client';
;
;
function UserTracker() {
    const pathname = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["usePathname"])();
    const searchParams = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useSearchParams"])();
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        // Track page views
        trackEvent('page_view', {
            path: pathname,
            search: searchParams.toString()
        });
    }, [
        pathname,
        searchParams
    ]);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$server$2f$route$2d$modules$2f$app$2d$page$2f$vendored$2f$ssr$2f$react$2e$js__$5b$app$2d$ssr$5d$__$28$ecmascript$29$__["useEffect"])(()=>{
        // Single event listener for ALL interactions
        const trackInteraction = (e)=>{
            const target = e.target;
            // Get element details
            const data = {
                type: e.type,
                tagName: target.tagName,
                id: target.id,
                className: target.className,
                text: target.textContent?.slice(0, 100),
                timestamp: Date.now(),
                path: pathname
            };
            // Capture data attributes (for custom tracking)
            Object.keys(target.dataset).forEach((key)=>{
                data[`data_${key}`] = target.dataset[key];
            });
            // Form-specific data
            if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
                data.inputType = target.type;
                data.inputName = target.name;
            // Don't log actual values for privacy
            }
            // Button/link specific
            if (target.tagName === 'BUTTON' || target.tagName === 'A') {
                data.href = target.href;
            }
            trackEvent(`user_${e.type}`, data);
        };
        // Listen to multiple event types
        const events = [
            'click',
            'submit',
            'change',
            'focus',
            'input'
        ];
        events.forEach((eventType)=>{
            document.addEventListener(eventType, trackInteraction, true);
        });
        // Track mouse movement (sampled)
        let lastMouseTrack = 0;
        const trackMouse = (e)=>{
            const now = Date.now();
            if (now - lastMouseTrack > 1000) {
                trackEvent('mouse_position', {
                    x: e.clientX,
                    y: e.clientY,
                    path: pathname
                });
                lastMouseTrack = now;
            }
        };
        document.addEventListener('mousemove', trackMouse);
        // Track scroll depth
        let maxScroll = 0;
        const trackScroll = ()=>{
            const scrollHeight = document.body.scrollHeight - window.innerHeight;
            if (scrollHeight <= 0) return; // Avoid division by zero
            const scrollPercent = Math.round(window.scrollY / scrollHeight * 100);
            if (scrollPercent > maxScroll) {
                maxScroll = scrollPercent;
                trackEvent('scroll_depth', {
                    depth: scrollPercent,
                    path: pathname
                });
            }
        };
        window.addEventListener('scroll', trackScroll);
        // Cleanup
        return ()=>{
            events.forEach((eventType)=>{
                document.removeEventListener(eventType, trackInteraction, true);
            });
            document.removeEventListener('mousemove', trackMouse);
            window.removeEventListener('scroll', trackScroll);
        };
    }, [
        pathname
    ]);
    return null;
}
// Helper to send events to Supabase
async function trackEvent(event, data) {
    try {
        await fetch('/api/track', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                event,
                data,
                session_id: getSessionId(),
                user_id: getUserId(),
                timestamp: new Date().toISOString()
            })
        });
    } catch (error) {
        console.error('Tracking failed:', error);
    }
}
function getSessionId() {
    let sessionId = sessionStorage.getItem('session_id');
    if (!sessionId) {
        sessionId = crypto.randomUUID();
        sessionStorage.setItem('session_id', sessionId);
    }
    return sessionId;
}
function getUserId() {
    // Get from localStorage if user is logged in
    return localStorage.getItem('user_id') || null;
}
}),
"[externals]/next/dist/server/app-render/after-task-async-storage.external.js [external] (next/dist/server/app-render/after-task-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/after-task-async-storage.external.js", () => require("next/dist/server/app-render/after-task-async-storage.external.js"));

module.exports = mod;
}),
"[externals]/next/dist/server/app-render/dynamic-access-async-storage.external.js [external] (next/dist/server/app-render/dynamic-access-async-storage.external.js, cjs)", ((__turbopack_context__, module, exports) => {

const mod = __turbopack_context__.x("next/dist/server/app-render/dynamic-access-async-storage.external.js", () => require("next/dist/server/app-render/dynamic-access-async-storage.external.js"));

module.exports = mod;
}),
];

//# sourceMappingURL=%5Broot-of-the-server%5D__379150e1._.js.map