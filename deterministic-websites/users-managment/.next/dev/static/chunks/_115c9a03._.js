(globalThis.TURBOPACK || (globalThis.TURBOPACK = [])).push([typeof document === "object" ? document.currentScript : undefined,
"[project]/components/UserTracker.tsx [app-client] (ecmascript)", ((__turbopack_context__) => {
"use strict";

__turbopack_context__.s([
    "default",
    ()=>UserTracker
]);
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/dist/compiled/react/index.js [app-client] (ecmascript)");
var __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__ = __turbopack_context__.i("[project]/node_modules/next/navigation.js [app-client] (ecmascript)");
var _s = __turbopack_context__.k.signature();
'use client';
;
;
function UserTracker() {
    _s();
    const pathname = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["usePathname"])();
    const searchParams = (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useSearchParams"])();
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "UserTracker.useEffect": ()=>{
            // Track page views
            trackEvent('page_view', {
                path: pathname,
                search: searchParams.toString()
            });
        }
    }["UserTracker.useEffect"], [
        pathname,
        searchParams
    ]);
    (0, __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$dist$2f$compiled$2f$react$2f$index$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useEffect"])({
        "UserTracker.useEffect": ()=>{
            // Single event listener for ALL interactions
            const trackInteraction = {
                "UserTracker.useEffect.trackInteraction": (e)=>{
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
                    Object.keys(target.dataset).forEach({
                        "UserTracker.useEffect.trackInteraction": (key)=>{
                            data[`data_${key}`] = target.dataset[key];
                        }
                    }["UserTracker.useEffect.trackInteraction"]);
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
                }
            }["UserTracker.useEffect.trackInteraction"];
            // Listen to multiple event types
            const events = [
                'click',
                'submit',
                'change',
                'focus',
                'input'
            ];
            events.forEach({
                "UserTracker.useEffect": (eventType)=>{
                    document.addEventListener(eventType, trackInteraction, true);
                }
            }["UserTracker.useEffect"]);
            // Track mouse movement (sampled)
            let lastMouseTrack = 0;
            const trackMouse = {
                "UserTracker.useEffect.trackMouse": (e)=>{
                    const now = Date.now();
                    if (now - lastMouseTrack > 1000) {
                        trackEvent('mouse_position', {
                            x: e.clientX,
                            y: e.clientY,
                            path: pathname
                        });
                        lastMouseTrack = now;
                    }
                }
            }["UserTracker.useEffect.trackMouse"];
            document.addEventListener('mousemove', trackMouse);
            // Track scroll depth
            let maxScroll = 0;
            const trackScroll = {
                "UserTracker.useEffect.trackScroll": ()=>{
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
                }
            }["UserTracker.useEffect.trackScroll"];
            window.addEventListener('scroll', trackScroll);
            // Cleanup
            return ({
                "UserTracker.useEffect": ()=>{
                    events.forEach({
                        "UserTracker.useEffect": (eventType)=>{
                            document.removeEventListener(eventType, trackInteraction, true);
                        }
                    }["UserTracker.useEffect"]);
                    document.removeEventListener('mousemove', trackMouse);
                    window.removeEventListener('scroll', trackScroll);
                }
            })["UserTracker.useEffect"];
        }
    }["UserTracker.useEffect"], [
        pathname
    ]);
    return null;
}
_s(UserTracker, "jq/6JV7jSw8H7h1siyRMT4JsAUQ=", false, function() {
    return [
        __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["usePathname"],
        __TURBOPACK__imported__module__$5b$project$5d2f$node_modules$2f$next$2f$navigation$2e$js__$5b$app$2d$client$5d$__$28$ecmascript$29$__["useSearchParams"]
    ];
});
_c = UserTracker;
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
var _c;
__turbopack_context__.k.register(_c, "UserTracker");
if (typeof globalThis.$RefreshHelpers$ === 'object' && globalThis.$RefreshHelpers !== null) {
    __turbopack_context__.k.registerExports(__turbopack_context__.m, globalThis.$RefreshHelpers$);
}
}),
"[project]/node_modules/next/navigation.js [app-client] (ecmascript)", ((__turbopack_context__, module, exports) => {

module.exports = __turbopack_context__.r("[project]/node_modules/next/dist/client/components/navigation.js [app-client] (ecmascript)");
}),
]);

//# sourceMappingURL=_115c9a03._.js.map