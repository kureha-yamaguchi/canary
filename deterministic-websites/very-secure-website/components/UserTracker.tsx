'use client';

import { useEffect } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

export default function UserTracker() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    // Track page views
    trackEvent('page_view', {
      path: pathname,
      search: searchParams.toString(),
    });
  }, [pathname, searchParams]);

  useEffect(() => {
    // Single event listener for ALL interactions
    const trackInteraction = (e: Event) => {
      const target = e.target as HTMLElement;

      // Get element details
      const data: any = {
        type: e.type,
        tagName: target.tagName,
        id: target.id,
        className: target.className,
        text: target.textContent?.slice(0, 100), // First 100 chars
        timestamp: Date.now(),
        path: pathname,
      };

      // Capture data attributes (for custom tracking)
      Object.keys(target.dataset).forEach(key => {
        data[`data_${key}`] = target.dataset[key];
      });

      // Form-specific data
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
        data.inputType = (target as HTMLInputElement).type;
        data.inputName = (target as HTMLInputElement).name;
        // Don't log actual values for privacy
      }

      // Button/link specific
      if (target.tagName === 'BUTTON' || target.tagName === 'A') {
        data.href = (target as HTMLAnchorElement).href;
      }

      trackEvent(`user_${e.type}`, data);
    };

    // Listen to multiple event types
    const events = ['click', 'submit', 'change', 'focus', 'input'];
    events.forEach(eventType => {
      document.addEventListener(eventType, trackInteraction, true);
    });

    // Track mouse movement (sampled)
    let lastMouseTrack = 0;
    const trackMouse = (e: MouseEvent) => {
      const now = Date.now();
      if (now - lastMouseTrack > 1000) { // Sample every second
        trackEvent('mouse_position', {
          x: e.clientX,
          y: e.clientY,
          path: pathname,
        });
        lastMouseTrack = now;
      }
    };
    document.addEventListener('mousemove', trackMouse);

    // Track scroll depth
    let maxScroll = 0;
    const trackScroll = () => {
      const scrollHeight = document.body.scrollHeight - window.innerHeight;
      if (scrollHeight <= 0) return; // Avoid division by zero

      const scrollPercent = Math.round(
        (window.scrollY / scrollHeight) * 100
      );
      if (scrollPercent > maxScroll) {
        maxScroll = scrollPercent;
        trackEvent('scroll_depth', { depth: scrollPercent, path: pathname });
      }
    };
    window.addEventListener('scroll', trackScroll);

    // Cleanup
    return () => {
      events.forEach(eventType => {
        document.removeEventListener(eventType, trackInteraction, true);
      });
      document.removeEventListener('mousemove', trackMouse);
      window.removeEventListener('scroll', trackScroll);
    };
  }, [pathname]);

  return null;
}

// Helper to send events to Supabase
async function trackEvent(event: string, data: any) {
  try {
    await fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event,
        data,
        session_id: getSessionId(),
        user_id: getUserId(), // If you have auth
        timestamp: new Date().toISOString(),
      }),
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
