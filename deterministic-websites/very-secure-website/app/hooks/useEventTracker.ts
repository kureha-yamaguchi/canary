'use client';

import { useCallback, useEffect, useRef } from 'react';

interface TrackEventOptions {
  event_type: string;
  event_category: string;
  element_id?: string;
  element_class?: string;
  element_text?: string;
  scroll_depth?: number;
  click_x?: number;
  click_y?: number;
  metadata?: Record<string, any>;
}

export function useEventTracker() {
  const sessionIdRef = useRef<string>('');

  // Initialize session ID
  useEffect(() => {
    if (typeof window !== 'undefined') {
      let sessionId = sessionStorage.getItem('analytics_session_id');
      if (!sessionId) {
        sessionId = crypto.randomUUID();
        sessionStorage.setItem('analytics_session_id', sessionId);
      }
      sessionIdRef.current = sessionId;
    }
  }, []);

  const trackEvent = useCallback(async (options: TrackEventOptions) => {
    if (typeof window === 'undefined') return;

    try {
      // Calculate current scroll depth for all events
      const windowHeight = window.innerHeight;
      const documentHeight = document.documentElement.scrollHeight;
      const scrollTop = window.scrollY;
      const currentScrollDepth = Math.round(
        ((scrollTop + windowHeight) / documentHeight) * 100
      );

      const payload = {
        session_id: sessionIdRef.current,
        page_url: window.location.href,
        page_path: window.location.pathname,
        viewport_width: window.innerWidth,
        viewport_height: window.innerHeight,
        timestamp: new Date().toISOString(),
        scroll_depth: currentScrollDepth, // Always include current scroll position
        ...options, // This will override scroll_depth for actual scroll events
      };

      // Use sendBeacon for reliability (doesn't wait for response)
      if (navigator.sendBeacon) {
        const blob = new Blob([JSON.stringify(payload)], {
          type: 'application/json'
        });
        navigator.sendBeacon('/api/analytics/track', blob);
      } else {
        // Fallback to fetch
        fetch('/api/analytics/track', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          keepalive: true,
        }).catch(err => console.error('Failed to track event:', err));
      }
    } catch (error) {
      console.error('Error tracking event:', error);
    }
  }, []);

  return { trackEvent };
}