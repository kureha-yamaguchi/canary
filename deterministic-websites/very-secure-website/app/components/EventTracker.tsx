'use client';

import { useEffect, useRef } from 'react';
import { useEventTracker } from '@/app/hooks/useEventTracker';

export default function EventTracker() {
  const { trackEvent } = useEventTracker();
  const lastScrollDepth = useRef(0);
  const scrollCheckInterval = useRef<NodeJS.Timeout>();
  
  useEffect(() => {
    // Track page view
    trackEvent({
      event_type: 'page_view',
      event_category: 'navigation',
    });
    
    // Track clicks
    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;

      trackEvent({
        event_type: 'click',
        event_category: 'interaction',
        element_id: target.id || undefined,
        element_class: target.className || undefined,
        element_text: target.textContent?.substring(0, 100) || undefined,
        click_x: e.clientX,
        click_y: e.clientY,
        metadata: {
          tag_name: target.tagName,
        },
      });
    };
    
    // Track scroll depth (throttled)
    const handleScroll = () => {
      const windowHeight = window.innerHeight;
      const documentHeight = document.documentElement.scrollHeight;
      const scrollTop = window.scrollY;
      const scrollPercentage = Math.round(
        ((scrollTop + windowHeight) / documentHeight) * 100
      );

      // Only log at 25%, 50%, 75%, 100% milestones
      const milestones = [25, 50, 75, 100];
      const nextMilestone = milestones.find(m => m > lastScrollDepth.current && scrollPercentage >= m);

      if (nextMilestone) {
        console.log('Scroll milestone reached:', nextMilestone, 'Current scroll:', scrollPercentage);
        lastScrollDepth.current = nextMilestone;
        trackEvent({
          event_type: 'scroll',
          event_category: 'engagement',
          scroll_depth: nextMilestone,
        });
      }
    };
    
    // Track form interactions
    const handleFormFocus = (e: FocusEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
        trackEvent({
          event_type: 'form_focus',
          event_category: 'interaction',
          element_id: target.id || undefined,
          metadata: {
            input_type: (target as HTMLInputElement).type,
          },
        });
      }
    };
    
    // Track time on page
    const startTime = Date.now();
    const trackTimeOnPage = () => {
      const timeSpent = Math.round((Date.now() - startTime) / 1000);
      trackEvent({
        event_type: 'time_on_page',
        event_category: 'engagement',
        metadata: { seconds: timeSpent },
      });
    };
    
    // Add event listeners
    document.addEventListener('click', handleClick);
    window.addEventListener('scroll', handleScroll, { passive: true });
    document.addEventListener('focusin', handleFormFocus);
    
    // Track time on page every 30 seconds and on unload
    const timeInterval = setInterval(trackTimeOnPage, 30000);
    window.addEventListener('beforeunload', trackTimeOnPage);
    
    return () => {
      document.removeEventListener('click', handleClick);
      window.removeEventListener('scroll', handleScroll);
      document.removeEventListener('focusin', handleFormFocus);
      window.removeEventListener('beforeunload', trackTimeOnPage);
      clearInterval(timeInterval);
      if (scrollCheckInterval.current) {
        clearInterval(scrollCheckInterval.current);
      }
    };
  }, [trackEvent]);
  
  return null;
}