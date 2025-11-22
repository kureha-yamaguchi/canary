import React from 'react'

interface TruncateProps {
  text: string
  maxLength: number
  className?: string
}

/**
 * Component that truncates text and shows full text on hover
 */
export function TruncateText({ text, maxLength, className = '' }: TruncateProps) {
  if (!text) return <span className={className}>-</span>
  
  if (text.length <= maxLength) {
    return <span className={className}>{text}</span>
  }

  return (
    <span 
      className={`${className} cursor-help`}
      title={text}
    >
      {text.substring(0, maxLength)}
      <span className="text-slate-500">...</span>
    </span>
  )
}

/**
 * Format URL for display - show domain prominently
 */
export function formatUrl(url: string, maxLength: number = 40): string {
  try {
    const urlObj = new URL(url)
    const domain = urlObj.hostname
    const path = urlObj.pathname

    if (url.length <= maxLength) {
      return url
    }

    if (domain.length + 10 > maxLength) {
      return domain.length > maxLength 
        ? domain.substring(0, maxLength - 3) + '...'
        : domain
    }

    const remainingLength = maxLength - domain.length - 5 // for "..." and spacing
    if (path.length > remainingLength) {
      return `${domain}${path.substring(0, remainingLength)}...`
    }

    return url.length > maxLength ? url.substring(0, maxLength - 3) + '...' : url
  } catch {
    // If URL parsing fails, just truncate
    return url.length > maxLength ? url.substring(0, maxLength - 3) + '...' : url
  }
}

/**
 * Format vulnerability type for display
 */
export function formatVulnerabilityType(type: string, maxLength: number = 30): string {
  // Replace dashes with spaces and capitalize
  const formatted = type.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
  
  if (formatted.length <= maxLength) {
    return formatted
  }

  return formatted.substring(0, maxLength - 3) + '...'
}

/**
 * Format IP address (can add geolocation later)
 */
export function formatIp(ip: string): string {
  return ip
}

