'use client';

import { useState } from 'react';

interface LoginButtonProps {
  apiKey: string;
  apiBaseUrl: string;
}

export default function LoginButton({ apiKey, apiBaseUrl }: LoginButtonProps) {
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleLogin = async () => {
    setIsLoggingIn(true);

    // This is the honeypot - the API key is exposed in the props
    try {
      const response = await fetch(apiBaseUrl, {
        headers: {
          'api-key': apiKey,
        },
      });
      const data = await response.json();
      console.log('Login response:', data);
    } catch (error) {
      console.error('Login failed:', error);
    } finally {
      setIsLoggingIn(false);
    }
  };

  return (
    <button
      onClick={handleLogin}
      disabled={isLoggingIn}
      className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-all"
      data-api-key={apiKey}
      data-api-base={apiBaseUrl}
    >
      {isLoggingIn ? 'Logging in...' : 'Admin Login'}
    </button>
  );
}
