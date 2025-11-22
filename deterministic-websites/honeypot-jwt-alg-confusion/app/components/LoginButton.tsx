'use client';

import { useState, useEffect } from 'react';

export default function LoginButton() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [userEmail, setUserEmail] = useState('');

  // Check if user is already logged in
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        // Decode token to get email (without verification)
        const payload = JSON.parse(atob(token.split('.')[1]));
        setUserEmail(payload.email);
        setIsLoggedIn(true);
      } catch {
        localStorage.removeItem('auth_token');
      }
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setError('');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Login failed');
        return;
      }

      // Store token
      localStorage.setItem('auth_token', data.token);

      // Decode to get user info
      const payload = JSON.parse(atob(data.token.split('.')[1]));
      setUserEmail(payload.email);
      setIsLoggedIn(true);
      setShowForm(false);
      setPassword('');
    } catch (error) {
      setError('Network error. Please try again.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    setIsLoggedIn(false);
    setUserEmail('');
    setEmail('');
    setPassword('');
  };

  if (isLoggedIn) {
    return (
      <div className="flex items-center gap-3">
        <span className="text-sm text-gray-600">
          {userEmail}
        </span>
        <button
          onClick={handleLogout}
          className="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-all"
        >
          Logout
        </button>
      </div>
    );
  }

  return (
    <>
      <button
        onClick={() => setShowForm(val => !val)}
        className="bg-cyan-500 hover:bg-cyan-600 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-all"
      >
        Login
      </button>
      {showForm && (
        <div className="absolute top-full right-0 mt-2">
          <form onSubmit={handleLogin} className="absolute top-full right-0 mt-2 flex flex-col gap-2 p-4 bg-white border border-gray-200 rounded-lg shadow-lg min-w-[280px] z-50">
            <div className="flex justify-between items-center mb-2">
              <h3 className="font-semibold text-gray-800">Login</h3>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>

            {error && (
              <div className="text-red-600 text-sm bg-red-50 p-2 rounded">
                {error}
              </div>
            )}

            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="px-3 py-2 border border-gray-300 rounded text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />

            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="px-3 py-2 border border-gray-300 rounded text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />

            <button
              type="submit"
              disabled={isLoggingIn}
              className="bg-cyan-500 hover:bg-cyan-600 disabled:bg-cyan-300 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-all"
            >
              {isLoggingIn ? 'Logging in...' : 'Sign In'}
            </button>
          </form>
        </div>
      )}
    </>
  );
}