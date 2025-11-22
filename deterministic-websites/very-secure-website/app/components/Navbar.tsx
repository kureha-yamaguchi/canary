'use client';

import { useState, useEffect } from 'react';

export default function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled
          ? 'bg-slate-950/95 backdrop-blur-md border-b border-cyan-500/20 shadow-lg shadow-cyan-500/10'
          : 'bg-transparent'
      }`}
    >
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between h-20">
          <div className="text-2xl font-bold text-cyan-400 tracking-tight">
            def/<span className="text-white">acc</span>
          </div>
          <div className="hidden md:flex items-center gap-8">
            <a
              href="#problem"
              className="text-gray-300 hover:text-cyan-400 transition-colors text-sm font-medium"
            >
              The Problem
            </a>
            <a
              href="#building"
              className="text-gray-300 hover:text-cyan-400 transition-colors text-sm font-medium"
            >
              What We Build
            </a>
            <a
              href="#schedule"
              className="text-gray-300 hover:text-cyan-400 transition-colors text-sm font-medium"
            >
              Schedule
            </a>
            <a
              href="#prizes"
              className="text-gray-300 hover:text-cyan-400 transition-colors text-sm font-medium"
            >
              Prizes
            </a>
            <a
              href="https://apartresearch.com"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-6 py-2.5 rounded-lg font-semibold text-sm transition-all shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50"
            >
              Apply Now
            </a>
          </div>
        </div>
      </div>
    </nav>
  );
}
