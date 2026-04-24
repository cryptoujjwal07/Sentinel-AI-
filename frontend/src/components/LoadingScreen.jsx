/**
 * LoadingScreen Component
 * Premium full-screen loading animation with SentinelAI branding
 * Shown during initial app load and auth verification
 */

import { useState, useEffect } from 'react';

export default function LoadingScreen({ onFinished }) {
  const [fadeOut, setFadeOut] = useState(false);
  const [statusText, setStatusText] = useState('Initializing security systems');

  useEffect(() => {
    // Cycle through status messages for a premium feel
    const messages = [
      'Initializing security systems',
      'Loading threat detection engine',
      'Connecting to AI services',
      'Preparing dashboard',
    ];
    let index = 0;
    const msgInterval = setInterval(() => {
      index = (index + 1) % messages.length;
      setStatusText(messages[index]);
    }, 800);

    // Minimum display time, then trigger fade-out
    const timer = setTimeout(() => {
      setFadeOut(true);
      // Wait for fade animation to complete before calling onFinished
      setTimeout(() => {
        if (onFinished) onFinished();
      }, 500);
    }, 2000);

    return () => {
      clearTimeout(timer);
      clearInterval(msgInterval);
    };
  }, [onFinished]);

  return (
    <div className={`loading-screen-full${fadeOut ? ' loading-fade-out' : ''}`}>
      {/* Background ambient effects */}
      <div className="loading-bg-orb loading-bg-orb-1" />
      <div className="loading-bg-orb loading-bg-orb-2" />
      <div className="loading-bg-orb loading-bg-orb-3" />

      <div className="loading-content">
        {/* Animated shield with orbital ring */}
        <div className="loading-shield-wrapper">
          <div className="loading-ring" />
          <div className="loading-ring loading-ring-2" />
          <div className="loading-shield">🛡️</div>
        </div>

        {/* Brand name */}
        <h1 className="loading-brand">
          Sentinel<span>AI</span>
        </h1>
        <p className="loading-tagline">AI-Powered Web Application Firewall</p>

        {/* Progress bar */}
        <div className="loading-progress-track">
          <div className="loading-progress-fill" />
        </div>

        {/* Status text */}
        <p className="loading-status">{statusText}...</p>
      </div>
    </div>
  );
}
