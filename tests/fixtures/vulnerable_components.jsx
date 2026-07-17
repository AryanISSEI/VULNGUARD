// Example vulnerable React components for testing
import React, { useEffect, useState } from 'react';

// VULNERABLE: Using dangerouslySetInnerHTML
export function DangerousComponent({ content }) {
  return (
    <div
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
}

// VULNERABLE: Using eval
export function EvalComponent({ code }) {
  useEffect(() => {
    eval(code);  // CRITICAL: Never use eval
  }, [code]);

  return <div>Component loaded</div>;
}

// VULNERABLE: innerHTML assignment
export function DomComponent() {
  useEffect(() => {
    const userInput = window.location.search;
    document.getElementById('output').innerHTML = userInput;
  }, []);

  return <div id="output"></div>;
}

// VULNERABLE: JWT in localStorage
export function AuthComponent() {
  const [token, setToken] = useState('');

  const login = async (credentials) => {
    const response = await fetch('/api/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    });
    const data = await response.json();

    // VULNERABLE: Storing JWT in localStorage
    localStorage.setItem('token', data.token);
    setToken(data.token);
  };

  return (
    <button onClick={() => login({})}>Login</button>
  );
}

// SAFE: Sanitized content
export function SafeComponent({ content }) {
  // Using DOMPurify would be the safe approach
  return <div>{content}</div>;
}
