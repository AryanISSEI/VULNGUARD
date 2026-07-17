/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        glass: {
          100: 'rgba(255, 255, 255, 0.05)',
          200: 'rgba(255, 255, 255, 0.1)',
          300: 'rgba(255, 255, 255, 0.15)',
          400: 'rgba(255, 255, 255, 0.2)',
          500: 'rgba(255, 255, 255, 0.3)',
          border: 'rgba(255, 255, 255, 0.1)',
        },
        dark: {
          900: '#0a0a0f',
          800: '#12121a',
          700: '#1a1a25',
          600: '#232330',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
        }
      },
      backdropBlur: {
        xs: '2px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 20px rgba(59, 130, 246, 0.3)' },
          '100%': { boxShadow: '0 0 40px rgba(59, 130, 246, 0.5)' },
        },
      },
    },
  },
  plugins: [],
}
