/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          black: '#0A0A0A',
          surface: '#121216',
          border: '#1E293B',
          cerulean: '#007BA7',
          rose: '#FF2D95',
          muted: '#94A3B8',
          text: '#F8FAFC',
          cardHover: '#181822',
          darkBg: '#0D0E12',
          danger: '#EF4444',
          warning: '#F59E0B',
          success: '#10B981',
          info: '#3B82F6',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-cerulean': '0 0 15px -2px rgba(0, 123, 167, 0.4)',
        'glow-rose': '0 0 15px -2px rgba(255, 45, 149, 0.4)',
        'soc-card': '0 4px 20px -2px rgba(0, 0, 0, 0.5)',
      },
      borderColor: {
        soc: '#1E293B',
      },
    },
  },
  plugins: [],
}
