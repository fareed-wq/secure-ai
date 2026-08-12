/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        white: 'rgb(var(--color-white) / <alpha-value>)',
        black: 'rgb(var(--color-black) / <alpha-value>)',
        amber: {
          200: 'rgb(var(--color-amber-200) / <alpha-value>)',
          300: 'rgb(var(--color-amber-300) / <alpha-value>)',
          400: 'rgb(var(--color-amber-400) / <alpha-value>)',
          500: 'rgb(var(--color-amber-500) / <alpha-value>)',
        },
        blue: {
          200: 'rgb(var(--color-blue-200) / <alpha-value>)',
          300: 'rgb(var(--color-blue-300) / <alpha-value>)',
          400: 'rgb(var(--color-blue-400) / <alpha-value>)',
          500: 'rgb(var(--color-blue-500) / <alpha-value>)',
        },
        cyan: {
          200: 'rgb(var(--color-cyan-200) / <alpha-value>)',
          300: 'rgb(var(--color-cyan-300) / <alpha-value>)',
          400: 'rgb(var(--color-cyan-400) / <alpha-value>)',
          500: 'rgb(var(--color-cyan-500) / <alpha-value>)',
        },
        emerald: {
          200: 'rgb(var(--color-emerald-200) / <alpha-value>)',
          300: 'rgb(var(--color-emerald-300) / <alpha-value>)',
          400: 'rgb(var(--color-emerald-400) / <alpha-value>)',
          500: 'rgb(var(--color-emerald-500) / <alpha-value>)',
        },
        indigo: {
          200: 'rgb(var(--color-indigo-200) / <alpha-value>)',
          300: 'rgb(var(--color-indigo-300) / <alpha-value>)',
          400: 'rgb(var(--color-indigo-400) / <alpha-value>)',
          500: 'rgb(var(--color-indigo-500) / <alpha-value>)',
        },
        red: {
          200: 'rgb(var(--color-red-200) / <alpha-value>)',
          300: 'rgb(var(--color-red-300) / <alpha-value>)',
          400: 'rgb(var(--color-red-400) / <alpha-value>)',
          500: 'rgb(var(--color-red-500) / <alpha-value>)',
        },
        rose: {
          200: 'rgb(var(--color-rose-200) / <alpha-value>)',
          300: 'rgb(var(--color-rose-300) / <alpha-value>)',
          400: 'rgb(var(--color-rose-400) / <alpha-value>)',
          500: 'rgb(var(--color-rose-500) / <alpha-value>)',
        },
        sky: {
          200: 'rgb(var(--color-sky-200) / <alpha-value>)',
          300: 'rgb(var(--color-sky-300) / <alpha-value>)',
          400: 'rgb(var(--color-sky-400) / <alpha-value>)',
          500: 'rgb(var(--color-sky-500) / <alpha-value>)',
        },
        slate: {
          50: 'rgb(var(--color-slate-50) / <alpha-value>)',
          100: 'rgb(var(--color-slate-100) / <alpha-value>)',
          200: 'rgb(var(--color-slate-200) / <alpha-value>)',
          300: 'rgb(var(--color-slate-300) / <alpha-value>)',
          400: 'rgb(var(--color-slate-400) / <alpha-value>)',
          500: 'rgb(var(--color-slate-500) / <alpha-value>)',
          600: 'rgb(var(--color-slate-600) / <alpha-value>)',
          700: 'rgb(var(--color-slate-700) / <alpha-value>)',
          800: 'rgb(var(--color-slate-800) / <alpha-value>)',
          900: 'rgb(var(--color-slate-900) / <alpha-value>)',
          950: 'rgb(var(--color-slate-950) / <alpha-value>)',
        }
      }
    },
  },
  plugins: [],
}
