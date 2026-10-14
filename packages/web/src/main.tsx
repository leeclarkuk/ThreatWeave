import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { ErrorBoundary } from './ErrorBoundary';
import './styles.css';

try { const t = localStorage.getItem('tw.theme'); if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t); } catch { /* storage unavailable: follow system */ }
createRoot(document.getElementById('root')!).render(<StrictMode><ErrorBoundary><App /></ErrorBoundary></StrictMode>);
