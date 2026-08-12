import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { Analytics } from '@vercel/analytics/react';
import SaaSLayout from './components/layout/SaaSLayout';
import RootLayout from './components/layout/RootLayout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import ScanHistory from './pages/ScanHistory';
import SavedReports from './pages/SavedReports';
import Compare from './pages/Compare';
import Settings from './pages/Settings';
import Services from './pages/Services';
import About from './pages/About';

const PlaceholderPage = ({ title }) => (
  <div className="flex flex-col items-center justify-center h-[60vh] text-slate-400">
    <h2 className="text-2xl font-bold text-slate-50 mb-2">{title}</h2>
    <p>This page is under construction.</p>
  </div>
);

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes with Sidebar */}
          <Route element={<RootLayout />}>
            <Route path="/" element={<Scanner />} />
            <Route path="/services" element={<Services />} />
            <Route path="/about" element={<About />} />
            <Route path="/scan" element={<Scanner />} />
            
            {/* New ChatGPT-Sidebar Routes */}
            <Route path="/services" element={<PlaceholderPage title="Services" />} />
            <Route path="/docs" element={<PlaceholderPage title="API Docs" />} />
            <Route path="/blog" element={<PlaceholderPage title="Security Blog" />} />
            <Route path="/pricing" element={<PlaceholderPage title="Pricing" />} />
            <Route path="/about" element={<PlaceholderPage title="About Us" />} />
            <Route path="/trust" element={<PlaceholderPage title="Trust Policy" />} />
            <Route path="/contact" element={<PlaceholderPage title="Contact Support" />} />
          </Route>

          {/* Auth Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          
          {/* Protected SaaS Routes */}
          <Route element={<SaaSLayout />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/history" element={<ScanHistory />} />
            <Route path="/reports" element={<SavedReports />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/settings" element={<Settings />} />
          </Route>

          {/* Redirect root to dashboard */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
      <Analytics />
    </AuthProvider>
  );
};

export default App;
