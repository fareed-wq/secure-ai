import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import SaaSLayout from './components/layout/SaaSLayout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import ScanHistory from './pages/ScanHistory';
import SavedReports from './pages/SavedReports';
import Compare from './pages/Compare';
import Settings from './pages/Settings';

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<Scanner />} />
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
    </AuthProvider>
  );
};

export default App;
