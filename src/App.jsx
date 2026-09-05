import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { Analytics } from '@vercel/analytics/react';
import SaaSLayout from './components/layout/SaaSLayout';
import RootLayout from './components/layout/RootLayout';
import Scanner from './pages/Scanner';

const Login = React.lazy(() => import('./pages/Login'));
const Register = React.lazy(() => import('./pages/Register'));
const EmailConfirmed = React.lazy(() => import('./pages/EmailConfirmed'));
const ForgotPassword = React.lazy(() => import('./pages/ForgotPassword'));
const ResetPassword = React.lazy(() => import('./pages/ResetPassword'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const ScanHistory = React.lazy(() => import('./pages/ScanHistory'));
const ScanReport = React.lazy(() => import('./pages/ScanReport'));
const HistoryCompare = React.lazy(() => import('./pages/HistoryCompare'));
const Compare = React.lazy(() => import('./pages/Compare'));
const Settings = React.lazy(() => import('./pages/Settings'));
const Services = React.lazy(() => import('./pages/Services'));
const ScannerCapabilities = React.lazy(() => import('./pages/ScannerCapabilities'));
const SecurityAudits = React.lazy(() => import('./pages/SecurityAudits'));
const About = React.lazy(() => import('./pages/About'));
const BlogLanding = React.lazy(() => import('./pages/blog/BlogLanding'));
const ArticlePage = React.lazy(() => import('./pages/blog/ArticlePage'));
const Contact = React.lazy(() => import('./pages/Contact'));
const SecurityTrust = React.lazy(() => import('./pages/SecurityTrust'));
const TermsOfService = React.lazy(() => import('./pages/TermsOfService'));
const ResponsibleDisclosure = React.lazy(() => import('./pages/ResponsibleDisclosure'));
const TrustAndPolicy = React.lazy(() => import('./pages/TrustAndPolicy'));
const ApiDocs = React.lazy(() => import('./pages/ApiDocs'));
const Pricing = React.lazy(() => import('./pages/Pricing'));
const NotFound = React.lazy(() => import('./pages/NotFound'));

// Admin Routes
const AdminLayout = React.lazy(() => import('./pages/admin/AdminLayout'));
const AdminOverview = React.lazy(() => import('./pages/admin/Overview'));
const AdminUsers = React.lazy(() => import('./pages/admin/Users'));
const AdminUserDetail = React.lazy(() => import('./pages/admin/UserDetail'));
const AdminScans = React.lazy(() => import('./pages/admin/Scans'));
const AdminAuditLogs = React.lazy(() => import('./pages/admin/AuditLogs'));

const PlaceholderPage = ({ title }) => (
  <div className="flex flex-col items-center justify-center h-[60vh] text-slate-400">
    <h2 className="text-2xl font-bold text-slate-50 mb-2">{title}</h2>
    <p>This page is under construction.</p>
  </div>
);

const RecoveryGuard = ({ children }) => {
  const { isRecovery } = useAuth();
  const location = useLocation();

  if (isRecovery && location.pathname !== '/reset-password') {
    return <Navigate to="/reset-password" replace />;
  }

  return children;
};

const App = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <RecoveryGuard>
          <React.Suspense fallback={<div className="flex h-screen bg-slate-950 items-center justify-center text-slate-500">Loading...</div>}>
          <main className="flex-1 w-full h-full">
            <Routes>
              {/* Public Routes with Sidebar */}
              <Route element={<RootLayout />}>
                <Route path="/" element={<Scanner />} />
                <Route path="/services" element={<Services />} />
                <Route path="/services/scanner-capabilities" element={<ScannerCapabilities />} />
                <Route path="/services/security-audits" element={<SecurityAudits />} />
                <Route path="/about" element={<About />} />
                <Route path="/scan" element={<Scanner />} />

                {/* New ChatGPT-Sidebar Routes */}
                <Route path="/docs" element={<ApiDocs />} />
                <Route path="/blog" element={<BlogLanding />} />
                <Route path="/blog/:slug" element={<ArticlePage />} />
                <Route path="/pricing" element={<Pricing />} />
                <Route path="/trust-policy" element={<TrustAndPolicy />} />
                <Route path="/security-trust" element={<SecurityTrust />} />
                <Route path="/terms" element={<TermsOfService />} />
                <Route path="/responsible-disclosure" element={<ResponsibleDisclosure />} />
                <Route path="/contact" element={<Contact />} />
              </Route>

              {/* Auth Routes */}
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/email-confirmed" element={<EmailConfirmed />} />
              <Route path="/forgot-password" element={<ForgotPassword />} />
              <Route path="/reset-password" element={<ResetPassword />} />

              {/* Protected SaaS Routes */}
              <Route element={<SaaSLayout />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/history" element={<ScanHistory />} />
                <Route path="/history/compare" element={<HistoryCompare />} />
                <Route path="/history/:scanId" element={<ScanReport />} />
                <Route path="/compare" element={<Compare />} />
                <Route path="/settings" element={<Settings />} />
              </Route>

              {/* Admin Routes */}
              <Route path="/admin" element={<AdminLayout />}>
                <Route index element={<AdminOverview />} />
                <Route path="users" element={<AdminUsers />} />
                <Route path="users/:userId" element={<AdminUserDetail />} />
                <Route path="scans" element={<AdminScans />} />
                                <Route path="audit-logs" element={<AdminAuditLogs />} />
              </Route>

              {/* Redirect root to dashboard (if we were previously doing that globally, wait, let's keep * to NotFound inside RootLayout or outside) */}
              <Route element={<RootLayout />}>
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </main>
          </React.Suspense>
        </RecoveryGuard>
      </BrowserRouter>
      <Analytics />
    </AuthProvider>
  );
};

export default App;
