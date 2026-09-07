import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Code,
  Book,
  CreditCard,
  Info,
  Settings,
  User,
  UserPlus,
  MessageSquare,
  LogOut,
  LayoutDashboard,
  Activity,
  X,
  Sun,
  Moon,
  FileText,
  AlertTriangle
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const Sidebar = ({ isMobileOpen, setIsMobileOpen }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { signOut, user, isAdmin } = useAuth();
  const [isCollapsed, setIsCollapsed] = useState(false);

  const [isLightMode, setIsLightMode] = useState(() => {
    return localStorage.getItem('theme') === 'light';
  });

  React.useEffect(() => {
    if (isLightMode) {
      document.documentElement.classList.add('light-theme');
      localStorage.setItem('theme', 'light');
    } else {
      document.documentElement.classList.remove('light-theme');
      localStorage.setItem('theme', 'dark');
    }
  }, [isLightMode]);

  const navItems = [
    { label: "Dashboard", href: "/dashboard", icon: <LayoutDashboard size={18} /> },
    { label: "Services", href: "/services", icon: <Shield size={18} /> },
    { label: "About Us", href: "/about", icon: <Info size={18} /> },
    { label: "Security Blog", href: "/blog", icon: <Book size={18} /> },
    { label: "Pricing", href: "/pricing", icon: <CreditCard size={18} /> },
    { label: "Contact Us", href: "/contact", icon: <MessageSquare size={18} /> },
    { label: "API Docs", href: "/docs", icon: <Code size={18} /> },
    { label: "Trust & Policy", href: "/trust-policy", icon: <Shield size={18} /> },
  ];

  if (isAdmin) {
    navItems.push({ label: "Admin", href: "/admin", icon: <Shield size={18} className="text-red-400" /> });
  }

  const isScannerActive = location.pathname === '/' || location.pathname === '/scan';

  return (
    <>
      {/* Mobile Overlay */}
      {isMobileOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/60 z-40 backdrop-blur-sm"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed top-0 left-0 bottom-0 md:relative z-50 flex flex-col bg-slate-950 border-r border-slate-800 h-screen transition-transform md:transition-all duration-300
          ${isMobileOpen ? 'translate-x-0 w-60' : '-translate-x-full md:translate-x-0'}
          ${isCollapsed ? 'md:w-16' : 'md:w-60'}
        `}
      >
        {/* 1. HEADER */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800">
          {!isCollapsed && (
            <Link to="/" className="flex items-center hover:opacity-80 transition-opacity">
              <img src="/logo-transparent.webp" alt="URLScan Online Logo" width="256" height="64" className="h-8 w-auto" />
            </Link>
          )}
          <div className={`flex items-center ${isCollapsed ? 'flex-col gap-4 w-full' : 'gap-2'}`}>
            <button
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="hidden md:block p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
              title="Toggle Sidebar"
              aria-label="Toggle Sidebar"
            >
              {isCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
            </button>

            {/* Mobile Close Button */}
            <button
              onClick={() => setIsMobileOpen(false)}
              className="md:hidden p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
              title="Close Sidebar"
              aria-label="Close Sidebar"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* 2. MAIN NAV */}
        <div className="flex-1 overflow-y-auto overflow-x-hidden flex flex-col p-3 gap-1">
          {/* New Scan Button */}
          <button
            onClick={() => {
              navigate('/', { state: { resetScan: Date.now() } });
              window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
            }}
            title={isCollapsed ? "New Scan" : undefined}
            aria-label="New Scan"
            className={`flex items-center gap-2 p-2 mb-2 text-sm font-medium rounded-lg shadow-sm transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
              isScannerActive
                ? 'text-white bg-indigo-600/90 border border-indigo-500/50 hover:bg-indigo-500'
                : 'text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white border border-slate-700'
            } ${isCollapsed ? 'justify-center' : ''}`}
          >
            <Plus size={18} className={isScannerActive ? "text-indigo-100" : "text-slate-400"} />
            {!isCollapsed && <span>New Scan</span>}
          </button>

          {navItems.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.href}
                to={item.href}
                className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                  isActive
                    ? 'bg-slate-800/80 text-slate-50'
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-50'
                } ${isCollapsed ? 'justify-center' : ''}`}
                title={isCollapsed ? item.label : undefined}
                aria-label={item.label}
              >
                <div className={isActive ? "text-indigo-400" : "text-slate-500"}>
                  {item.icon}
                </div>
                {!isCollapsed && <span className="truncate">{item.label}</span>}
              </Link>
            );
          })}
        </div>

        {/* 3. USER FOOTER */}
        <div className="border-t border-slate-800 p-3 flex flex-col gap-1">
          <button
            onClick={() => setIsLightMode(!isLightMode)}
            className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800/50 hover:text-slate-50 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${isCollapsed ? 'justify-center' : ''}`}
            title={isCollapsed ? (isLightMode ? "Dark Mode" : "Light Mode") : undefined}
            aria-label={isLightMode ? "Switch to Dark Mode" : "Switch to Light Mode"}
          >
            {isLightMode ? <Moon size={18} className="text-slate-500" /> : <Sun size={18} className="text-slate-500" />}
            {!isCollapsed && <span>{isLightMode ? 'Dark Mode' : 'Light Mode'}</span>}
          </button>

          {user ? (
            <>
              <Link
                to="/settings"
                className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                  location.pathname === '/settings'
                    ? 'bg-slate-800/80 text-slate-50'
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-50'
                } ${isCollapsed ? 'justify-center' : ''}`}
                title={isCollapsed ? "Settings" : undefined}
                aria-label="Settings"
              >
                <Settings size={18} className={location.pathname === '/settings' ? "text-indigo-400" : "text-slate-500"} />
                {!isCollapsed && <span>Settings</span>}
              </Link>
              <button
                onClick={signOut}
                className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-rose-500/10 hover:text-rose-400 transition-colors w-full text-left focus:outline-none focus:ring-2 focus:ring-rose-500 ${isCollapsed ? 'justify-center' : ''}`}
                title={isCollapsed ? "Log Out" : undefined}
                aria-label="Log Out"
              >
                <LogOut size={18} />
                {!isCollapsed && <span>Log Out</span>}
              </button>
            </>
          ) : (
            <>
              <Link
                to="/login"
                className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800/50 hover:text-slate-50 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${isCollapsed ? 'justify-center' : ''}`}
                title={isCollapsed ? "Log In" : undefined}
                aria-label="Log In"
              >
                <User size={18} className="text-slate-500" />
                {!isCollapsed && <span>Log In</span>}
              </Link>
              <Link
                to="/register"
                className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800/50 hover:text-slate-50 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${isCollapsed ? 'justify-center' : ''}`}
                title={isCollapsed ? "Sign Up" : undefined}
                aria-label="Sign Up"
              >
                <UserPlus size={18} className="text-slate-500" />
                {!isCollapsed && <span>Sign Up</span>}
              </Link>
            </>
          )}
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
