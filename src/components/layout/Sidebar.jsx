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
  const { signOut, user } = useAuth();
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
            className="hidden md:block p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors"
            title="Toggle Sidebar"
            aria-label="Toggle Sidebar"
          >
            {isCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          </button>

          {/* Mobile Close Button */}
          <button
            onClick={() => setIsMobileOpen(false)}
            className="md:hidden p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors"
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
          className="flex items-center gap-2 p-2 mb-2 text-sm font-medium text-white bg-indigo-600/90 border border-indigo-500/50 rounded-lg shadow-sm hover:bg-indigo-500 transition-colors"
        >
          <Plus size={18} className="text-indigo-100" />
          {!isCollapsed && <span>New Scan</span>}
        </button>

        {navItems.map((item) => {
          const isActive = location.pathname === item.href || (item.href === '/scan' && location.pathname === '/');
          return (
            <Link
              key={item.href}
              to={item.href}
              className={`flex items-center gap-3 p-2 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-slate-800/80 text-slate-50'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-50'
              }`}
              title={isCollapsed ? item.label : undefined}
            >
              <div className={isActive ? "text-indigo-400" : "text-slate-500"}>
                {item.icon}
              </div>
              {!isCollapsed && <span className="truncate">{item.label}</span>}
            </Link>
          );
        })}





      </div>

      {/* 4. FOOTER */}
      <div className="p-3 flex flex-col gap-2 border-t border-slate-800/80">
        <div
          className={`flex items-center transition-all duration-200 p-2 rounded-lg ${
            isCollapsed ? 'justify-center w-full px-0' : 'justify-start gap-4 w-full'
          }`}
        >
          {!isCollapsed && (
            <div className="flex items-center gap-0">
              <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
                {isLightMode ? <Sun size={18} /> : <Moon size={18} />}
              </div>
              <span className="text-sm font-medium text-slate-400 truncate">Theme</span>
            </div>
          )}

          <button
            onClick={() => setIsLightMode(!isLightMode)}
            className={`${
              isLightMode ? 'bg-indigo-500' : 'bg-slate-700'
            } relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors duration-200 ease-in-out focus:outline-none`}
            title={isLightMode ? "Switch to Dark Mode" : "Switch to Light Mode"}
          >
            <span className="sr-only">Toggle Theme</span>
            <span
              className={`${
                isLightMode ? 'translate-x-6' : 'translate-x-1'
              } inline-block h-4 w-4 transform rounded-full bg-white transition duration-200 ease-in-out`}
            />
          </button>
        </div>

        <div
          className={`flex items-center transition-all duration-200 ${
            isCollapsed
              ? 'justify-center w-full px-0'  // Center icon when collapsed
              : 'justify-start px-3 gap-3'   // Standard row layout when expanded
          }`}
        >
          {/* User Avatar Circle */}
          <div className="w-9 h-9 rounded-full bg-indigo-600/30 flex items-center justify-center shrink-0">
            <User className="w-5 h-5 text-indigo-400" />
          </div>

          {/* User Info Text (Hidden when collapsed) */}
          {!isCollapsed && (
            <div className="flex flex-col truncate">
              {user ? (
                <>
                  <span className="text-sm font-medium text-slate-200">{user.user_metadata?.full_name || 'Pro Tier'}</span>
                  <span className="text-xs text-slate-400 truncate">{user.email}</span>
                </>
              ) : (
                <>
                  <span className="text-sm font-medium text-slate-200">Guest User</span>
                  <span className="text-xs text-slate-400">Not logged in</span>
                </>
              )}
            </div>
          )}
        </div>

        {/* Sign In / Sign Out Button */}
        {!isCollapsed && (
          user ? (
            <>
              <Link
                to="/settings"
                className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-slate-400 hover:text-slate-50 hover:bg-slate-900/50 transition-colors text-sm font-medium"
              >
                <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
                  <Settings size={16} />
                </div>
                <span className="truncate">Settings</span>
              </Link>
              <button
                onClick={async () => { await signOut(); navigate('/login'); }}
                className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-slate-400 hover:text-slate-50 hover:bg-slate-900/50 transition-colors text-sm font-medium"
              >
                <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
                  <LogOut size={16} />
                </div>
                <span className="truncate">Sign Out</span>
              </button>
            </>
          ) : (
            <>
              <Link
                to="/login"
                className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-indigo-400 hover:text-indigo-300 hover:bg-indigo-900/20 transition-colors text-sm font-medium"
              >
                <div className="w-7 h-7 flex items-center justify-center shrink-0 text-indigo-400">
                  <User size={16} />
                </div>
                <span className="truncate">Sign In</span>
              </Link>
              <Link
                to="/register"
                className="w-full flex items-center gap-3 px-2.5 py-2 mt-1 rounded-lg text-emerald-400 hover:text-emerald-300 hover:bg-emerald-900/20 transition-colors text-sm font-medium"
              >
                <div className="w-7 h-7 flex items-center justify-center shrink-0 text-emerald-400">
                  <User size={16} />
                </div>
                <span className="truncate">Sign Up</span>
              </Link>
            </>
          )
        )}

        {isCollapsed && (
          user ? (
            <button
              onClick={async () => { await signOut(); navigate('/login'); }}
              className="w-full flex justify-center px-2.5 py-2 rounded-lg text-slate-400 hover:text-slate-50 hover:bg-slate-900/50 transition-colors"
              title="Sign Out"
              aria-label="Sign Out"
            >
              <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
                <LogOut size={16} />
              </div>
            </button>
          ) : (
            <Link
              to="/login"
              className="w-full flex justify-center px-2.5 py-2 rounded-lg text-indigo-400 hover:text-indigo-300 hover:bg-indigo-900/20 transition-colors"
              title="Sign In"
              aria-label="Sign In"
            >
              <div className="w-7 h-7 flex items-center justify-center shrink-0 text-indigo-400">
                <User size={16} />
              </div>
            </Link>
          )
        )}
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
