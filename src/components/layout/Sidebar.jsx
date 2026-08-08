import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  Shield, 
  Search, 
  PanelLeftClose, 
  PanelLeftOpen, 
  Plus, 
  Code, 
  Book, 
  CreditCard, 
  Info, 
  MoreHorizontal, 
  Settings,
  User,
  MessageSquare,
  LogOut,
  LayoutDashboard,
  Activity
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

const Sidebar = ({ isMobileOpen, setIsMobileOpen }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { signOut, user } = useAuth();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [showMore, setShowMore] = useState(false);

  const navItems = [
    { label: "Dashboard", href: "/dashboard", icon: <LayoutDashboard size={18} /> },
    { label: "Run Scan", href: "/scan", icon: <Activity size={18} /> },
    { label: "Services", href: "/services", icon: <Shield size={18} /> },
    { label: "API Docs", href: "/docs", icon: <Code size={18} /> },
    { label: "Security Blog", href: "/blog", icon: <Book size={18} /> },
    { label: "Pricing", href: "/pricing", icon: <CreditCard size={18} /> },
    { label: "About Us", href: "/about", icon: <Info size={18} /> },
  ];

  const moreItems = [
    { label: "Trust Policy", href: "/trust", icon: <Shield size={18} /> },
    { label: "Contact", href: "/contact", icon: <MessageSquare size={18} /> },
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
        className={`fixed md:relative z-50 flex flex-col bg-slate-950 border-r border-slate-800 h-screen transition-transform md:transition-all duration-300
          ${isMobileOpen ? 'translate-x-0 w-64' : '-translate-x-full md:translate-x-0'}
          ${isCollapsed ? 'md:w-16' : 'md:w-64'}
        `}
      >
      {/* 1. HEADER */}
      <div className="flex items-center justify-between p-4 border-b border-slate-800">
        {!isCollapsed && (
          <Link to="/" className="flex items-center hover:opacity-80 transition-opacity">
            <img src="/logo-transparent.png" alt="URLScan Online Logo" className="h-8 w-auto" />
          </Link>
        )}
        <div className={`flex items-center ${isCollapsed ? 'flex-col gap-4 w-full' : 'gap-2'}`}>
          <button className="p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors" title="Quick Search">
            <Search size={18} />
          </button>
          <button 
            onClick={() => setIsCollapsed(!isCollapsed)} 
            className="p-1.5 text-slate-400 hover:bg-slate-800 rounded-md transition-colors"
            title="Toggle Sidebar"
          >
            {isCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          </button>
        </div>
      </div>

      {/* 2. MAIN NAV */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden flex flex-col p-3 gap-1">
        {/* New Scan Button */}
        <button 
          onClick={() => navigate('/', { state: { resetScan: Date.now() } })}
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
                  ? 'bg-slate-800/80 text-white' 
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-white'
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

        {/* More Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowMore(!showMore)}
            className="w-full flex items-center gap-3 p-2 rounded-lg text-sm font-medium text-slate-400 hover:bg-slate-800/50 hover:text-white transition-colors"
            title={isCollapsed ? "More" : undefined}
          >
            <div className="text-slate-500"><MoreHorizontal size={18} /></div>
            {!isCollapsed && <span>More</span>}
          </button>
          
          {showMore && !isCollapsed && (
            <div className="ml-8 mt-1 flex flex-col gap-1 border-l-2 border-slate-800 pl-2">
              {moreItems.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  className={`flex items-center gap-2 p-1.5 rounded-md text-sm transition-colors ${
                    location.pathname === item.href 
                      ? 'bg-slate-800/80 text-white font-medium' 
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <div className={location.pathname === item.href ? "text-indigo-400" : "text-slate-500"}>
                    {item.icon}
                  </div>
                  <span className="truncate">{item.label}</span>
                </Link>
              ))}
            </div>
          )}
        </div>


      </div>

      {/* 4. FOOTER */}
      <div className="p-3 flex flex-col gap-2 border-t border-slate-800/80">
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
              <span className="text-sm font-medium text-slate-200">Free Tier</span>
              <span className="text-xs text-slate-400">guest@urlscanonline.com</span>
            </div>
          )}
        </div>
        {!isCollapsed && (
          <button
            onClick={signOut}
            className="w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900/50 transition-colors text-sm font-medium"
          >
            <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
              <LogOut size={16} />
            </div>
            <span className="truncate">Sign Out</span>
          </button>
        )}
        {isCollapsed && (
          <button
            onClick={signOut}
            className="w-full flex justify-center px-2.5 py-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900/50 transition-colors"
            title="Sign Out"
          >
            <div className="w-7 h-7 flex items-center justify-center shrink-0 text-slate-400">
              <LogOut size={16} />
            </div>
          </button>
        )}
      </div>
    </aside>
    </>
  );
};

export default Sidebar;
