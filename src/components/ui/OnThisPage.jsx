import React, { useState, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';

const OnThisPage = ({ sections }) => {
  const [activeId, setActiveId] = useState('');
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  useEffect(() => {
    const observers = [];
    let isBottom = false;

    const handleScroll = () => {
      // Handle the edge case where the user scrolls to the absolute bottom
      if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 50) {
        if (sections.length > 0) {
          isBottom = true;
          setActiveId(sections[sections.length - 1].id);
        }
      } else {
        isBottom = false;
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !isBottom) {
            setActiveId(entry.target.id);
          }
        });
      },
      {
        rootMargin: '-15% 0px -70% 0px',
      }
    );

    sections.forEach(({ id }) => {
      const element = document.getElementById(id);
      if (element) {
        observer.observe(element);
      }
    });

    return () => {
      window.removeEventListener('scroll', handleScroll);
      observer.disconnect();
    };
  }, [sections]);

  useEffect(() => {
    if (window.location.hash) {
      const id = window.location.hash.substring(1);
      if (sections.some(s => s.id === id)) {
        setActiveId(id);
        setTimeout(() => {
          const element = document.getElementById(id);
          if (element) {
             const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
             element.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth' });
          }
        }, 100);
      }
    } else if (sections.length > 0 && !activeId) {
       setActiveId(sections[0].id);
    }
  }, [sections]);

  const handleClick = (e, id) => {
    e.preventDefault();
    setActiveId(id);
    const element = document.getElementById(id);
    if (element) {
      const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      element.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth' });
      window.history.pushState(null, '', `#${id}`);
      setIsMobileOpen(false);
    }
  };

  if (!sections || sections.length === 0) return null;

  return (
    <>
      {/* Desktop View */}
      <nav aria-label="On this page (Desktop)" className="hidden lg:block w-full">
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">On this page</h4>
        <ul className="space-y-3 border-l border-slate-800">
          {sections.map(({ id, label }) => (
            <li key={id}>
              <a
                href={`#${id}`}
                onClick={(e) => handleClick(e, id)}
                aria-current={activeId === id ? 'location' : undefined}
                className={`block text-sm transition-colors border-l-2 pl-4 py-1 -ml-[1px] ${
                  activeId === id
                    ? 'border-indigo-400 text-indigo-400 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-700'
                }`}
              >
                {label}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      {/* Mobile View */}
      <nav aria-label="On this page (Mobile)" className="lg:hidden w-full mb-8">
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <button
            onClick={() => setIsMobileOpen(!isMobileOpen)}
            aria-expanded={isMobileOpen}
            className="w-full flex items-center justify-between p-4 text-sm font-semibold text-slate-300"
          >
            <span className="uppercase tracking-wider text-xs font-bold text-slate-500">On this page</span>
            <div className="flex items-center gap-2">
              <span className="text-slate-400 text-xs">{activeId ? sections.find(s => s.id === activeId)?.label : 'Sections'}</span>
              <ChevronDown size={14} className={`text-slate-500 transition-transform ${isMobileOpen ? 'rotate-180' : ''}`} />
            </div>
          </button>

          {isMobileOpen && (
            <ul className="px-4 pb-4 space-y-2 border-t border-slate-800/50 pt-3">
              {sections.map(({ id, label }) => (
                <li key={id}>
                  <a
                    href={`#${id}`}
                    onClick={(e) => handleClick(e, id)}
                    aria-current={activeId === id ? 'location' : undefined}
                    className={`block text-sm py-2 px-3 rounded-lg transition-colors ${
                      activeId === id
                        ? 'bg-indigo-500/10 text-indigo-400 font-semibold'
                        : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-300'
                    }`}
                  >
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      </nav>
    </>
  );
};

export default OnThisPage;
