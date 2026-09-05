import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { articles } from '../../data/blog';
import { BookOpen, Search, ChevronRight } from 'lucide-react';

const PREFERRED_ORDER = [
  "Website Security",
  "Website Vulnerabilities",
  "OWASP Security",
  "Security Headers",
  "SSL / TLS Security",
  "API Security",
  "Web Application Security",
  "WordPress Security",
  "E-Commerce Security",
  "Cloud & Infrastructure Security",
  "DevSecOps",
  "Security Testing",
  "Security Guides"
];

const availableCategories = Array.from(new Set(articles.map(a => a.category)));
const CATEGORIES = [
  "All",
  ...PREFERRED_ORDER.filter(c => availableCategories.includes(c)),
  ...availableCategories.filter(c => !PREFERRED_ORDER.includes(c))
];

const BlogLanding = () => {
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");

  // SEO setup
  useEffect(() => {
    // 1. Record previous states
    const prevTitle = document.title;

    const descTag = document.querySelector('meta[name="description"]');
    const prevDesc = descTag ? descTag.content : null;

    const canonicalTag = document.querySelector('link[rel="canonical"]');
    const prevCanonical = canonicalTag ? canonicalTag.href : null;

    const prevMeta = {};

    const setMetaProperty = (selector, attr, prop, content) => {
      let tag = document.querySelector(selector);
      let created = false;
      if (!tag) {
        tag = document.createElement('meta');
        tag.setAttribute(attr, prop);
        document.head.appendChild(tag);
        created = true;
      } else {
        prevMeta[selector] = tag.content;
      }
      tag.content = content;
      return { tag, created, selector };
    };

    // 2. Set new states
    document.title = "Website Security Blog | Security Guides & Best Practices | URLScanOnline";

    let activeDesc = descTag;
    let createdDesc = false;
    if (!activeDesc) {
      activeDesc = document.createElement('meta');
      activeDesc.name = "description";
      document.head.appendChild(activeDesc);
      createdDesc = true;
    }
    activeDesc.content = "Practical website security guides covering security headers, SSL/TLS, CSP, CORS, cookies, APIs, DNS, email security and common website misconfigurations.";

    let activeCanonical = canonicalTag;
    let createdCanonical = false;
    if (!activeCanonical) {
      activeCanonical = document.createElement('link');
      activeCanonical.rel = "canonical";
      document.head.appendChild(activeCanonical);
      createdCanonical = true;
    }
    activeCanonical.href = "https://www.urlscanonline.com/blog";

    const managedTags = [];
    managedTags.push(setMetaProperty('meta[property="og:title"]', 'property', 'og:title', 'Website Security Blog | Security Guides & Best Practices | URLScanOnline'));
    managedTags.push(setMetaProperty('meta[property="og:description"]', 'property', 'og:description', 'Practical website security guides covering security headers, SSL/TLS, CSP, CORS, cookies, APIs, DNS, email security and common website misconfigurations.'));
    managedTags.push(setMetaProperty('meta[property="og:url"]', 'property', 'og:url', 'https://www.urlscanonline.com/blog'));
    managedTags.push(setMetaProperty('meta[property="og:type"]', 'property', 'og:type', 'website'));
    managedTags.push(setMetaProperty('meta[name="twitter:card"]', 'name', 'twitter:card', 'summary'));
    managedTags.push(setMetaProperty('meta[name="twitter:title"]', 'name', 'twitter:title', 'Website Security Blog | Security Guides & Best Practices | URLScanOnline'));
    managedTags.push(setMetaProperty('meta[name="twitter:description"]', 'name', 'twitter:description', 'Practical website security guides covering security headers, SSL/TLS, CSP, CORS, cookies, APIs, DNS, email security and common website misconfigurations.'));

    // Cleanup on unmount
    return () => {
      document.title = prevTitle;

      if (createdDesc) {
        activeDesc.remove();
      } else if (prevDesc !== null) {
        activeDesc.content = prevDesc;
      }

      if (createdCanonical) {
        activeCanonical.remove();
      } else if (prevCanonical !== null) {
        activeCanonical.href = prevCanonical;
      }

      managedTags.forEach(({ tag, created, selector }) => {
        if (created) {
          tag.remove();
        } else if (prevMeta[selector] !== undefined) {
          tag.content = prevMeta[selector];
        }
      });
    };
  }, []);

  const featuredArticles = articles.slice(0, 3); // Just pick first 3 as featured

  const filteredArticles = articles.filter(article => {
    const isDefaultView = selectedCategory === "All" && searchQuery === "";
    const isFeatured = featuredArticles.some(f => f.id === article.id);

    if (isDefaultView && isFeatured) {
      return false;
    }

    const matchesCategory = selectedCategory === "All" || article.category === selectedCategory;
    const searchLower = searchQuery.toLowerCase();
    const matchesSearch =
      article.title.toLowerCase().includes(searchLower) ||
      article.excerpt.toLowerCase().includes(searchLower) ||
      article.category.toLowerCase().includes(searchLower);
    return matchesCategory && matchesSearch;
  });


  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">

        {/* HEADER */}
        <header className="mb-16 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-bold text-slate-50 mb-6">Website Security Blog</h1>
          <p className="text-xl text-slate-400">
            Practical security guides for websites, web applications, APIs, and online businesses.
          </p>
          <p className="mt-4 text-slate-500">
            Learn about website security, OWASP risks, security headers, SSL/TLS, API security, security testing, remediation, and security concepts.
          </p>
        </header>

        {/* WHY IT MATTERS */}
        <section className="mb-16 bg-slate-900/50 p-8 rounded-2xl border border-slate-800">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">Why Website Security Matters</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-slate-300">
            <p>
              In today's digital landscape, a strong security posture is not optional. Attackers constantly scan for weaknesses like security misconfiguration, exposed information, weak security headers, and insecure authentication or session configurations.
            </p>
            <p>
              A single oversight&mdash;such as exposed APIs, outdated software dependencies, poor TLS/HTTPS configuration, or client-side JavaScript exposure&mdash;can lead to severe breaches. Proactive security assessment helps you stay ahead of the threats.
            </p>
          </div>
        </section>

        {/* FEATURED ARTICLES */}
        <section className="mb-16">
          <h2 className="text-2xl font-bold text-slate-50 mb-6 flex items-center gap-2">
            <BookOpen className="text-indigo-400" />
            Featured Security Guides
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {featuredArticles.map(article => (
              <Link key={article.id} to={`/blog/${article.slug}`} className="group flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-indigo-500/50 transition-colors">
                <div className="p-6 flex-1 flex flex-col">
                  <div className="text-xs font-semibold text-indigo-400 mb-2 uppercase tracking-wider">{article.category}</div>
                  <h3 className="text-xl font-bold text-slate-50 mb-3 group-hover:text-indigo-300 transition-colors">{article.title}</h3>
                  <p className="text-slate-400 text-sm mb-4 flex-1 line-clamp-3">{article.excerpt}</p>
                  <div className="flex items-center text-sm font-medium text-indigo-400">
                    Read Article <ChevronRight size={16} className="ml-1" />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </section>

        <hr className="border-slate-800 mb-16" />

        {/* SEARCH & FILTER */}
        <div className="flex flex-col md:flex-row gap-8 mb-12">
          {/* Categories Sidebar */}
          <div className="w-full md:w-64 shrink-0">
            <h2 className="text-lg font-bold text-slate-50 mb-4 uppercase tracking-wider">Browse by Topic</h2>
            <div className="flex flex-col gap-1">
              {CATEGORIES.map(category => (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  className={`text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                    selectedCategory === category
                      ? 'bg-indigo-600 text-white font-medium'
                      : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  }`}
                >
                  {category}
                </button>
              ))}
            </div>
          </div>

          {/* Articles List */}
          <div className="flex-1">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-slate-50">Latest Security Articles</h2>
              <div className="relative w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  type="text"
                  placeholder="Search articles..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 text-sm rounded-lg pl-10 pr-4 py-2 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                />
              </div>
            </div>

            {filteredArticles.length === 0 ? (
              <div className="text-slate-400 text-center py-12 bg-slate-900/50 rounded-xl border border-slate-800">
                No articles found matching your criteria.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                {filteredArticles.map(article => (
                  <Link key={article.id} to={`/blog/${article.slug}`} className="group flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-indigo-500/50 transition-colors">
                    <div className="p-6 flex-1 flex flex-col">
                      <div className="text-xs font-semibold text-indigo-400 mb-2 uppercase tracking-wider">{article.category}</div>
                      <h3 className="text-lg font-bold text-slate-50 mb-3 group-hover:text-indigo-300 transition-colors line-clamp-2">{article.title}</h3>
                      <p className="text-slate-400 text-sm mb-4 flex-1 line-clamp-3">{article.excerpt}</p>
                      <div className="flex items-center text-sm font-medium text-indigo-400">
                        Read Article <ChevronRight size={16} className="ml-1" />
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* CTA */}
        <section className="mt-20 text-center bg-indigo-900/20 border border-indigo-500/30 rounded-2xl p-12">
          <h2 className="text-3xl font-bold text-slate-50 mb-4">Want to check your website's security posture?</h2>
          <p className="text-xl text-indigo-200 mb-8 max-w-2xl mx-auto">
            Run a passive security scan with URLScanOnline. Helps identify potential security issues like missing headers, exposed files, and misconfigurations.
          </p>
          <Link to="/scan" className="inline-flex items-center justify-center px-6 py-3 rounded-lg text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-500 transition-colors">
            Run a Free Scan
          </Link>
        </section>

      </div>
    </div>
  );
};

export default BlogLanding;
