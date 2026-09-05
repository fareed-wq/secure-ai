import React, { useEffect } from 'react';
import { useParams, Link, useLocation } from 'react-router-dom';
import { articles } from '../../data/blog';
import { ChevronRight, ArrowLeft, CheckCircle2 } from 'lucide-react';

const ArticlePage = () => {
  const { slug } = useParams();
  const { hash } = useLocation();
  const article = articles.find(a => a.slug === slug);

  // Effect: Unknown-article metadata (noindex + title)
  useEffect(() => {
    if (article) return;

    const previousTitle = document.title;
    document.title = "Article Not Found | URLScanOnline";

    let robots = document.querySelector('meta[name="robots"]');
    const created = !robots;

    if (!robots) {
      robots = document.createElement("meta");
      robots.setAttribute("name", "robots");
      document.head.appendChild(robots);
    }

    const previousRobots = robots.getAttribute("content");
    robots.setAttribute("content", "noindex");

    return () => {
      document.title = previousTitle;

      if (created) {
        robots.remove();
      } else if (previousRobots === null) {
        robots.removeAttribute("content");
      } else {
        robots.setAttribute("content", previousRobots);
      }
    };
  }, [article]);

  useEffect(() => {
    if (article) {
      // 1. Record previous states
      const prevTitle = document.title;

      const descTag = document.querySelector('meta[name="description"]');
      const prevDesc = descTag ? descTag.content : null;

      const canonicalTag = document.querySelector('link[rel="canonical"]');
      const prevCanonical = canonicalTag ? canonicalTag.href : null;

      // Map to store previous values of other meta tags
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
      document.title = article.seoTitle || `${article.title} | URLScanOnline`;

      let activeDesc = descTag;
      let createdDesc = false;
      if (!activeDesc) {
        activeDesc = document.createElement('meta');
        activeDesc.name = "description";
        document.head.appendChild(activeDesc);
        createdDesc = true;
      }
      activeDesc.content = article.metaDescription || article.excerpt;

      let activeCanonical = canonicalTag;
      let createdCanonical = false;
      if (!activeCanonical) {
        activeCanonical = document.createElement('link');
        activeCanonical.rel = "canonical";
        document.head.appendChild(activeCanonical);
        createdCanonical = true;
      }
      activeCanonical.href = `https://www.urlscanonline.com/blog/${article.slug}`;

      const managedTags = [];
      managedTags.push(setMetaProperty('meta[property="og:title"]', 'property', 'og:title', article.seoTitle || `${article.title} | URLScanOnline`));
      managedTags.push(setMetaProperty('meta[property="og:description"]', 'property', 'og:description', article.metaDescription || article.excerpt));
      managedTags.push(setMetaProperty('meta[property="og:url"]', 'property', 'og:url', `https://www.urlscanonline.com/blog/${article.slug}`));
      managedTags.push(setMetaProperty('meta[property="og:type"]', 'property', 'og:type', 'article'));
      if (article.image) {
        managedTags.push(setMetaProperty('meta[property="og:image"]', 'property', 'og:image', article.image));
      }

      managedTags.push(setMetaProperty('meta[name="twitter:card"]', 'name', 'twitter:card', 'summary_large_image'));
      managedTags.push(setMetaProperty('meta[name="twitter:title"]', 'name', 'twitter:title', article.seoTitle || `${article.title} | URLScanOnline`));
      managedTags.push(setMetaProperty('meta[name="twitter:description"]', 'name', 'twitter:description', article.metaDescription || article.excerpt));
      if (article.image) {
        managedTags.push(setMetaProperty('meta[name="twitter:image"]', 'name', 'twitter:image', article.image));
      }

      // Structured Data - BlogPosting
      let scriptSchema = document.querySelector('#schema-article');
      if (!scriptSchema) {
        scriptSchema = document.createElement('script');
        scriptSchema.id = "schema-article";
        scriptSchema.type = "application/ld+json";
        document.head.appendChild(scriptSchema);
      }

      const schema = {
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        "headline": article.title,
        "description": article.metaDescription || article.excerpt,
        "url": `https://www.urlscanonline.com/blog/${article.slug}`,
        "mainEntityOfPage": {
          "@type": "WebPage",
          "@id": `https://www.urlscanonline.com/blog/${article.slug}`
        },
        "publisher": {
          "@type": "Organization",
          "name": "URLScanOnline"
        }
      };

      if (article.author) {
        schema.author = {
          "@type": "Organization",
          "name": article.author
        };
      }

      if (article.image) {
        schema.image = article.image;
      }

      if (article.datePublished) {
        schema.datePublished = article.datePublished;
      }

      if (article.dateModified) {
        schema.dateModified = article.dateModified;
      }


      scriptSchema.textContent = JSON.stringify(schema);

      // Structured Data - BreadcrumbList
      let breadcrumbSchema = document.querySelector('#schema-breadcrumb');
      if (!breadcrumbSchema) {
        breadcrumbSchema = document.createElement('script');
        breadcrumbSchema.id = "schema-breadcrumb";
        breadcrumbSchema.type = "application/ld+json";
        document.head.appendChild(breadcrumbSchema);
      }

      const breadcrumbData = {
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        "itemListElement": [
          {
            "@type": "ListItem",
            "position": 1,
            "name": "Home",
            "item": "https://www.urlscanonline.com/"
          },
          {
            "@type": "ListItem",
            "position": 2,
            "name": "Security Blog",
            "item": "https://www.urlscanonline.com/blog"
          },
          {
            "@type": "ListItem",
            "position": 3,
            "name": article.title,
            "item": `https://www.urlscanonline.com/blog/${article.slug}`
          }
        ]
      };
      breadcrumbSchema.textContent = JSON.stringify(breadcrumbData);

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

        if (scriptSchema) scriptSchema.remove();
        if (breadcrumbSchema) breadcrumbSchema.remove();
      };
    }
  }, [article]);

  useEffect(() => {
    if (hash) {
      const id = hash.replace('#', '');
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    } else {
      window.scrollTo(0, 0);
    }
  }, [hash, slug]);

  if (!article) {
    return (
      <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200 font-sans items-center justify-center p-8">
        <h1 className="text-4xl font-bold mb-4">Article Not Found</h1>
        <p className="text-slate-400 mb-8">The article you are looking for does not exist.</p>
        <Link to="/blog" className="text-indigo-400 hover:text-indigo-300 flex items-center">
          <ArrowLeft size={16} className="mr-2" />
          Back to Blog
        </Link>
      </div>
    );
  }

  // Get related articles (same category, exclude current, up to 3)
  const relatedArticles = articles
    .filter(a => a.category === article.category && a.id !== article.id)
    .slice(0, 3);

  // If not enough in the same category, fill with others
  if (relatedArticles.length < 3) {
    const additional = articles
      .filter(a => a.id !== article.id && !relatedArticles.find(r => r.id === a.id))
      .slice(0, 3 - relatedArticles.length);
    relatedArticles.push(...additional);
  }

  const showToc = article.sections && article.sections.length >= 5;

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200 font-sans">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">

        {/* Breadcrumbs */}
        <nav className="flex items-center text-sm text-slate-400 mb-8" aria-label="Breadcrumb">
          <Link to="/blog" className="hover:text-indigo-400 transition-colors">Blog</Link>
          <ChevronRight size={16} className="mx-2 text-slate-600" aria-hidden="true" />
          <span className="text-slate-500">{article.category}</span>
        </nav>

        {/* Header */}
        <header className="mb-12">
          <div className="text-indigo-400 font-semibold tracking-wider uppercase text-sm mb-4">
            {article.category}
          </div>
          <h1 className="text-3xl md:text-5xl font-black text-slate-50 mb-6 leading-tight tracking-tight">
            {article.title}
          </h1>
          <p className="text-xl text-slate-300 border-l-4 border-indigo-500 pl-5 py-2 leading-relaxed bg-indigo-500/5 rounded-r-lg">
            {article.excerpt}
          </p>
        </header>

        {/* Content Area */}
        <div className="mb-16 text-lg text-slate-300 leading-relaxed">
          {/* Introduction */}
          <div
            className="mb-10 prose prose-invert prose-slate max-w-none prose-p:leading-relaxed prose-a:text-indigo-400 hover:prose-a:text-indigo-300"
            dangerouslySetInnerHTML={{ __html: article.content }}
          />

          {/* Table of Contents */}
          {showToc && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-12">
              <h2 id="on-this-page" className="text-sm font-bold uppercase tracking-widest text-slate-500 mb-4">On this page</h2>
              <ul className="space-y-3 text-base">
                {article.sections.map((sec, idx) => (
                  <li key={sec.id || idx}>
                    <a
                      href={`#${sec.id}`}
                      className="text-indigo-400 hover:text-indigo-300 transition-colors flex items-start gap-2"
                    >
                      {sec.number && <span className="text-slate-500 font-mono text-sm mt-0.5">{sec.number}.</span>}
                      <span>{sec.title}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Sections */}
          <div className="space-y-16">
            {article.sections?.map((sec, idx) => (
              <section key={sec.id || idx} id={sec.id} className="scroll-mt-24">
                {/* Visual Number (if applicable, typically for checklist) */}
                {sec.number && (
                  <div className="text-5xl font-black text-slate-800 mb-4 font-mono select-none">
                    {sec.number}
                  </div>
                )}

                <h2 className="text-2xl font-bold text-slate-50 mb-4 tracking-tight">
                  {sec.title}
                </h2>

                <div
                  className="mb-6 text-slate-300 prose prose-invert prose-slate max-w-none"
                  dangerouslySetInnerHTML={{ __html: sec.content }}
                />

                {sec.list && sec.list.length > 0 && (
                  <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 mt-6">
                    {sec.listTitle && (
                      <h3 className="text-sm font-bold uppercase tracking-widest text-slate-400 mb-4">
                        {sec.listTitle}
                      </h3>
                    )}
                    <ul className="space-y-3">
                      {sec.list.map((item, i) => (
                        <li key={i} className="flex items-start gap-3">
                          <CheckCircle2 className="w-5 h-5 text-indigo-500 shrink-0 mt-0.5" />
                          <span className="text-slate-300">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Subtle Divider (not after last item) */}
                {idx < article.sections.length - 1 && (
                  <hr className="border-slate-800 mt-16" />
                )}
              </section>
            ))}
          </div>

          {/* FAQ Section */}
          {article.faqs && article.faqs.length > 0 && (
            <div className="mt-16 bg-slate-900/40 border border-slate-800 rounded-2xl p-8">
              <h2 className="text-2xl font-bold text-slate-50 mb-8">Frequently Asked Questions</h2>
              <div className="space-y-6">
                {article.faqs.map((faq, i) => (
                  <div key={i}>
                    <h3 className="text-lg font-bold text-slate-200 mb-2">{faq.question}</h3>
                    <p className="text-slate-400">{faq.answer}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <hr className="border-slate-800 mb-12" />

        {/* Related Articles */}
        {relatedArticles.length > 0 && (
          <section className="mb-16">
            <h2 className="text-2xl font-bold text-slate-50 mb-6">Related Articles</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {relatedArticles.map(rel => (
                <Link key={rel.id} to={`/blog/${rel.slug}`} className="group flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-indigo-500/50 transition-all hover:-translate-y-1 hover:shadow-xl hover:shadow-indigo-500/10">
                  <div className="p-6 flex flex-col h-full">
                    <div className="text-xs font-semibold text-indigo-400 uppercase tracking-wider mb-2">{rel.category}</div>
                    <h3 className="text-lg font-bold text-slate-50 mb-3 group-hover:text-indigo-300 transition-colors leading-snug">{rel.title}</h3>
                    <p className="text-slate-400 text-sm line-clamp-3 mt-auto">{rel.excerpt}</p>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        )}

        {/* Bottom CTA */}
        <section className="text-center bg-indigo-900/20 border border-indigo-500/30 rounded-2xl p-8 sm:p-12 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/10 to-purple-500/10 pointer-events-none"></div>
          <div className="relative z-10">
            <h2 className="text-2xl font-bold text-slate-50 mb-4">Ready to check your website's security posture?</h2>
            <p className="text-lg text-indigo-200/80 mb-8 max-w-xl mx-auto">
              Run a passive security scan with URLScanOnline to identify potential website security issues.
            </p>
            <Link to="/scan" className="inline-flex items-center justify-center px-8 py-3.5 rounded-xl text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-500 transition-all shadow-lg shadow-indigo-500/25 hover:shadow-indigo-500/40 hover:-translate-y-0.5">
              Run a Free Scan
            </Link>
          </div>
        </section>

        <div className="mt-16 text-center">
          <Link to="/blog" className="inline-flex items-center text-slate-400 hover:text-slate-200 transition-colors font-medium">
            <ArrowLeft size={16} className="mr-2" />
            Back to Blog
          </Link>
        </div>

      </div>
    </div>
  );
};

export default ArticlePage;
