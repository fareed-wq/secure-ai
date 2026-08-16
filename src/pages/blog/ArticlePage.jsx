import React, { useEffect } from 'react';
import { useParams, Link, Navigate } from 'react-router-dom';
import { articles } from '../../data/blog';
import { ChevronRight, ArrowLeft } from 'lucide-react';

const ArticlePage = () => {
  const { slug } = useParams();
  const article = articles.find(a => a.slug === slug);

  useEffect(() => {
    if (article) {
      document.title = `${article.category} Guides & Best Practices | URLScannerOnline`;
      
      let metaDesc = document.querySelector('meta[name="description"]');
      if (!metaDesc) {
        metaDesc = document.createElement('meta');
        metaDesc.name = "description";
        document.head.appendChild(metaDesc);
      }
      metaDesc.content = article.excerpt;

      let linkCanonical = document.querySelector('link[rel="canonical"]');
      if (!linkCanonical) {
        linkCanonical = document.createElement('link');
        linkCanonical.rel = "canonical";
        document.head.appendChild(linkCanonical);
      }
      linkCanonical.href = `https://www.urlscanonline.com/blog/${article.slug}`;

      // Structured Data
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
        "description": article.excerpt,
        "url": `https://www.urlscanonline.com/blog/${article.slug}`,
        "publisher": {
          "@type": "Organization",
          "name": "URLScannerOnline"
        }
      };
      scriptSchema.textContent = JSON.stringify(schema);
    }
  }, [article]);

  if (!article) {
    return <Navigate to="/blog" replace />;
  }

  // Get related articles (same category, exclude current)
  const relatedArticles = articles
    .filter(a => a.category === article.category && a.id !== article.id)
    .slice(0, 2);

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12 w-full">
        
        {/* Breadcrumbs */}
        <nav className="flex items-center text-sm text-slate-400 mb-8">
          <Link to="/blog" className="hover:text-indigo-400 transition-colors">Blog</Link>
          <ChevronRight size={16} className="mx-2 text-slate-600" />
          <span className="text-slate-500">{article.category}</span>
        </nav>

        {/* Header */}
        <header className="mb-12">
          <div className="text-indigo-400 font-semibold tracking-wider uppercase text-sm mb-4">
            {article.category}
          </div>
          <h1 className="text-3xl md:text-5xl font-bold text-slate-50 mb-6 leading-tight">
            {article.title}
          </h1>
          <p className="text-xl text-slate-400 border-l-4 border-indigo-500 pl-4 py-1">
            {article.excerpt}
          </p>
        </header>

        {/* Content */}
        <article 
          className="prose prose-invert prose-slate max-w-none prose-h3:text-slate-100 prose-a:text-indigo-400 hover:prose-a:text-indigo-300 prose-p:text-slate-300 prose-p:leading-relaxed mb-16"
          dangerouslySetInnerHTML={{ __html: article.content }}
        />

        <hr className="border-slate-800 mb-12" />

        {/* Related Articles */}
        {relatedArticles.length > 0 && (
          <section className="mb-16">
            <h2 className="text-2xl font-bold text-slate-50 mb-6">Related Articles</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {relatedArticles.map(rel => (
                <Link key={rel.id} to={`/blog/${rel.slug}`} className="group flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-indigo-500/50 transition-colors">
                  <div className="p-6">
                    <h3 className="text-lg font-bold text-slate-50 mb-2 group-hover:text-indigo-300 transition-colors">{rel.title}</h3>
                    <p className="text-slate-400 text-sm line-clamp-2">{rel.excerpt}</p>
                  </div>
                </Link>
              ))}
            </div>
          </section>
        )}

        {/* Bottom CTA */}
        <section className="text-center bg-indigo-900/20 border border-indigo-500/30 rounded-2xl p-8 sm:p-12">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">Ready to check your website's security posture?</h2>
          <p className="text-lg text-indigo-200 mb-8 max-w-xl mx-auto">
            Run a passive security scan with URLScannerOnline. Helps identify potential security issues safely.
          </p>
          <Link to="/scan" className="inline-flex items-center justify-center px-6 py-3 rounded-lg text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-500 transition-colors">
            Run a Free Scan
          </Link>
        </section>

        <div className="mt-12 text-center">
          <Link to="/blog" className="inline-flex items-center text-slate-400 hover:text-slate-200 transition-colors">
            <ArrowLeft size={16} className="mr-2" />
            Back to Blog
          </Link>
        </div>

      </div>
    </div>
  );
};

export default ArticlePage;
