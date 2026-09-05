import fs from 'fs';
import path from 'path';

const CANONICAL_HOST = 'https://www.urlscanonline.com';
const DEFAULT_IMAGE = `${CANONICAL_HOST}/logo-v6.png`;

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// 1. Read dist/index.html
const indexHtmlPath = path.resolve('dist/index.html');
if (!fs.existsSync(indexHtmlPath)) {
  console.error("dist/index.html not found. Run vite build first.");
  process.exit(1);
}
const template = fs.readFileSync(indexHtmlPath, 'utf8');

// 2. Load articles
let dataFile = fs.readFileSync('src/data/blog/index.js', 'utf8');
dataFile = dataFile.replace('export const articles = ', '').replace('export const articles =', '').trim();
if (dataFile.endsWith(';')) {
  dataFile = dataFile.slice(0, -1);
}
const articles = JSON.parse(dataFile);

// 3. Helper to replace/inject meta tags safely
function injectMeta(html, { title, description, url, type, image, schema }) {
  const t = escapeHtml(title);
  const d = escapeHtml(description);
  const u = escapeHtml(url);
  const img = escapeHtml(image);

  let out = html;

  // Title
  out = out.replace(/<title>.*?<\/title>/, `<title>${t}</title>`);
  out = out.replace(/<meta name="title"[^>]*>/, `<meta name="title" content="${t}" />`);

  // Description
  out = out.replace(/<meta name="description"[^>]*>/, `<meta name="description" content="${d}" />`);

  // OG tags
  out = out.replace(/<meta property="og:type"[^>]*>/, `<meta property="og:type" content="${type}" />`);
  out = out.replace(/<meta property="og:url"[^>]*>/, `<meta property="og:url" content="${u}" />`);
  out = out.replace(/<meta property="og:title"[^>]*>/, `<meta property="og:title" content="${t}" />`);
  out = out.replace(/<meta property="og:description"[^>]*>/, `<meta property="og:description" content="${d}" />`);
  out = out.replace(/<meta property="og:image"[^>]*>/, `<meta property="og:image" content="${img}" />`);

  // Twitter tags — original index.html uses property= instead of name=, replace in-place
  out = out.replace(/<meta property="twitter:card"[^>]*>/, `<meta name="twitter:card" content="summary_large_image" />`);
  out = out.replace(/<meta property="twitter:url"[^>]*>/, `<meta name="twitter:url" content="${u}" />`);
  out = out.replace(/<meta property="twitter:title"[^>]*>/, `<meta name="twitter:title" content="${t}" />`);
  out = out.replace(/<meta property="twitter:description"[^>]*>/, `<meta name="twitter:description" content="${d}" />`);

  // twitter:image is missing from the base template — append it before </head>
  const twitterImageTag = `<meta name="twitter:image" content="${img}" />`;
  // Canonical
  const canonicalTag = `<link rel="canonical" href="${u}" />`;

  let insertions = `    ${canonicalTag}\n    ${twitterImageTag}\n`;

  // Schema
  if (schema) {
    insertions += `    ${schema}\n`;
  }

  out = out.replace('</head>', `${insertions}  </head>`);

  return out;
}

// 4. Generate /blog landing
const blogDir = path.resolve('dist/blog');
if (!fs.existsSync(blogDir)) {
  fs.mkdirSync(blogDir, { recursive: true });
}

const blogLandingHtml = injectMeta(template, {
  title: 'Website Security Blog | Security Guides & Best Practices | URLScanOnline',
  description: 'Practical website security guides covering security headers, SSL/TLS, CSP, CORS, cookies, APIs, DNS, email security and common website misconfigurations.',
  url: `${CANONICAL_HOST}/blog`,
  type: 'website',
  image: DEFAULT_IMAGE,
});
fs.writeFileSync(path.resolve('dist/blog.html'), blogLandingHtml);

// 5. Generate /blog/:slug routes
for (const article of articles) {
  const seoTitle = article.seoTitle || `${article.title} | URLScanOnline`;
  const metaDesc = article.metaDescription || article.excerpt;
  const articleUrl = `${CANONICAL_HOST}/blog/${article.slug}`;

  let image = article.image || DEFAULT_IMAGE;
  if (!image.startsWith('http')) {
    image = CANONICAL_HOST + image;
  }

  const schemaObj = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    "headline": article.title,
    "description": metaDesc,
    "url": articleUrl,
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": articleUrl
    },
    "publisher": {
      "@type": "Organization",
      "name": "URLScanOnline"
    }
  };
  if (article.author) {
    schemaObj.author = { "@type": "Organization", "name": article.author };
  }
  if (article.image) {
    schemaObj.image = article.image;
  }
  if (article.datePublished) {
    schemaObj.datePublished = article.datePublished;
  }
  if (article.dateModified) {
    schemaObj.dateModified = article.dateModified;
  }

  const breadcrumbObj = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    "itemListElement": [
      {
        "@type": "ListItem",
        "position": 1,
        "name": "Home",
        "item": `${CANONICAL_HOST}/`
      },
      {
        "@type": "ListItem",
        "position": 2,
        "name": "Blog",
        "item": `${CANONICAL_HOST}/blog`
      },
      {
        "@type": "ListItem",
        "position": 3,
        "name": article.title,
        "item": articleUrl
      }
    ]
  };

  const schemaScript =
    `<script id="schema-article" type="application/ld+json">${JSON.stringify(schemaObj)}</script>\n` +
    `    <script id="schema-breadcrumb" type="application/ld+json">${JSON.stringify(breadcrumbObj)}</script>`;

  const articleHtml = injectMeta(template, {
    title: seoTitle,
    description: metaDesc,
    url: articleUrl,
    type: 'article',
    image: image,
    schema: schemaScript,
  });

  fs.writeFileSync(path.resolve(`dist/blog/${article.slug}.html`), articleHtml);
}

console.log(`Generated 1 blog landing and ${articles.length} article HTML files.`);
