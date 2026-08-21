import json
content_str = open('src/data/blog/index.js', encoding='utf-8').read()
start_idx = content_str.find('[')
end_idx = content_str.rfind(']') + 1
json_str = content_str[start_idx:end_idx]

data = json.loads(json_str)

for article in data:
    # 1. Update Title for OWASP Top 10
    if article['id'] == '3' and 'OWASP Top 10 Explained' in article['title']:
        article['title'] = 'How to Detect OWASP Top 10 Vulnerabilities Using Passive Scanning'
    
    # 2. Add Inline CTAs
    if article.get('content'):
        article['content'] = article['content'].replace('Checking for these items manually', 'Checking for these items manually or with a <a href=\"/scan\">free passive vulnerability scanner</a>')
    
    # 3. Add internal links only to article.content or section.content
    def add_links(text):
        text = text.replace('Content Security Policy (CSP)', '<a href=\"/blog/content-security-policy-guide\">Content Security Policy (CSP)</a>')
        text = text.replace('security headers', '<a href=\"/blog/http-security-headers-guide\">security headers</a>')
        text = text.replace('HTTP Strict Transport Security', '<a href=\"/blog/hsts-explained\">HTTP Strict Transport Security</a>')
        return text

    if article['id'] != '5' and article.get('content'):
        # Don't link to CSP from the CSP article itself
        pass
    
    # Let's be more specific. Just link in a few places.
    if article['id'] == '1': # Website Security Checklist
        for sec in article.get('sections', []):
            if sec['id'] == 'setup-csp':
                sec['content'] = sec['content'].replace('Content Security Policy', '<a href=\"/blog/content-security-policy-guide\">Content Security Policy</a>')
            if sec['id'] == 'security-headers':
                sec['content'] = sec['content'].replace('security headers', '<a href=\"/blog/http-security-headers-guide\">security headers</a>')
            if sec['id'] == 'enable-hsts':
                sec['content'] = sec['content'].replace('HTTP Strict Transport Security', '<a href=\"/blog/hsts-explained\">HTTP Strict Transport Security</a>')
            
            # Add inline CTA to the first section
            if sec['id'] == 'enforce-https':
                if '<a href=\"/scan\"' not in sec['content']:
                    sec['content'] += ' You can quickly verify your HTTPS setup using a <a href=\"/scan\">passive vulnerability scanner</a>.'

    # 4. Add FAQs to an article
    if article['id'] == '4':
        article['faqs'] = [
            { "question": "What are the most critical HTTP security headers?", "answer": "The most critical headers are Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy." },
            { "question": "Can I check my website security headers for free?", "answer": "Yes, you can use online passive vulnerability scanners to check your security headers without performing any active exploitation." },
            { "question": "Does missing X-Frame-Options mean I am vulnerable to Clickjacking?", "answer": "Yes, if X-Frame-Options or a CSP frame-ancestors directive is missing, malicious sites can embed your site in an iframe to trick users into clicking buttons." }
        ]

new_json_str = json.dumps(data, indent=4)
new_content_str = content_str[:start_idx] + new_json_str + content_str[end_idx:]

open('src/data/blog/index.js', 'w', encoding='utf-8').write(new_content_str)
