import time
from playwright.sync_api import sync_playwright
import json

def run_test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        errors = []
        def handle_console(msg):
            if msg.type == "error" and "Supabase" not in msg.text and "favicon" not in msg.text and "404" not in msg.text:
                errors.append(msg.text)
        page.on("console", handle_console)
        
        def handle_pageerror(err):
            if "Supabase" not in err.message:
                errors.append(err.message)
        page.on("pageerror", handle_pageerror)

        def check_seo(url, expect_faq):
            page.goto(url)
            page.wait_for_selector("h1")
            
            title = page.title()
            meta_desc = page.locator('meta[name="description"]').get_attribute('content')
            canonical = page.locator('link[rel="canonical"]').get_attribute('href')
            
            og_title = page.locator('meta[property="og:title"]').get_attribute('content')
            og_desc = page.locator('meta[property="og:description"]').get_attribute('content')
            og_url = page.locator('meta[property="og:url"]').get_attribute('content')
            og_type = page.locator('meta[property="og:type"]').get_attribute('content')
            
            schema_text = page.locator('#schema-article').text_content()
            schema = json.loads(schema_text) if schema_text else {}
            
            has_faq = "mainEntity" in schema and isinstance(schema["mainEntity"], list) and len(schema["mainEntity"]) > 0 and schema["mainEntity"][0].get("@type") == "Question"
            
            # Check for duplicates
            title_count = page.evaluate('document.querySelectorAll("title").length')
            desc_count = page.evaluate('document.querySelectorAll("meta[name=\\"description\\"]").length')
            canonical_count = page.evaluate('document.querySelectorAll("link[rel=\\"canonical\\"]").length')
            schema_count = page.evaluate('document.querySelectorAll("#schema-article").length')
            
            print(f"--- Checking {url} ---")
            print(f"Title: {title} (Count: {title_count})")
            print(f"Desc: {meta_desc[:30]}... (Count: {desc_count})")
            print(f"Canonical: {canonical} (Count: {canonical_count})")
            print(f"OG Title: {og_title}")
            print(f"OG Desc: {og_desc[:30]}...")
            print(f"Schema @type: {schema.get('@type')} (Count: {schema_count})")
            print(f"Has FAQ in Schema: {has_faq} (Expected: {expect_faq})")
            
            if title_count > 1 or desc_count > 1 or canonical_count > 1 or schema_count > 1:
                errors.append(f"Duplicate SEO tags found on {url}")
            
            if expect_faq and not has_faq:
                errors.append(f"FAQ expected but missing on {url}")
            if not expect_faq and has_faq:
                errors.append(f"FAQ not expected but found on {url}")
                
            return errors
        
        # Test 1: Normal article (Website Security Checklist)
        check_seo("http://localhost:5176/blog/website-security-checklist", False)
        
        # Test 2: FAQ article (HTTP Security Headers)
        check_seo("http://localhost:5176/blog/http-security-headers-guide", True)
        
        browser.close()
        
        if errors:
            print("Errors found:", errors)
            exit(1)
        else:
            print("All SEO checks passed cleanly!")

if __name__ == '__main__':
    run_test()
