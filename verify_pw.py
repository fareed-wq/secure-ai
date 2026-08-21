from playwright.sync_api import sync_playwright

def run_test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        errors = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda err: errors.append(err.message))

        page.goto("http://localhost:5175/")
        page.wait_for_selector(".scanner-page", state="visible")
        
        # Check logo
        logo_loaded = page.evaluate("() => { const img = document.querySelector('img[src=\"/logo-transparent.webp\"]'); return img && img.complete && img.naturalHeight > 0 && img.getAttribute('width') === '256'; }")
        if not logo_loaded:
            print("FAIL: Logo not loaded correctly or missing width attribute")
            errors.append("Logo not loaded correctly")
        
        # Check height/layout (CLS proxy)
        client_rect = page.evaluate("() => { const img = document.querySelector('img[src=\"/logo-transparent.webp\"]'); return img ? img.getBoundingClientRect() : null; }")
        print("Logo Client Rect:", client_rect)
        
        browser.close()
        
        if errors:
            print("Console errors:", errors)
        else:
            print("No console errors, logo is valid")

if __name__ == '__main__':
    run_test()
