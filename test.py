from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    def on_console(msg):
        print(f"BROWSER LOG: {msg.text}")
        
    def on_pageerror(err):
        print(f"BROWSER ERROR: {err}")
        
    page.on("console", on_console)
    page.on("pageerror", on_pageerror)
    
    print("Navigating to https://urlscanonline.com")
    page.goto("https://urlscanonline.com", wait_until="networkidle")
    
    print("Waiting for page load...")
    page.wait_for_timeout(2000)
    
    print("Typing google.com")
    try:
        page.fill('input[placeholder="example.com"]', "google.com")
        page.keyboard.press("Enter")
    except Exception as e:
        print("Could not type google.com:", e)
    
    print("Waiting for Technical button...")
    try:
        page.wait_for_selector('button:has-text("Technical")', timeout=10000)
        print("Found Technical button, clicking...")
        page.click('button:has-text("Technical")')
        page.wait_for_timeout(2000)
        print("Clicked! Getting page content...")
        
        # Check if the page is empty
        content = page.content()
        if "Something went wrong" in content:
            print("FOUND ERROR BOUNDARY TEXT")
        else:
            print("NO ERROR BOUNDARY TEXT")
            
        print("URL after click:", page.url)
    except Exception as e:
        print(f"Failed to find button: {e}")
        
    browser.close()
