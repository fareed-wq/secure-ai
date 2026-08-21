from playwright.sync_api import sync_playwright
import time

def test():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(color_scheme='dark')
        page = context.new_page()
        
        requests = []
        page.on("request", lambda r: requests.append(r.url))

        # 1. Home page logged out
        page.goto("http://localhost:5173/")
        page.wait_for_selector(".scanner-page", state="visible")
        
        # Check if auth loaded (Sidebar says Login)
        page.wait_for_selector("text=Sign In", state="visible")
        
        # Check wallpapers requested
        dark_wp = any('home_wallpaper_dark.webp' in url for url in requests)
        light_wp = any('home-wallpaper-light.webp' in url for url in requests)
        print(f"Dark requested: {dark_wp}, Light requested: {light_wp}")

        # 2. Protected route
        page.goto("http://localhost:5173/dashboard")
        page.wait_for_url("**/login")
        print("Protected route redirects to login: OK")
        
        browser.close()

if __name__ == '__main__':
    test()
