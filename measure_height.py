import subprocess
import time
from playwright.sync_api import sync_playwright

def measure(page, width, height, name):
    page.set_viewport_size({"width": width, "height": height})
    page.wait_for_selector(".pb-32", state="visible")
    # Wait for any animations
    time.sleep(1)
    
    data = page.evaluate('''() => {
        const scrollContainer = document.querySelector('#main-scroll-container') || document.documentElement;
        // Looking for main wrapper (the one with pb-32)
        const lastContent = document.querySelector('.pb-32');
        
        const scrollH = scrollContainer.scrollHeight;
        const clientH = scrollContainer.clientHeight;
        const scrollTop = scrollContainer.scrollTop;
        
        const lastRect = lastContent ? lastContent.getBoundingClientRect() : null;
        
        // CSS background check on .scanner-wallpaper
        const wallpaper = document.querySelector('.scanner-wallpaper');
        const bg = wallpaper ? window.getComputedStyle(wallpaper).background : null;
        const wallpaperRect = wallpaper ? wallpaper.getBoundingClientRect() : null;
        
        // Find bottom spacing
        const pb = lastContent ? window.getComputedStyle(lastContent).paddingBottom : '0px';
        
        return {
            scroll: { clientHeight: clientH, scrollHeight: scrollH, scrollTop: scrollTop },
            lastContentHeight: lastRect ? lastRect.height : 0,
            lastContentBottom: lastRect ? lastRect.bottom : 0,
            paddingBottom: pb,
            bg: bg,
            wallpaperHeight: wallpaperRect ? wallpaperRect.height : 0,
            wallpaperBottom: wallpaperRect ? wallpaperRect.bottom : 0,
            bodyHeight: document.body.getBoundingClientRect().height
        }
    }''')
    print(f"--- {name} ({width}x{height}) ---")
    print(f"Scroll Container: clientH={data['scroll']['clientHeight']} scrollH={data['scroll']['scrollHeight']} scrollTop={data['scroll']['scrollTop']}")
    print(f"Last Content (.pb-32): height={data['lastContentHeight']} bottom={data['lastContentBottom']} paddingBottom={data['paddingBottom']}")
    print(f"Wallpaper (.scanner-wallpaper): height={data['wallpaperHeight']} bottom={data['wallpaperBottom']}")
    print(f"Body height: {data['bodyHeight']}")
    
def main():
    server = subprocess.Popen(["npm", "run", "preview", "--", "--port", "5175"], shell=True)
    time.sleep(4)
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://localhost:5175/")
        
        measure(page, 1280, 800, "Desktop")
        measure(page, 375, 812, "Mobile")
        
        browser.close()
        
    server.terminate()

if __name__ == '__main__':
    main()
