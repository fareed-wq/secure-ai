import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        slugs = [
            'fix-missing-strict-transport-security-header',
            'fix-missing-content-security-policy-header',
            'fix-missing-x-frame-options-header',
            'fix-insecure-cookie-flags',
            'fix-cors-misconfiguration',
            'passive-vulnerability-scanner-vs-active-penetration-testing'
        ]

        for slug in slugs:
            url = f'http://localhost:5173/blog/{slug}'
            print(f'Checking {url}...')
            await page.goto(url)
            await page.wait_for_timeout(1000)
            
            title = await page.title()
            og_url = await page.locator('meta[property="og:url"]').get_attribute('content')
            canonical = await page.locator('link[rel="canonical"]').get_attribute('href')
            desc = await page.locator('meta[name="description"]').get_attribute('content')
            
            print(f'  Title: {title}')
            print(f'  Canonical: {canonical}')
            print(f'  OG URL: {og_url}')
            print(f'  Desc: {desc}')
            
            # Check for console errors
            # (We will just ensure it renders, wait_for_timeout handles the render)
            content = await page.content()
            if 'Page Not Found' in content:
                print('  ERROR: Renders 404 Not Found')
            
        await browser.close()

asyncio.run(run())
