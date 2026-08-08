const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  
  // Capture console logs
  page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
  page.on('pageerror', error => console.log('BROWSER ERROR:', error.message));
  
  await page.goto('http://localhost:5173');
  
  // Wait for load
  await new Promise(r => setTimeout(r, 2000));
  
  // Simulate a scan
  await page.type('input[placeholder="Enter website URL to scan..."]', 'google.com');
  await page.keyboard.press('Enter');
  
  console.log('Scanning...');
  
  // Wait for scan to finish and report to show
  await page.waitForSelector('button:has-text("Technical")', { timeout: 15000 }).catch(e => console.log('Could not find Technical button'));
  
  // Click Technical
  const technicalBtn = await page.$('button:has-text("Technical")');
  if (technicalBtn) {
    console.log('Clicking Technical button...');
    await technicalBtn.click();
    await new Promise(r => setTimeout(r, 1000));
    await page.screenshot({ path: 'test_technical.png' });
    console.log('Screenshot saved to test_technical.png');
  } else {
    console.log('Technical button not found, taking screenshot anyway');
    await page.screenshot({ path: 'test_error.png' });
  }

  await browser.close();
})();
