const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setViewportSize({width: 1280, height: 800});
  await page.goto('http://localhost:5173/');
  await page.waitForSelector('.scanner-page');
  
  await page.evaluate(() => {
    document.getElementById('main-scroll-container').scrollTo(0, 99999);
  });
  await page.waitForTimeout(1000);
  
  const bottomElements = await page.evaluate(() => {
    const mainScroll = document.getElementById('main-scroll-container');
    const rect = mainScroll.getBoundingClientRect();
    let el = document.elementFromPoint(rect.left + rect.width / 2, rect.bottom - 2);
    
    let result = [];
    while(el && el.tagName !== 'HTML') {
      const computed = window.getComputedStyle(el);
      result.push({
        tag: el.tagName,
        id: el.id,
        className: el.className,
        height: el.clientHeight,
        bg: computed.backgroundColor,
        paddingBottom: computed.paddingBottom,
        marginBottom: computed.marginBottom
      });
      el = el.parentElement;
    }
    return result;
  });
  
  console.log('ELEMENTS AT BOTTOM-CENTER:');
  console.dir(bottomElements, {depth: null});
  
  await browser.close();
})();
