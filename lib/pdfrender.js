// Verdict cards as PDF, the print side: the card page printed by headless Chromium with its own print
// stylesheet, the same pages a reader gets from Print → Save as PDF (Letter; dark, like the hand cards'
// print rule). Imported by api/pdf.js only: Chromium is bundled with that one function and started on
// demand there.

const SITE = () => process.env.PUBLIC_BASE_URL || 'https://cutsign.vercel.app';
// what a card page may load while it prints: its own site (the page, lifecycle.js, the cards JSON)
// and the two Google Fonts hosts the cards name. Everything else is refused.
const FONT_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com'];

// Tests swap this in place of Chromium.
let renderer = null;
export function _setRenderer(fn) { renderer = fn; }

/** Print one page of this site to PDF bytes. Throws on anything but a 200 page. */
export async function renderPdf(url, { timeoutMs = 30_000 } = {}) {
  const origin = new URL(SITE()).origin;
  if (new URL(url).origin !== origin) throw new Error('renderPdf prints pages of this site only');
  if (renderer) return renderer(url);
  const { default: puppeteer } = await import('puppeteer-core');
  let launch;
  if (process.env.CHROME_PATH) launch = { executablePath: process.env.CHROME_PATH, headless: true }; // a local run: desktop Chrome
  else {
    const { default: chromium } = await import('@sparticuz/chromium');
    launch = { args: await puppeteer.defaultArgs({ args: chromium.args, headless: 'shell' }), executablePath: await chromium.executablePath(), headless: 'shell' };
  }
  const browser = await puppeteer.launch({ ...launch, defaultViewport: { width: 1100, height: 1400, deviceScaleFactor: 1 } });
  try {
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', (r) => {
      let ok = false;
      try { const u = new URL(r.url()); ok = u.protocol === 'data:' || u.origin === origin || FONT_HOSTS.includes(u.hostname); } catch { ok = false; }
      if (ok) r.continue(); else r.abort();
    });
    await page.emulateMediaType('print');
    // the hand cards print dark whatever the theme; the AI card pages follow the color scheme, so ask for dark
    await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'dark' }]);
    const res = await page.goto(url, { waitUntil: 'networkidle0', timeout: timeoutMs });
    if (!res || res.status() !== 200) throw new Error(`the card page answered ${res ? res.status() : 'nothing'}`);
    await page.evaluate(() => document.fonts.ready);
    return Buffer.from(await page.pdf({ format: 'letter', printBackground: true, preferCSSPageSize: true, timeout: timeoutMs }));
  } finally {
    await browser.close().catch(() => {});
  }
}
