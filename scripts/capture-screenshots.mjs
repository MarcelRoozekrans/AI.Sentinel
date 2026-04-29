// Captures dashboard + chat screenshots at three viewports.
// Usage: node scripts/capture-screenshots.mjs http://localhost:5160
import { chromium } from 'playwright';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const baseUrl = process.argv[2] ?? 'http://localhost:5160';
const outDir = path.resolve(__dirname, '..', 'docs', 'assets', 'screenshots');

const viewports = [
  { name: 'desktop', width: 1920, height: 1080 },
  { name: 'tablet',  width: 768,  height: 1024 },
  { name: 'mobile',  width: 375,  height: 812  },
];

const pages = [
  { slug: 'dashboard', url: `${baseUrl}/ai-sentinel/`, waitFor: 'AI.Sentinel' },
  { slug: 'chat',      url: `${baseUrl}/`,             waitFor: 'AI Chat' },
];

const browser = await chromium.launch({ headless: true });
try {
  for (const vp of viewports) {
    for (const p of pages) {
      const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
      const page = await ctx.newPage();
      await page.goto(p.url, { waitUntil: 'domcontentloaded' });
      await page.getByText(p.waitFor).first().waitFor({ timeout: 15_000 });
      await page.waitForTimeout(3_500); // let HTMX poll once and SSE arc fill
      const file = path.join(outDir, `${p.slug}-${vp.name}.png`);
      await page.screenshot({ path: file, fullPage: true });
      console.log('saved', file);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}
