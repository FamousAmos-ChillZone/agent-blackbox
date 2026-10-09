/**
 * Real-browser pass of the Blackbox dashboard (LES-002, KI-199) — the browser half.
 *
 * Opens the dashboard at desktop (1440) and phone (390) widths, lands, switches
 * to the Community tab, and writes one JSON summary per viewport: console
 * errors, page errors, failed requests, horizontal overflow and the text of
 * the sections the Refine work added. `tests/plugins/test_blackbox_dashboard_browser.py`
 * serves a fixture app, runs this script and asserts on the summary.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/dashboard_browser_pass.mjs <base url> <out dir>
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const base = process.argv[2];
const outDir = process.argv[3] || ".";
const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 390, height: 844 },
];

const launch = process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {};
const browser = await chromium.launch(launch);
const summary = [];
for (const vp of viewports) {
  const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];
  page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 300)); });
  page.on("pageerror", (err) => pageErrors.push(String(err.stack || err).slice(0, 600)));
  page.on("requestfailed", (req) => failedRequests.push(`${req.method()} ${req.url()} — ${req.failure()?.errorText}`));
  page.on("response", (res) => { if (res.status() >= 400) failedRequests.push(`${res.status()} ${res.url()}`); });

  await page.goto(base, { waitUntil: "domcontentloaded", timeout: 30000 });
  try { await page.waitForLoadState("networkidle", { timeout: 15000 }); } catch { /* the page polls */ }
  await page.waitForTimeout(3000);

  const overflow = async (label) => page.evaluate((label) => {
    const doc = document.documentElement;
    return { label, scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth,
             horizontalOverflow: doc.scrollWidth > doc.clientWidth };
  }, label);
  const sectionText = async (id) => page.evaluate((id) => {
    const el = document.getElementById(id);
    return el ? (el.innerText || "").replace(/\s+/g, " ").trim().slice(0, 400) : null;
  }, id);
  const cellSqueeze = async () => page.evaluate(() => {
    // In the phone card mode (rows laid out as a grid) a track collapsing under an
    // unbreakable token leaves a cell a few pixels wide: text spills over its
    // neighbour, or wraps one character per line (KI-200). In the two Refine
    // tables this pass certifies, flag any grid cell narrower than 25% of its
    // row, or spilling past its box.
    const squeezed = [];
    const tables = 'table[aria-label="Community statements"] tbody tr, table[aria-label="My reports"] tbody tr';
    for (const tr of document.querySelectorAll(tables)) {
      if (getComputedStyle(tr).display !== "grid") continue;
      const rowWidth = tr.getBoundingClientRect().width;
      for (const td of tr.querySelectorAll("td")) {
        if (!td.innerText.trim() || td.colSpan > 1) continue;
        const width = td.getBoundingClientRect().width;
        if (width < rowWidth * 0.25 || td.scrollWidth > td.clientWidth + 1) {
          squeezed.push(`${Math.round(width)}px of ${Math.round(rowWidth)}px: ${td.innerText.trim().slice(0, 40)}`);
        }
      }
    }
    return squeezed.slice(0, 8);
  });

  const checks = [await overflow("landing")];
  const sections = {};
  for (const id of ["health-strip", "community-statements-body", "my-reports-body", "tab-community",
                    "stat-community-count", "stat-sharing-state", "cg-summary",
                    "vs-pct", "vs-chip", "vs-val-downloaded", "vs-note"]) sections[id] = await sectionText(id);
  // The community panel's own tabs: each pane renders without page overflow.
  for (const pane of ["statements", "reports", "agents"]) {
    const tab = page.locator(`#cg-tab-${pane}`);
    if (await tab.count()) { await tab.click(); await page.waitForTimeout(300); checks.push(await overflow(`community-${pane}`)); }
  }
  const spillingCells = await cellSqueeze();
  const communityTab = page.locator("#tab-community");
  if (await communityTab.count()) {
    await communityTab.click();
    await page.waitForTimeout(2500);
    checks.push(await overflow("community-tab"));
  }
  summary.push({ viewport: vp, consoleErrors, pageErrors, failedRequests, checks, sections, spillingCells });
  await context.close();
}
await browser.close();
writeFileSync(`${outDir}/dashboard-browser-summary.json`, JSON.stringify(summary, null, 2));
