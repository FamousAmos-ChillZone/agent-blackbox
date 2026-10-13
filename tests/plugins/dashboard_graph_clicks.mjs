/**
 * Every graph bubble opens something — the browser half of
 * `tests/plugins/test_blackbox_dashboard_graph_clicks.py`.
 *
 * For each tier named on the command line, switches to that graph tab, lets the
 * force layout settle, then finds the bubbles the way a person does: sweeps the
 * mouse over the canvas and reads the hover card. It clicks each bubble it found
 * (closing any open window in between) and records whether the detail window
 * opened and with which title. The graph's node positions are not exposed, so
 * the hover card is the only honest way to know what is under the pointer.
 *
 *   PW_EXEC=<chromium> node tests/plugins/dashboard_graph_clicks.mjs <base url> <out.json> local community
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const [base, out, ...tiers] = process.argv.slice(2);
const STEP = 9;
const launch = process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {};
const browser = await chromium.launch(launch);
const page = await browser.newPage({ viewport: { width: 1440, height: 1800 }, deviceScaleFactor: 1 });
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));
await page.goto(base, { waitUntil: "load" });
await page.waitForTimeout(2500);

const hoverCard = () => page.evaluate(() => {
  const tip = document.querySelector(".graph-tip");
  return tip && tip.offsetParent ? tip.innerText.replace(/\n/g, " | ") : "";
});

const result = { pageErrors, tiers: {} };
for (const tier of tiers) {
  await page.locator("#tab-" + tier).click();
  const canvas = page.locator("canvas").first();
  await canvas.scrollIntoViewIfNeeded();
  await page.waitForTimeout(4500);                     // the force layout settles
  const box = await canvas.boundingBox();
  const found = {};
  for (let y = box.y + 8; y < box.y + box.height - 8; y += STEP) {
    for (let x = box.x + 8; x < box.x + box.width - 8; x += STEP) {
      await page.mouse.move(x, y);
      const card = await hoverCard();
      if (card && !found[card]) found[card] = { x, y };
    }
  }
  const clicks = [];
  for (const [card, point] of Object.entries(found)) {
    const kind = /click for details/.test(card) ? "type" : /^(Local|Community|Verifiable)\b/.test(card) ? "centre" : "threat";
    if (kind === "centre") continue;                    // the centre only reframes the graph
    await page.keyboard.press("Escape");
    await page.waitForTimeout(150);
    await page.mouse.click(point.x, point.y);
    await page.waitForTimeout(700);
    const opened = (await page.locator("#threat-modal.open").count()) > 0;
    const title = opened ? await page.locator("#tm-title").innerText() : "";
    const rows = opened ? await page.locator("#tm-body [data-local-idx]").count() : 0;
    clicks.push({ card: card.slice(0, 80), kind, opened, title, rows });
  }
  await page.keyboard.press("Escape");
  result.tiers[tier] = clicks;
}
writeFileSync(out, JSON.stringify(result, null, 1));
await browser.close();
