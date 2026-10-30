// End-to-end checks for the analyst console, run against the live backend.
// They follow the test checklist for SJSU-112 "Connect and test end to end".
// Warning: the first step restarts the backend replay, which clears its incidents.
import { expect, test } from '@playwright/test';

const API = process.env.E2E_API_URL;
const KEY = process.env.E2E_API_KEY;
const MIN_WARMUP = 150;      // replay at least this many windows first
const MIN_NEW_INCIDENTS = 5; // ...and keep going until there are incidents to work with (tests 4-8)
const MAX_WARMUP = 1500;     // Sai's test split has no attacks in its first ~550 windows
let warmed = 0;              // windows replayed by beforeAll

async function api(request, method, path, data) {
  const res = await request.fetch(API + path, { method, data, headers: { 'X-API-Key': KEY } });
  expect(res.ok(), `${method} ${path} -> ${res.status()}`).toBeTruthy();
  return res.json();
}

/** Window index shown in the replay bar, e.g. "Window 151 of 5,326". */
async function windowIndex(page) {
  await expect(page.locator('.replay-clock')).toContainText('Window');
  const text = await page.locator('.replay-clock').innerText();
  return Number(text.match(/Window ([\d,]+)/)[1].replace(/,/g, ''));
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ request }) => {
  const health = await request.get(`${API}/health`);
  expect(health.ok(), `Backend not reachable at ${API}. Start it first (backend/README.md).`).toBeTruthy();
  await api(request, 'POST', '/detect', { reset: true });
  warmed = 1;
  const enough = async () => (await api(request, 'GET', '/incidents')).incidents.filter((i) => i.status === 'new').length >= MIN_NEW_INCIDENTS;
  while (warmed < MAX_WARMUP && (warmed < MIN_WARMUP || (warmed % 25 !== 0 || !(await enough())))) {
    await api(request, 'POST', '/detect', {});
    warmed += 1;
  }
  expect(await enough(), `no incidents after ${warmed} windows`).toBeTruthy();
});

test('1. Overview loads data from the backend', async ({ page }) => {
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await expect(page.locator('.replay-clock')).toContainText(`Window ${warmed.toLocaleString('en-US')} of`);
  await expect(page.locator('.model-box strong')).not.toHaveText('…');
  await expect(page.locator('.kpi-value').first()).not.toHaveText('0');
  expect(errors).toEqual([]);
});

test('2. Step advances the replay by exactly one window', async ({ page }) => {
  await page.goto('/');
  const before = await windowIndex(page);
  await page.getByRole('button', { name: 'Step one window' }).click();
  await expect(page.locator('.replay-clock')).toContainText(`Window ${(before + 1).toLocaleString('en-US')} of`);
});

test('3. Play keeps detecting until Pause', async ({ page }) => {
  await page.goto('/');
  await page.locator('.replay-speed select').first().selectOption('250');
  const before = await windowIndex(page);
  await page.getByRole('button', { name: 'Play replay' }).click();
  await expect.poll(() => windowIndex(page), { timeout: 15_000 }).toBeGreaterThan(before + 2);
  await page.getByRole('button', { name: 'Pause replay' }).click();
  const paused = await windowIndex(page);
  await page.waitForTimeout(1500);
  expect(await windowIndex(page)).toBeLessThanOrEqual(paused + 1); // at most one in-flight window
});

test('4. New incidents wait behind the banner until Show updates', async ({ page }) => {
  await page.goto('/incidents');
  await expect(page.locator('.inc-cols.trow').first()).toBeVisible();
  await page.goto('/');
  for (let i = 0; i < 40; i++) await page.getByRole('button', { name: 'Step one window' }).click();
  await page.getByRole('link', { name: /Incidents/ }).first().click();
  const banner = page.locator('.banner');
  if (await banner.count()) {
    await expect(banner).toContainText('need');
    await page.getByRole('button', { name: 'Show updates' }).click();
    await expect(banner).toHaveCount(0);
  }
});

test('5. Incident detail shows explanation, evidence and the evidence funnel', async ({ page }) => {
  await page.goto('/incidents');
  await page.locator('.inc-cols.trow a').first().click();
  await expect(page).toHaveURL(/\/incidents\/INC-\d+/);
  await expect(page.locator('.sentence').first()).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('.evidence').first()).toBeVisible();
  await expect(page.locator('.funnel')).toContainText('Search by technique');
  await expect(page.locator('.funnel')).toContainText('MITRE');
  const detail = await page.request.get(`${API}${new URL(page.url()).pathname}`, { headers: { 'X-API-Key': KEY } });
  await expect(page.getByRole('heading', { name: /5-minute window/ })).toBeVisible();   // window graph (API 0.4.2)
  await page.getByRole('tab', { name: 'Network' }).click();
  await expect(page.getByRole('img', { name: 'Network graph of the window' })).toBeVisible();
  if ((await detail.json()).retrieval_trace?.behavior_check) {        // backend with the RAG behaviour check (API 0.4.2)
    await expect(page.getByRole('heading', { name: 'Behaviour check' })).toBeVisible();
  }
});

test('6. Confirm attack updates the status and the list counts', async ({ page, request }) => {
  const list = await api(request, 'GET', '/incidents');
  const target = list.incidents.find((i) => i.status === 'new');
  const confirmedBefore = list.incidents.filter((i) => i.status === 'confirmed').length;
  await page.goto(`/incidents/${target.incident_id}`);
  await page.getByRole('button', { name: 'Confirm attack' }).click();
  await expect(page.locator('.stepper .is-current')).toHaveText('Confirmed');
  await page.goto('/incidents');
  await expect(page.getByRole('tab', { name: /Confirmed/ })).toContainText(String(confirmedBefore + 1));
});

test('7. Mitigations and notes are saved, and the tab survives a reload', async ({ page, request }) => {
  const list = await api(request, 'GET', '/incidents');
  const id = list.incidents.find((i) => i.status === 'new').incident_id;
  await page.goto(`/incidents/${id}?tab=response`);
  await expect(page.getByRole('tab', { name: 'Response' })).toHaveAttribute('aria-selected', 'true');
  const box = page.locator('.check-row input').first();
  const name = (await page.locator('.check-row').first().innerText()).trim();
  await box.check();
  await expect(box).toBeChecked();
  await page.fill('#note', 'e2e note');
  await page.getByRole('button', { name: 'Add' }).click();
  await expect(page.locator('.activity').first()).toContainText('e2e note');

  await page.reload();
  await expect(page.getByRole('tab', { name: 'Response' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('.check-row input').first()).toBeChecked();
  await expect(page.locator('.activity').getByText(`analyst: Applied ${name}`)).toBeVisible();
  await expect(page.locator('.activity').getByText('Note: e2e note')).toBeVisible();
});

test('8. A closed incident can be reopened and the status corrected', async ({ page, request }) => {
  const list = await api(request, 'GET', '/incidents');
  const id = list.incidents.find((i) => i.status === 'new').incident_id;
  await api(request, 'PATCH', `/incidents/${id}`, { status: 'closed' });
  await page.goto(`/incidents/${id}`);
  await expect(page.locator('.stepper .is-current')).toHaveText('Closed');
  await page.getByRole('button', { name: 'Reopen' }).click();
  await expect(page.locator('.stepper .is-current')).toHaveText('Investigating');
  await page.locator('select[title^="Correct the status"]').selectOption('confirmed');
  await expect(page.locator('.stepper .is-current')).toHaveText('Confirmed');
});

test('9. After a jump, Traffic only shows the 6 hours before the clock', async ({ page, request }) => {
  const { replay } = await api(request, 'GET', '/incidents');
  // the first recorded day after the replay clock (the replay only moves forward)
  const day = replay.day_starts.find((d) => new Date(d) > new Date(new Date(replay.window_start).getTime() + 6 * 3600e3));
  await page.goto('/');
  const jump = page.locator('.replay-right select');
  await expect(jump.locator(`option[value="${day}"]`)).toBeAttached();
  await jump.selectOption(day);
  await expect(page.locator('.replay-clock')).toContainText(day.slice(11, 16));
  // Only the window just jumped to is within 6 hours, so each lane has one bar.
  await expect(page.locator('.lane .bars').first().locator('.bar')).toHaveCount(1);
  // flagged bars split into high-confidence (red) and the rest (yellow) (API 0.4.3)
  if (replay.day_starts && (await api(request, 'GET', '/incidents')).windows.some((w) => 'high_confidence_edges' in w)) {
    await expect(page.locator('.lane-key')).toContainText('of which p ≥ 0.80');
  }
});

test('10. Jump to offers only days with recorded traffic, including the last one', async ({ page, request }) => {
  const { replay } = await api(request, 'GET', '/incidents');
  await page.goto('/');
  const jump = page.locator('.replay-right select');
  await expect(jump.locator('option').nth(5)).toBeAttached();
  const days = await jump.locator('option').evaluateAll((o) => o.map((x) => x.value).filter(Boolean));
  if (replay.day_starts) expect(days).toEqual(replay.day_starts);   // gaps in the test split are skipped
  await jump.selectOption(days[days.length - 1]);
  await expect(page.locator('.replay-clock')).toContainText(days[days.length - 1].slice(11, 16));
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('11. A down backend shows a message instead of a blank page', async ({ page }) => {
  await page.route(`${API}/**`, (route) => route.abort());
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText("Can't reach the server");
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});

test('12. A wrong API key is explained', async ({ page }) => {
  await page.route(`${API}/**`, (route) => route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"Invalid API key"}' }));
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('API key was rejected');
});
