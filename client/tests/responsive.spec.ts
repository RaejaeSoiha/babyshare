import { test, expect, type Page } from '@playwright/test';

const longName = 'VeryLongNameWithoutSpaces'.repeat(6);
async function mockWorkspace(page: Page) {
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    const payload = path === '/api/me' ? { user: longName, isAdmin: true }
      : path === '/api/admin/overview' ? { usersCount: 1, guestsCount: 0 }
      : path === '/api/admin/users' ? { users: [{ username: longName, fileCount: 0 }] }
      : path === '/api/lan/devices' ? { devices: [{ id: 'peer', displayName: longName, deviceName: longName, platform: 'Desktop', online: true }] }
      : path === '/api/lan/chats' ? { chats: [{ id: 'chat', peerId: 'peer', peerName: longName, status: 'active', direction: 'outgoing', messages: [{ id: 'message', mine: true, text: longName, sentAt: Date.now() }] }] }
      : path === '/api/lan/transfers' ? { transfers: [{ id: 'transfer', name: longName + '.pdf', peerName: longName, peerId: 'peer', status: 'completed', direction: 'outgoing', size: 1024, progress: 100, updatedAt: Date.now() }] }
      : { signals: [] };
    return route.fulfill({ json: payload });
  });
}
async function expectFits(page: Page) {
  await expect.poll(() => page.evaluate(() => [...document.querySelectorAll('body *')].filter(el => {
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    if (!rect.width || !rect.height || style.visibility === 'hidden' || el.closest('.bg-canvas, .starfield, .visually-hidden, .dashboard-file-input')) return false;
    // Check actual elements, even when the document conceals overflow with clipping.
    return rect.left < -1 || rect.right > innerWidth + 1;
  }).map(el => `${el.tagName}.${el.className}`).slice(0, 12))).toEqual([]);
}
for (const width of [320, 375, 680, 768, 900, 1024, 1440, 2560]) {
  test(`all routes fit ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 768 ? 360 : 900 });
    await mockWorkspace(page);
    for (const path of ['/', '/login', '/register', '/guest-upload', '/guest-receive', '/dashboard', '/files', '/admin', '/settings', '/missing']) {
      await page.goto(path);
      await page.locator('.page, .home-page').first().waitFor();
      if (path === '/dashboard') {
        await page.getByText('Choose files and a recipient').waitFor();
        await page.locator('input[type=file]').first().setInputFiles({ name: longName + '.pdf', mimeType: 'application/pdf', buffer: Buffer.from('test') });
      }
      if (path === '/files') await page.locator('.transfer-history-status').waitFor();
      if (path === '/admin') await page.locator('.admin-user-row').waitFor();
      await expectFits(page);
      if (path === '/admin') {
        await page.getByRole('button', { name: 'Reset password', exact: true }).click();
        await expectFits(page);
        await page.getByRole('button', { name: 'Close password reset' }).click();
      }
      if (path === '/') {
        await page.getByRole('button', { name: /Open Nearby Users/ }).click();
        await expectFits(page);
      }
      if (path === '/dashboard') {
        await page.getByRole('button', { name: /Open Online Users/ }).click();
        await page.locator('.workspace-chat-user').first().click();
        await expectFits(page);
      }
    }
  });
}

test('chat stays on screen after dragging and resizing', async ({ page }) => {
  await mockWorkspace(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/dashboard');
  await page.getByRole('button', { name: /Open Online Users/ }).click();
  const header = page.locator('.workspace-chat-header');
  const bounds = (await header.boundingBox())!;
  await page.mouse.move(bounds.x + 60, bounds.y + 15);
  await page.mouse.down();
  await page.mouse.move(1300, 700);
  await page.mouse.up();
  for (const size of [{ width: 800, height: 400 }, { width: 320, height: 240 }]) {
    await page.setViewportSize(size);
    await expectFits(page);
    const dock = (await page.locator('.workspace-chat-dock').boundingBox())!;
    expect(dock.y).toBeGreaterThanOrEqual(0);
    expect(dock.y + dock.height).toBeLessThanOrEqual(size.height);
  }
});

test('public password, guest and error documents fit narrow screens', async ({ page }) => {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const { renderPasswordPrompt, renderGuestAccess, renderError } = require('../../src/utils/html.js');
  await page.setViewportSize({ width: 320, height: 360 });
  for (const html of [
    renderPasswordPrompt({ title: 'Protected file', filename: longName, actionUrl: '/' }),
    renderGuestAccess({ filename: longName, previewUrl: '/', downloadUrl: '/' }),
    renderError('File unavailable', longName),
  ]) {
    await page.setContent(html);
    await expectFits(page);
  }
});
