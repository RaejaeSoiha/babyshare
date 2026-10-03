import { test as base, expect } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// WebKit's ephemeral automation contexts deny OPFS; exercise normal browsing
// with an isolated persistent profile and delete it after every test.
const test = base.extend({
  context: async ({ playwright, browserName }, provideContext) => {
    const directory = await mkdtemp(join(tmpdir(), 'babyshare-mobile-test-'));
    const context = await playwright[browserName].launchPersistentContext(directory, {
      baseURL: 'http://127.0.0.1:3000', viewport: { width: 390, height: 844 },
    });
    try { await provideContext(context); } finally { await context.close(); await rm(directory, { recursive: true, force: true }); }
  },
});

test('40 MiB transfers through WebRTC to mobile storage without a save picker', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('/guest-receive');
  const result = await page.evaluate(async () => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
    const storagePath = '/src/lib/receiveStorage.ts';
    const sendPath = '/src/lib/sendFileChunks.ts';
    const { createReceiveSink } = await import(storagePath);
    const { sendFileChunks } = await import(sendPath);
    const block = new Uint8Array(64 * 1024).map((_, index) => index % 251);
    const original = new File(Array.from({ length: 640 }, () => block), 'mobile-large.bin');
    const sink = await createReceiveSink(original.name, original.size);
    const sender = new RTCPeerConnection();
    const receiver = new RTCPeerConnection();
    sender.onicecandidate = event => { if (event.candidate) void receiver.addIceCandidate(event.candidate); };
    receiver.onicecandidate = event => { if (event.candidate) void sender.addIceCandidate(event.candidate); };
    let received = 0;
    let stored: Blob | undefined;
    let queue = Promise.resolve();
    receiver.ondatachannel = event => {
      const channel = event.channel;
      channel.binaryType = 'arraybuffer';
      channel.onmessage = message => {
        queue = queue.then(async () => {
          if (typeof message.data === 'string') {
            stored = await sink.close();
            channel.send(JSON.stringify({ type: 'saved' }));
          } else {
            const size = message.data.byteLength;
            await sink.write(message.data);
            received += size;
            channel.send(JSON.stringify({ type: 'ack', bytes: received }));
          }
        });
      };
    };
    const channel = sender.createDataChannel('file');
    const opened = new Promise<void>(resolve => { channel.onopen = () => resolve(); });
    await sender.setLocalDescription(await sender.createOffer());
    await receiver.setRemoteDescription(sender.localDescription!);
    await receiver.setLocalDescription(await receiver.createAnswer());
    await sender.setRemoteDescription(receiver.localDescription!);
    await opened;
    try {
      const transfer = await sendFileChunks(channel, original, () => {});
      channel.send(JSON.stringify({ type: 'complete' }));
      await transfer.waitForSave();
      transfer.dispose();
      const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', await original.arrayBuffer()));
      const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', await stored!.arrayBuffer()));
      return { size: stored!.size, equal: expected.every((byte, index) => byte === actual[index]) };
    } finally {
      sender.close(); receiver.close(); await sink.dispose();
    }
  });
  expect(result).toEqual({ size: 40 * 1024 * 1024, equal: true });
});

test('temporary storage is removed on cancellation and quota errors are actionable', async ({ page }) => {
  await page.goto('/guest-receive');
  const result = await page.evaluate(async () => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
    const modulePath = '/src/lib/receiveStorage.ts';
    const { createReceiveSink, receiveStorageError } = await import(modulePath);
    const root = await navigator.storage.getDirectory();
    const entries = async () => { const names = []; for await (const name of (root as unknown as { keys(): AsyncIterableIterator<string> }).keys()) if (name.startsWith('babyshare-receive-')) names.push(name); return names.length; };
    const before = await entries();
    const sink = await createReceiveSink('cancel.bin', 40 * 1024 * 1024);
    await sink.write(new ArrayBuffer(64 * 1024));
    const during = await entries();
    await sink.dispose();
    Object.defineProperty(navigator.storage, 'estimate', { value: async () => ({ usage: 0, quota: 1 }), configurable: true });
    let error = '';
    try { await createReceiveSink('too-big.bin', 40 * 1024 * 1024); } catch (cause) { error = receiveStorageError(cause); }
    return { before, during, after: await entries(), error };
  });
  expect(result.during).toBe(result.before + 1);
  expect(result.after).toBe(result.before);
  expect(result.error).toContain('Not enough free storage');
});

test('QR screens send and receive a 40 MiB file without a desktop save dialog', async ({ context }) => {
  test.setTimeout(90_000);
  await context.addInitScript(() => Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }));
  const token = 'a'.repeat(32);
  const pairing = { status: 'waiting', expiresAt: Date.now() + 600_000, file: { name: 'mobile.bin', size: 40 * 1024 * 1024 } };
  const signals: Record<string, unknown[]> = { sender: [], receiver: [] };
  await context.route('**/api/**', async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (!path.startsWith('/api/qr/')) {
      return route.fulfill({ json: path.endsWith('/devices') ? { devices: [] } : path.endsWith('/chats') ? { chats: [] } : path.endsWith('/transfers') ? { transfers: [] } : {} });
    }
    if (path === '/api/qr/pairings') return route.fulfill({ json: { pairToken: token, senderSecret: 'sender', shortCode: '1234', expiresAt: pairing.expiresAt, url: `http://127.0.0.1:3000/guest-receive?pair=${token}` } });
    if (path.endsWith('/claim')) { pairing.status = 'claimed'; return route.fulfill({ json: { pairing, receiverSecret: 'receiver' } }); }
    if (path.endsWith('/accept')) pairing.status = 'accepted';
    if (path.endsWith('/complete')) pairing.status = 'complete';
    if (path.endsWith('/signals')) {
      const role = request.headers()['x-babyshare-qr-role'];
      if (request.method() === 'POST') { signals[role === 'sender' ? 'receiver' : 'sender'].push(request.postDataJSON().signal); return route.fulfill({ json: { ok: true } }); }
      return route.fulfill({ json: { signals: signals[role].splice(0) } });
    }
    return route.fulfill({ json: { pairing } });
  });
  try {
    const sender = await context.newPage();
    await sender.goto('http://127.0.0.1:3000/guest-upload');
    await sender.locator('input[type=file]').setInputFiles({ name: 'mobile.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(40 * 1024 * 1024, 37) });
    await sender.getByRole('button', { name: /Create.*QR/i }).click();
    await expect(sender.getByText('Scan this QR code.')).toBeVisible();
    const receiver = await context.newPage();
    await receiver.goto(`http://127.0.0.1:3000/guest-receive?pair=${token}`);
    await receiver.getByRole('button', { name: 'Review and accept file' }).click();
    await expect(receiver.getByText('Your file is ready.')).toBeVisible({ timeout: 60_000 });
    await expect(sender.getByText('File sent directly.')).toBeVisible({ timeout: 10_000 });
    const size = await receiver.getByRole('link', { name: 'Download file' }).evaluate(async link => {
      const bytes = new Uint8Array(await (await fetch((link as HTMLAnchorElement).href)).arrayBuffer());
      if (!bytes.every(byte => byte === 37)) throw new Error('file_corrupted');
      return bytes.length;
    });
    expect(size).toBe(40 * 1024 * 1024);
  } finally { await context.close(); }
});

test('workspace screens transfer 40 MiB to a receiver without a save picker', async ({ context }) => {
  test.setTimeout(90_000);
  await context.addInitScript(() => Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }));
  const sender = await context.newPage();
  const receiver = await context.newPage();
  let status = '';
  let reportedBytes = 0;
  const signals: Record<string, unknown[]> = { sender: [], receiver: [] };
  for (const [role, page] of [['sender', sender], ['receiver', receiver]] as const) {
    const peer = role === 'sender' ? 'receiver' : 'sender';
    await page.route('**/api/**', route => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      const transfer = () => ({ id: 'large', peerId: peer, peerName: peer, direction: role === 'sender' ? 'outgoing' : 'incoming', name: 'mobile.bin', size: 40 * 1024 * 1024, transport: 'peer', status, progress: status === 'completed' ? 100 : 0, createdAt: Date.now(), updatedAt: Date.now() });
      if (path === '/api/me') return route.fulfill({ json: { user: role, isAdmin: false } });
      if (path.endsWith('/devices')) return route.fulfill({ json: { devices: [{ id: peer, displayName: peer, deviceName: peer, platform: 'Mobile', online: true }] } });
      if (path.endsWith('/chats')) return route.fulfill({ json: { chats: [] } });
      if (path.endsWith('/transfers')) return route.fulfill({ json: { transfers: status ? [transfer()] : [] } });
      if (path.endsWith('/transfers/request')) { status = 'pending'; return route.fulfill({ json: { transfers: [transfer()] } }); }
      if (path.endsWith('/accept')) status = 'accepted';
      if (path.endsWith('/peer-start')) status = 'receiving';
      if (path.endsWith('/peer-progress')) {
        if (status !== 'receiving') return route.fulfill({ status: 409, json: { error: 'transfer_unavailable' } });
        reportedBytes = request.postDataJSON().bytesTransferred;
      }
      if (path.endsWith('/peer-complete')) {
        if (status !== 'receiving' || reportedBytes !== 40 * 1024 * 1024) return route.fulfill({ status: 409, json: { error: 'transfer_incomplete' } });
        status = 'completed';
      }
      if (path.endsWith('/cancel')) status = 'cancelled';
      if (path.endsWith('/signals')) {
        if (request.method() === 'POST') { signals[peer].push({ senderId: role, signal: request.postDataJSON().signal }); return route.fulfill({ json: { ok: true } }); }
        return route.fulfill({ json: { signals: signals[role].splice(0) } });
      }
      return route.fulfill({ json: { transfer: transfer() } });
    });
  }
  await sender.goto('http://127.0.0.1:3000/dashboard');
  await receiver.goto('http://127.0.0.1:3000/dashboard');
  await sender.locator('input[type=file]').first().setInputFiles({ name: 'mobile.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(40 * 1024 * 1024, 19) });
  await sender.getByRole('button', { name: 'Request direct transfer', exact: true }).click();
  await receiver.getByRole('button', { name: 'Accept file', exact: true }).click();
  await expect(receiver.getByRole('button', { name: 'Save file', exact: true })).toBeVisible({ timeout: 60_000 });
  expect(status).toBe('completed');
  const downloadPromise = receiver.waitForEvent('download');
  await receiver.getByRole('button', { name: 'Save file', exact: true }).click();
  const download = await downloadPromise;
  const { readFile } = await import('node:fs/promises');
  const bytes = await readFile((await download.path())!);
  expect(bytes.length).toBe(40 * 1024 * 1024);
  expect(bytes.every(byte => byte === 19)).toBe(true);
});
