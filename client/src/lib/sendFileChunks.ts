// Limit unacknowledged data to 1 MiB so a slow mobile disk cannot create an
// unbounded queue of chunks in the receiving tab's memory.
export async function sendFileChunks(channel: RTCDataChannel, file: File, onProgress: (bytes: number) => void | Promise<void>) {
  let acknowledged = 0;
  let sent = 0;
  let lastActivity = Date.now();
  let saved = false;
  const onMessage = (event: MessageEvent) => {
    if (typeof event.data !== 'string') return;
    try {
      const message = JSON.parse(event.data) as { type?: string; bytes?: number };
      if (message.type === 'ack' && Number.isSafeInteger(message.bytes) && message.bytes! > acknowledged && message.bytes! <= sent) {
        acknowledged = message.bytes!;
        lastActivity = Date.now();
      }
      if (message.type === 'saved' && acknowledged === file.size) saved = true;
    } catch { /* Ignore unrelated control messages. */ }
  };
  channel.addEventListener('message', onMessage);
  const wait = async (blocked: () => boolean) => {
    while (blocked()) {
      if (channel.readyState !== 'open') throw new Error('channel_closed');
      if (Date.now() - lastActivity > 60_000) throw new Error('receiver_stalled');
      await new Promise(resolve => window.setTimeout(resolve, 10));
    }
  };
  try {
    for (let offset = 0; offset < file.size; offset += 64 * 1024) {
      await wait(() => sent - acknowledged >= 1024 * 1024 || channel.bufferedAmount > 512 * 1024);
      if (channel.readyState !== 'open') throw new Error('channel_closed');
      const chunk = await file.slice(offset, offset + 64 * 1024).arrayBuffer();
      sent += chunk.byteLength;
      channel.send(chunk);
      await onProgress(acknowledged);
    }
    await wait(() => acknowledged < file.size);
    await onProgress(file.size);
    return {
      waitForSave: async () => { await wait(() => !saved); },
      dispose: () => channel.removeEventListener('message', onMessage),
    };
  } catch (error) {
    channel.removeEventListener('message', onMessage);
    throw error;
  }
}
