// OPFS synchronous access works in workers on mobile browsers that do not
// expose the desktop save picker or asynchronous createWritable API.
interface SyncFile {
  write(buffer: ArrayBuffer, options: { at: number }): number;
  flush(): void;
  close(): void;
}
let file: SyncFile | undefined;
let offset = 0;
self.onmessage = async (event: MessageEvent<{ id: number; type: string; handle?: FileSystemFileHandle; chunk?: ArrayBuffer }>) => {
  const { id, type, handle, chunk } = event.data;
  try {
    if (type === 'open' && handle) {
      file = await (handle as FileSystemFileHandle & { createSyncAccessHandle(): Promise<SyncFile> }).createSyncAccessHandle();
    } else if (type === 'write' && file && chunk) {
      const written = file.write(chunk, { at: offset });
      if (written !== chunk.byteLength) throw new Error('storage_write_failed');
      offset += written;
    } else if (type === 'close' && file) {
      file.flush();
      file.close();
      file = undefined;
    } else if (type === 'abort') {
      file?.close();
      file = undefined;
    } else throw new Error('storage_unavailable');
    self.postMessage({ id });
  } catch (error) {
    self.postMessage({ id, error: error instanceof Error ? error.name : 'storage_write_failed' });
  }
};
export {};
