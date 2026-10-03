export interface ReceiveSink {
  write(chunk: ArrayBuffer): Promise<void>;
  close(type?: string): Promise<Blob | undefined>;
  dispose(): Promise<void>;
}
const MEMORY_LIMIT = 32 * 1024 * 1024;
const PREFIX = 'babyshare-receive-';

declare global {
  interface Window {
    showSaveFilePicker?: (options?: { suggestedName?: string }) => Promise<{ createWritable: () => Promise<FileSystemWritableFileStream> }>;
  }
}

export function receiveStorageError(error: unknown): string {
  if (error instanceof Error && (error.name === 'QuotaExceededError' || error.message === 'storage_full')) {
    return 'Not enough free storage for this file. Free some space on this device and try again.';
  }
  if (error instanceof Error && error.message === 'storage_unavailable') {
    return 'File storage is unavailable in this browser. Open BabyShare over HTTPS in an updated browser, outside private browsing, and try again.';
  }
  return 'The file could not be saved on this device. Check available storage and try again.';
}

export async function createReceiveSink(name: string, size: number): Promise<ReceiveSink> {
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error('invalid_file_size');
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: name });
      const writer = await handle.createWritable();
      let closed = false;
      return {
        write: chunk => writer.write(chunk),
        close: async () => { await writer.close(); closed = true; return undefined; },
        dispose: async () => { if (!closed) await writer.abort().catch(() => {}); },
      };
    } catch (error) {
      // Respect cancelling the picker; unsupported/blocked pickers can use OPFS.
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
    }
  }
  if (navigator.storage?.getDirectory) {
    let directory: FileSystemDirectoryHandle | undefined;
    const key = `${PREFIX}${Date.now()}-${crypto.randomUUID()}`;
    let worker: Worker | undefined;
    try {
      directory = await navigator.storage.getDirectory();
      // Reclaim abandoned partial downloads on a later visit, without touching
      // another tab's current transfers or any unrelated origin data.
      for await (const entry of (directory as FileSystemDirectoryHandle & { keys(): AsyncIterableIterator<string> }).keys()) {
        if (entry.startsWith(PREFIX) && Number(entry.slice(PREFIX.length).split('-')[0]) < Date.now() - 86_400_000) {
          await directory.removeEntry(entry).catch(() => {});
        }
      }
      const estimate = await navigator.storage.estimate().catch(() => ({} as StorageEstimate));
      if (estimate.quota !== undefined && size > estimate.quota - (estimate.usage ?? 0)) throw new Error('storage_full');
      const handle = await directory.getFileHandle(key, { create: true });
      worker = new Worker(new URL('./receiveStorage.worker.ts', import.meta.url), { type: 'module' });
      const storageWorker = worker;
      let nextId = 0;
      let disposed = false;
      let failed = false;
      let disposing: Promise<void> | undefined;
      const pending = new Map<number, { resolve: () => void; reject: (error: Error) => void }>();
      storageWorker.onmessage = (event: MessageEvent<{ id: number; error?: string }>) => {
        const call = pending.get(event.data.id);
        pending.delete(event.data.id);
        if (event.data.error) {
          const error = new Error(event.data.error);
          error.name = event.data.error;
          call?.reject(error);
        } else call?.resolve();
      };
      storageWorker.onerror = () => {
        failed = true;
        for (const call of pending.values()) call.reject(new Error('storage_unavailable'));
        pending.clear();
      };
      const request = (type: string, chunk?: ArrayBuffer) => new Promise<void>((resolve, reject) => {
        if (failed) return reject(new Error("storage_unavailable"));
        if (disposed) return reject(new Error('storage_closed'));
        const id = ++nextId;
        pending.set(id, { resolve, reject });
        storageWorker.postMessage({ id, type, ...(type === 'open' ? { handle } : {}), chunk }, chunk ? [chunk] : []);
      });
      await request('open');
      return {
        write: chunk => request('write', chunk),
        close: async (type = 'application/octet-stream') => {
          await request('close');
          // A disk-backed File/Blob avoids assembling the entire transfer in RAM.
          return (await handle.getFile()).slice(0, size, type);
        },
        dispose: () => disposing ??= (async () => {
          await request('abort').catch(() => {});
          disposed = true;
          storageWorker.terminate();
          await directory!.removeEntry(key).catch(() => {});
        })(),
      };
    } catch (error) {
      worker?.terminate();
      await directory?.removeEntry(key).catch(() => {});
      if (size > MEMORY_LIMIT) {
        if (error instanceof Error && (error.name === 'QuotaExceededError' || error.message === 'storage_full')) throw error;
        throw new Error('storage_unavailable');
      }
    }
  }
  if (size > MEMORY_LIMIT) throw new Error('storage_unavailable');
  let chunks: ArrayBuffer[] = [];
  let bytes = 0;
  return {
    write: async chunk => {
      bytes += chunk.byteLength;
      if (bytes > size) throw new Error('file_size_mismatch');
      chunks.push(chunk);
    },
    close: async type => { const blob = new Blob(chunks, { type }); chunks = []; return blob; },
    dispose: async () => { chunks = []; },
  };
}
