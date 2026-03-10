const CACHE_NAME = 'ticket-cache-v1';
const APP_SHELL = ['/', '/index.html', '/manifest.webmanifest'];

// Simple IndexedDB wrapper for request queue
const idbOpen = () =>
  new Promise((resolve, reject) => {
    const req = indexedDB.open('ticket-sw', 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('queue')) {
        db.createObjectStore('queue', { keyPath: 'id', autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

async function queueRequest(record) {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('queue', 'readwrite');
    tx.objectStore('queue').add(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getAllQueued() {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('queue', 'readonly');
    const req = tx.objectStore('queue').getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

async function clearQueue() {
  const db = await idbOpen();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('queue', 'readwrite');
    tx.objectStore('queue').clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
      )
      .then(() => self.clients.claim())
  );
});

// Replay queued requests
async function replayQueue() {
  const items = await getAllQueued();
  if (!items.length) return;
  for (const r of items) {
    try {
      const headers = new Headers(r.headers || {});
      const body = r.body ? (r.isForm ? r.body : JSON.stringify(r.body)) : undefined;
      const init = { method: r.method, headers, body };
      await fetch(r.url, init);
    } catch (e) {
      // if any fails, keep queue for next attempt
      return;
    }
  }
  await clearQueue();
}

self.addEventListener('sync', (e) => {
  if (e.tag === 'retry-queue') {
    e.waitUntil(replayQueue());
  }
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'REPLAY_QUEUE') {
    replayQueue();
  }
});

function shouldQueue(url, method) {
  if (method !== 'POST') return false;
  return /\/api\/tickets(\/\d+\/replies)?$/i.test(url);
}

self.addEventListener('fetch', (e) => {
  const url = e.request.url;
  const method = e.request.method;
  if (method === 'GET') {
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(e.request, copy));
          return res;
        })
        .catch(() => caches.match(e.request).then((res) => res || caches.match('/index.html')))
    );
    return;
  }

  if (shouldQueue(url, method)) {
    e.respondWith(
      fetch(e.request).catch(async () => {
        let body = null;
        let isForm = false;
        try {
          const contentType = e.request.headers.get('content-type') || '';
          if (contentType.includes('multipart/form-data')) {
            // Can't clone multipart easily; store minimal JSON with message only.
            // Client should resend attachment later or rely on message-only fallback.
            const form = await e.request.clone().formData();
            body = Object.fromEntries(form.entries());
            isForm = true;
          } else {
            body = await e.request.clone().json();
          }
        } catch (_) {
          body = null;
        }
        await queueRequest({
          url,
          method,
          headers: Object.fromEntries(e.request.headers.entries()),
          body,
          isForm
        });
        try {
          if ('sync' in self.registration) {
            await self.registration.sync.register('retry-queue');
          }
        } catch (_) {}
        return new Response(JSON.stringify({ queued: true, offline: true }), {
          status: 202,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
  }
});
