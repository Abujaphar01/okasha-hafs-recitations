// Service Worker for Okasha Kameny Hafs PWA (Offline Quran Audio)
const CACHE_NAME = 'okasha-hafs-v2.0';

const STATIC_ASSETS = [
  './',
  './index.html',
  './tailwind.min.css',
  './style.css',
  './app.js',
  './manifest.json',
  './img/sheikh_okasha.jpg',
  './img/sheikh_okasha_thumb.jpg',
  './icon-192.png',
  './icon-512.png'
];

// Install: Cache Core UI Assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate: Purge Outdated Caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

// Fetch: Strategy for Static Files & Audio Range Requests
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Enforce same-origin boundary on all fetch requests
  if (url.origin !== self.location.origin) {
    return; // Allow network directly, do not cache cross-origin
  }

  // Only handle GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Audio files (.mp3) - Cached on demand with Byte-Range support
  if (url.pathname.endsWith('.mp3')) {
    event.respondWith(handleAudioRequest(request));
    return;
  }

  // Static Assets (Cache First, fallback to Network)
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((networkRes) => {
        if (networkRes && networkRes.status === 200 && request.method === 'GET') {
          const clone = networkRes.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
        }
        return networkRes;
      }).catch(() => {
        if (request.mode === 'navigate') {
          return caches.match('./index.html');
        }
      });
    })
  );
});

// Audio Range Handler for Mobile & Desktop Offline Audio Playback
async function handleAudioRequest(request) {
  const cache = await caches.open(CACHE_NAME);
  const rangeHeader = request.headers.get('range');

  // Try network first if online, falling back to cache
  try {
    const networkResponse = await fetch(request);
    if (networkResponse && (networkResponse.status === 200 || networkResponse.status === 206)) {
      // If full 200 response, cache it for offline use
      if (networkResponse.status === 200) {
        cache.put(request.url, networkResponse.clone());
      }
      return networkResponse;
    }
  } catch (err) {
    // Offline or network failure: serve from cache
  }

  // Retrieve cached track
  const cachedResponse = await cache.match(request.url, { ignoreSearch: true });
  if (!cachedResponse) {
    return new Response('Audio unavailable offline. Please connect to internet to cache.', {
      status: 503,
      statusText: 'Service Unavailable',
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  // If no Range header, return full response
  if (!rangeHeader) {
    return cachedResponse;
  }

  // Build 206 Partial Content Response for Byte-Range Seeking
  const arrayBuffer = await cachedResponse.arrayBuffer();
  const totalLength = arrayBuffer.byteLength;
  const matches = rangeHeader.match(/bytes=(\d+)-(\d*)/);

  if (!matches) {
    return cachedResponse;
  }

  const start = parseInt(matches[1], 10);
  const end = matches[2] ? parseInt(matches[2], 10) : totalLength - 1;

  if (start >= totalLength || end >= totalLength) {
    return new Response('', {
      status: 416,
      statusText: 'Range Not Satisfiable',
      headers: { 'Content-Range': `bytes */${totalLength}` }
    });
  }

  const slicedBuffer = arrayBuffer.slice(start, end + 1);

  return new Response(slicedBuffer, {
    status: 206,
    statusText: 'Partial Content',
    headers: {
      'Content-Type': 'audio/mpeg',
      'Content-Range': `bytes ${start}-${end}/${totalLength}`,
      'Content-Length': slicedBuffer.byteLength,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public, max-age=31536000'
    }
  });
}
