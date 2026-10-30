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

  // Build 206 Partial Content Response for Byte-Range Seeking per RFC 7233 / RFC 9110
  const arrayBuffer = await cachedResponse.arrayBuffer();
  const totalLength = arrayBuffer.byteLength;

  // 1. Suffix range handling: bytes=-<suffix>
  const suffixMatch = rangeHeader.match(/^bytes=-(\d+)$/);
  if (suffixMatch) {
    const suffix = parseInt(suffixMatch[1], 10);
    if (suffix === 0) {
      return new Response('', {
        status: 416,
        statusText: 'Range Not Satisfiable',
        headers: { 'Content-Range': `bytes */${totalLength}` }
      });
    }
    const start = Math.max(0, totalLength - suffix);
    const end = totalLength - 1;
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

  // 2. Standard range handling: bytes=<start>-<end?>
  const rangeMatch = rangeHeader.match(/^bytes=(\d+)-(\d*)$/);
  if (!rangeMatch) {
    return cachedResponse;
  }

  let start = parseInt(rangeMatch[1], 10);
  let end = rangeMatch[2] ? parseInt(rangeMatch[2], 10) : totalLength - 1;

  // Inverted range (start > end) or start out of bounds (start >= totalLength)
  if (start >= totalLength || (rangeMatch[2] && start > end)) {
    return new Response('', {
      status: 416,
      statusText: 'Range Not Satisfiable',
      headers: { 'Content-Range': `bytes */${totalLength}` }
    });
  }

  // Clamp end to totalLength - 1 per RFC 7233 Section 2.1
  if (end >= totalLength) {
    end = totalLength - 1;
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
