// Basic service worker for a PWA
self.addEventListener('install', (e) => {
  console.log('[Service Worker] Install');
});

self.addEventListener('fetch', function(event) {
  // This is a minimal fetch event listener.
  // You might want to cache your site's assets for offline use.
});
