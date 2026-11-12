// AMB גמ"ח – service worker: מאפשר התקנה ועבודה גם בלי חיבור לרשת
const CACHE = 'amb-gemach-v3.2';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icons/icon.svg', './icons/icon-192.png', './icons/icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET') return;
  const u = new URL(r.url);
  // הדף עצמו: קודם רשת (לקבלת עדכונים), ואם אין חיבור – מהמטמון
  if (r.mode === 'navigate' || (u.origin === location.origin && u.pathname.endsWith('/index.html'))) {
    e.respondWith(fetch(r).then(res => { const c = res.clone(); caches.open(CACHE).then(x => x.put('./index.html', c)); return res; })
      .catch(() => caches.match('./index.html')));
    return;
  }
  // שאר הקבצים (אייקונים, ספריית האקסל): מהמטמון, ואם אין – מהרשת ושמירה
  if (u.origin === location.origin || u.hostname === 'cdnjs.cloudflare.com') {
    e.respondWith(caches.match(r).then(hit => hit || fetch(r).then(res => {
      if (res.ok) { const c = res.clone(); caches.open(CACHE).then(x => x.put(r, c)); }
      return res;
    })));
  }
});
