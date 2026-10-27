/* 공부노트: app/* 요청을 받아 enc/ 의 암호문을 복호화해 응답 */
const SALT = "gameplanner-cert-v1-11a2a301";
const SCOPE = new URL(self.registration.scope);
const TYPES = { webp: "image/webp", gif: "image/gif", html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", css: "text/css; charset=utf-8",
  jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", svg: "image/svg+xml", glb: "model/gltf-binary", txt: "text/plain; charset=utf-8", json: "application/json" };
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
function idbKey() {
  return new Promise(res => {
    const r = indexedDB.open("gameplanner-cert-gate", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onerror = () => res(null);
    r.onsuccess = () => { try { const g = r.result.transaction("k").objectStore("k").get("key"); g.onsuccess = () => res(g.result || null); g.onerror = () => res(null); } catch (e) { res(null); } };
  });
}
async function fileId(rel) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SALT + rel));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("").slice(0, 24);
}
function locked() { return Response.redirect(new URL("./?locked", SCOPE).href, 302); }
async function serve(rel) {
  const key = await idbKey();
  if (!key) return locked();
  const r = await fetch(new URL("enc/" + (await fileId(rel)) + ".bin", SCOPE));
  if (!r.ok) return new Response("Not found", { status: 404 });
  const buf = await r.arrayBuffer();
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, key, buf.slice(12));
    const ext = rel.split(".").pop().toLowerCase();
    return new Response(plain, { headers: { "Content-Type": TYPES[ext] || "application/octet-stream", "X-Robots-Tag": "noindex" } });
  } catch (e) { return locked(); }
}
self.addEventListener("fetch", e => {
  const url = new URL(e.request.url);
  if (url.origin !== SCOPE.origin) return;
  const appBase = SCOPE.pathname + "app/";
  if (!url.pathname.startsWith(appBase)) return;
  let rel = decodeURIComponent(url.pathname.slice(appBase.length));
  if (!rel || rel.endsWith("/")) rel += "index.html";
  e.respondWith(serve(rel));
});
