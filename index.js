/**
 * Cloudflare Worker – Secure screenshot service + in-browser test console
 *
 *  • Visit the Worker **without** query parameters to get a minimalist HTML UI
 *    that signs requests in your browser (secret stored in localStorage).
 *  • Hit the Worker **with** signed parameters and it proxies Cloudflare’s
 *    Browser-Rendering Screenshot API, caches, and serves the PNG.
 */

export default {
  async fetch(request, env, ctx) {
    const { searchParams } = new URL(request.url);

    // ────────────────────────────────────────────────────────────────────
    // 1. If no ?url= parameter ⇒ serve HTML playground
    // ────────────────────────────────────────────────────────────────────
    if (!searchParams.has("url")) {
      return new Response(HTML_PLAYGROUND, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    // ────────────────────────────────────────────────────────────────────
    // 2. Parameter extraction & validation
    // ────────────────────────────────────────────────────────────────────
    const targetUrl = searchParams.get("url");
    const version = searchParams.get("version");
    const signature = searchParams.get("sig");
    const width = searchParams.get("w") || "1200";
    const height = searchParams.get("h") || "800";
    const js = searchParams.get("js") || "";
    const css = searchParams.get("css") || "";

    if (!targetUrl || !version || !signature) {
      return new Response("Missing required parameters", { status: 400 });
    }

    try {
      new URL(targetUrl);
    } catch {
      return new Response("Invalid url", { status: 400 });
    }

    const wNum = parseInt(width, 10);
    if (Number.isNaN(wNum) || wNum < 100 || wNum > 3840)
      return new Response("Invalid w (100-3840)", { status: 400 });

    if (height !== "full") {
      const hNum = parseInt(height, 10);
      if (Number.isNaN(hNum) || hNum < 100 || hNum > 2160)
        return new Response('Invalid h (100-2160 or "full")', { status: 400 });
    }

    // Verify HMAC
    const ok = await verifySig(
      targetUrl,
      version,
      width,
      height,
      js,
      css,
      signature,
      env.SCREENSHOT_SECRET,
    );
    if (!ok) return new Response("Invalid signature", { status: 403 });

    // ────────────────────────────────────────────────────────────────────
    // 3. Cache lookup
    // ────────────────────────────────────────────────────────────────────
    const cacheKey = new Request(
      `https://screenshot-cache.${env.WORKER_DOMAIN}` +
        `/v${version}/w${width}/h${height}` +
        `/js${encodeURIComponent(js)}/css${encodeURIComponent(css)}/` +
        encodeURIComponent(targetUrl),
    );

    const cache = caches.default;
    let res = await cache.match(cacheKey);
    if (res) return res;

    // ────────────────────────────────────────────────────────────────────
    // 4. Call Browser-Rendering Screenshot API
    // ────────────────────────────────────────────────────────────────────
    try {
      const screenshotOptions = {
        type: "png",
        ...(height === "full" ? { fullPage: true } : {}),
      };

      const payload = {
        url: targetUrl,
        screenshotOptions,
        viewport: {
          width: wNum,
          height: height === "full" ? 800 : parseInt(height, 10),
        },
        gotoOptions: { waitUntil: "networkidle0", timeout: 30_000 },
        ...(js ? { addScriptTag: [{ content: js }] } : {}),
        ...(css ? { addStyleTag: [{ content: css }] } : {}),
      };

      const apiRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/browser-rendering/screenshot`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.CF_API_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        },
      );

      if (!apiRes.ok) {
        console.error("Screenshot API error:", await apiRes.text());
        return new Response("Screenshot generation failed", { status: 502 });
      }

      const blob = await apiRes.blob();
      res = new Response(blob, {
        headers: {
          "content-type": "image/png",
          "cache-control": "public, max-age=31536000, immutable",
          "x-screenshot-url": targetUrl,
          "x-screenshot-version": version,
          "x-screenshot-width": width,
          "x-screenshot-height": height,
          "x-screenshot-timestamp": new Date().toISOString(),
        },
      });
      ctx.waitUntil(cache.put(cacheKey, res.clone()));
      return res;
    } catch (err) {
      console.error("Worker error:", err);
      return new Response("Internal server error", { status: 500 });
    }
  },
};

/* ──────────────────────────────────────────────────────────────────────── */
/*  HMAC verification helper                                               */
/* ──────────────────────────────────────────────────────────────────────── */
async function verifySig(url, version, w, h, js, css, sig, secret) {
  const msg = `${url}|${version}|${w}|${h}|${js}|${css}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const out = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  const hex = [...new Uint8Array(out)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return constantTimeCompare(sig, hex);
}

function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

/* ──────────────────────────────────────────────────────────────────────── */
/*  Embeddable HTML playground                                             */
/* ──────────────────────────────────────────────────────────────────────── */
const HTML_PLAYGROUND = `<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>Screenshot Worker</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem;}
  h1{font-size:1.5rem;margin:0 0 1rem;}
  label{display:block;margin-top:1rem;font-weight:600;}
  input,textarea{width:100%;padding:.5rem;border:1px solid #ccc;border-radius:4px;}
  button{margin-top:1rem;padding:.6rem 1.2rem;border:0;border-radius:4px;background:#006eff;color:#fff;font-weight:600;cursor:pointer;}
  img{max-width:100%;display:block;margin-top:1rem;border:1px solid #eee;}
  code{word-break:break-all;display:block;background:#f6f8fa;padding:.5rem;border-radius:4px;}
</style>
<body>
<h1>Screenshot Worker test console</h1>
<form id="shotForm">
  <label>Target URL
    <input name="url" required placeholder="https://example.com">
  </label>
  <label>Version
    <input name="version" value="1">
  </label>
  <label>Width
    <input name="w" value="1200">
  </label>
  <label>Height
    <input name="h" value="800">
  </label>
  <label>JavaScript to inject (optional)
    <textarea name="js" rows="2" placeholder="document.body.style.background='pink'"></textarea>
  </label>
  <label>CSS to inject (optional)
    <textarea name="css" rows="2" placeholder="h1{font-size:72px;}"></textarea>
  </label>
  <button type="submit">Generate screenshot</button>
</form>

<h2 id="urlHeader" style="display:none">Signed URL</h2>
<code id="signedUrl"></code>
<img id="preview" alt="Preview">

<script>
const form  = document.getElementById('shotForm');
const outEl = document.getElementById('signedUrl');
const imgEl = document.getElementById('preview');
const hdrEl = document.getElementById('urlHeader');

const workerOrigin = location.origin + location.pathname.replace(/\\/[^/]*$/, ''); // handles custom routes

form.addEventListener('submit', async (ev) => {
  ev.preventDefault();

  let secret = localStorage.getItem('SCREENSHOT_SECRET');
  if (!secret) {
    secret = prompt('Enter your SCREENSHOT_SECRET:');
    if (!secret) return;
    localStorage.setItem('SCREENSHOT_SECRET', secret);
  }

  const data    = new FormData(form);
  const url     = data.get('url').trim();
  const version = data.get('version').trim();
  const w       = data.get('w').trim();
  const h       = data.get('h').trim();
  const js      = data.get('js').trim();
  const css     = data.get('css').trim();

  const msg = [url, version, w, h, js, css].join('|');
  const sig = await hmac256(secret, msg);

  const qs  = new URLSearchParams({ url, version, w, h, sig });
  if (js)  qs.append('js', js);
  if (css) qs.append('css', css);

  const signedUrl = workerOrigin + '?' + qs.toString();
  outEl.textContent = signedUrl;
  hdrEl.style.display = '';
  imgEl.src = signedUrl;
});

async function hmac256(key, msg) {
  const enc  = new TextEncoder();
  const keyData = await crypto.subtle.importKey('raw', enc.encode(key),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig  = await crypto.subtle.sign('HMAC', keyData, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
</script>
</body></html>`;
