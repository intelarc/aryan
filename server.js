"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const PORT = Number(process.env.PORT || 5000);
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const SESSION_TTL_MS = SESSION_TTL_SECONDS * 1000;
const MAX_FORM_BYTES = 4096;
const MAX_FAILED_ATTEMPTS = 10;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

const sitePassword = process.env.SITE_PASSWORD;
const sessionSecret = process.env.SESSION_SECRET;

if (!sitePassword || !sessionSecret) {
  throw new Error("SITE_PASSWORD and SESSION_SECRET must be configured as Replit Secrets.");
}

const sitePasswordDigest = crypto
  .createHmac("sha256", sessionSecret)
  .update(sitePassword)
  .digest();
const sessionSigningKey = crypto
  .createHmac("sha256", sessionSecret)
  .update(`private-site-session-key-v1:${sitePassword}`)
  .digest();
const indexHtml = fs.readFileSync(path.join(__dirname, "index.html"));
const failedAttempts = new Map();

const loginHtml = (message = "") => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <title>Restricted access</title>
  <style>
    :root { color-scheme: dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px;
      color: #fafaf7; background: #060606;
      background-image: radial-gradient(ellipse 80% 50% at 50% 0%, rgba(255,255,255,.06), transparent 70%);
    }
    main { width: min(100%, 390px); padding: 34px; border: 1px solid rgba(250,250,247,.12);
      border-radius: 18px; background: rgba(250,250,247,.035); }
    .eyebrow { margin: 0 0 22px; color: rgba(250,250,247,.62); font-size: 11px;
      letter-spacing: .15em; text-transform: uppercase; }
    .eyebrow::before { content: ""; display: inline-block; width: 7px; height: 7px;
      margin: 0 9px 1px 0; border-radius: 50%; background: #d0d0c9; }
    h1 { margin: 0; font-size: clamp(25px, 6vw, 31px); letter-spacing: -.04em; }
    .intro { margin: 12px 0 28px; color: rgba(250,250,247,.62); font-size: 14px; line-height: 1.6; }
    label { display: block; margin-bottom: 9px; font-size: 12px; color: rgba(250,250,247,.78); }
    input {
      display: block; width: 100%; height: 46px; padding: 0 13px; border: 1px solid rgba(250,250,247,.18);
      border-radius: 10px; color: #fafaf7; background: #101010; font: inherit;
    }
    .visually-hidden {
      position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden;
      clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
    }
    input:focus-visible { outline: 2px solid #fafaf7; outline-offset: 2px; }
    button {
      width: 100%; height: 45px; margin-top: 14px; border: 0; border-radius: 10px;
      color: #090909; background: #fafaf7; font: inherit; font-size: 13px; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #e4e4de; }
    .notice { margin: 19px 0 0; color: rgba(250,250,247,.42); font-size: 11px; line-height: 1.5; }
    .error { margin: 16px 0 0; color: #ffaaa3; font-size: 13px; }
  </style>
</head>
<body>
  <main>
    <p class="eyebrow">Private site</p>
    <h1>Access restricted</h1>
    <p class="intro">This site is not public. Enter the shared passphrase to continue.</p>
    <form method="post" action="/login">
      <input class="visually-hidden" type="text" name="username" autocomplete="username" value="site-access" tabindex="-1" aria-hidden="true">
      <label for="password">Passphrase</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
      <button type="submit">Continue</button>
    </form>
    ${message ? `<p class="error" role="alert">${message}</p>` : ""}
    <p class="notice">Only share the passphrase with people you trust.</p>
  </main>
</body>
</html>`;

const contentSecurityPolicies = {
  login:
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  site:
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
};

function setSecurityHeaders(response, policy = contentSecurityPolicies.login) {
  response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  response.setHeader("Content-Security-Policy", policy);
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function respond(response, request, status, type, body, headers = {}) {
  const { policy, ...responseHeaders } = headers;
  setSecurityHeaders(response, policy || contentSecurityPolicies.login);
  response.writeHead(status, {
    "Content-Type": type,
    ...responseHeaders,
  });
  response.end(request.method === "HEAD" ? undefined : body);
}

function redirect(response, request, location, cookie) {
  respond(response, request, 303, "text/plain; charset=utf-8", "", {
    Location: location,
    "Set-Cookie": cookie,
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.cookie || "";
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return "";
}

function signSession(payload) {
  return crypto
    .createHmac("sha256", sessionSigningKey)
    .update(`private-site-session-v1:${payload}`)
    .digest("base64url");
}

function createSessionCookieValue() {
  const expiry = Date.now() + SESSION_TTL_MS;
  const nonce = crypto.randomBytes(24).toString("base64url");
  const payload = `${expiry}.${nonce}`;
  return `${payload}.${signSession(payload)}`;
}

function hasValidSession(request) {
  const value = getCookie(request, "site_session");
  const [expiryText, nonce, suppliedSignature, ...extra] = value.split(".");
  if (extra.length || !/^\d{13}$/.test(expiryText || "")) return false;
  if (!/^[A-Za-z0-9_-]{32}$/.test(nonce || "")) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(suppliedSignature || "")) return false;

  const expiry = Number(expiryText);
  const now = Date.now();
  if (expiry <= now || expiry > now + SESSION_TTL_MS + 60_000) return false;

  const expected = Buffer.from(signSession(`${expiryText}.${nonce}`));
  const supplied = Buffer.from(suppliedSignature);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function getClientAddress(request) {
  const forwardedFor = request.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    return forwardedFor.split(",")[0].trim().slice(0, 100);
  }
  return request.socket.remoteAddress || "unknown";
}

function getAttemptState(address) {
  const now = Date.now();
  if (failedAttempts.size > 5000) {
    for (const [key, attempt] of failedAttempts) {
      if (attempt.resetAt <= now) failedAttempts.delete(key);
    }
  }
  const current = failedAttempts.get(address);
  if (!current || current.resetAt <= now) {
    const fresh = { count: 0, resetAt: now + ATTEMPT_WINDOW_MS };
    failedAttempts.set(address, fresh);
    return fresh;
  }
  return current;
}

function readForm(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];

    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_FORM_BYTES) {
        tooLarge = true;
        chunks.length = 0;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });
    request.on("end", () => {
      if (tooLarge) {
        reject(Object.assign(new Error("Request body too large"), { statusCode: 413 }));
        return;
      }
      resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8")));
    });
    request.on("error", reject);
  });
}

async function handleRequest(request, response) {
  respond(response, request, 200, "text/html; charset=utf-8", "");
  return;

  const requestUrl = new URL(request.url || "/", "http://site.local");
  const pathname = requestUrl.pathname;

  if (pathname === "/robots.txt" && (request.method === "GET" || request.method === "HEAD")) {
    respond(
      response,
      request,
      200,
      "text/plain; charset=utf-8",
      "User-agent: *\nDisallow: /\n",
    );
    return;
  }

  if (pathname === "/login" && (request.method === "GET" || request.method === "HEAD")) {
    if (hasValidSession(request)) {
      const cookie = getCookie(request, "site_session");
      redirect(
        response,
        request,
        "/",
        `site_session=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`,
      );
      return;
    }
    respond(response, request, 200, "text/html; charset=utf-8", loginHtml());
    return;
  }

  if (pathname === "/login" && request.method === "POST") {
    if (!String(request.headers["content-type"] || "").startsWith("application/x-www-form-urlencoded")) {
      respond(response, request, 415, "text/plain; charset=utf-8", "Unsupported media type");
      return;
    }

    const address = getClientAddress(request);
    const attempts = getAttemptState(address);
    if (attempts.count >= MAX_FAILED_ATTEMPTS) {
      respond(
        response,
        request,
        429,
        "text/html; charset=utf-8",
        loginHtml("Too many attempts. Please wait before trying again."),
        { "Retry-After": String(Math.ceil((attempts.resetAt - Date.now()) / 1000)) },
      );
      return;
    }

    let form;
    try {
      form = await readForm(request);
    } catch (error) {
      respond(
        response,
        request,
        error.statusCode || 400,
        "text/plain; charset=utf-8",
        error.statusCode === 413 ? "Request too large" : "Invalid request",
      );
      return;
    }

    const candidate = form.get("password") || "";
    if (Buffer.byteLength(candidate, "utf8") <= MAX_FORM_BYTES) {
      const candidateDigest = crypto
        .createHmac("sha256", sessionSecret)
        .update(candidate)
        .digest();
      if (crypto.timingSafeEqual(candidateDigest, sitePasswordDigest)) {
        failedAttempts.delete(address);
        const session = createSessionCookieValue();
        redirect(
          response,
          request,
          "/",
          `site_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`,
        );
        return;
      }
    }

    attempts.count += 1;
    respond(
      response,
      request,
      401,
      "text/html; charset=utf-8",
      loginHtml("Incorrect passphrase. Try again."),
    );
    return;
  }

  if (pathname === "/logout" && request.method === "POST") {
    redirect(
      response,
      request,
      "/login",
      "site_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    );
    return;
  }

  if (!hasValidSession(request)) {
    respond(response, request, 200, "text/html; charset=utf-8", loginHtml());
    return;
  }

  if ((pathname === "/" || pathname === "/index.html") &&
      (request.method === "GET" || request.method === "HEAD")) {
    respond(response, request, 200, "text/html; charset=utf-8", indexHtml, {
      policy: contentSecurityPolicies.site,
    });
    return;
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    respond(response, request, 405, "text/plain; charset=utf-8", "Method not allowed", {
      Allow: "GET, HEAD",
    });
    return;
  }

  respond(response, request, 404, "text/plain; charset=utf-8", "Not found");
}

const server = http.createServer((request, response) => {
  handleRequest(request, response).catch(() => {
    if (!response.headersSent) {
      respond(response, request, 500, "text/plain; charset=utf-8", "Internal server error");
    } else {
      response.destroy();
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Private site server listening on port ${PORT}`);
});
