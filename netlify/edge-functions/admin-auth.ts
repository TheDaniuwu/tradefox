/**
 * Trade Fox 🦊 — Protección del panel de administración
 * -----------------------------------------------------
 * Edge Function (Netlify) que actúa como "portero" delante de
 * /admin y /admin.html. Si el visitante no tiene una cookie de
 * sesión válida (firmada con HMAC-SHA256, caduca a las 8 h),
 * se le muestra una página de login.
 *
 * La contraseña se lee de la variable de entorno ADMIN_PASSWORD
 * (configurada en Netlify → Site settings → Environment variables),
 * por lo que NUNCA aparece en el repositorio público.
 *
 * Funcionamiento:
 *   - GET  sin sesión → página de login (HTML inline, tema Trade Fox)
 *   - POST del login  → verifica contraseña; si ok, setea cookie y
 *                       redirige (302) a /admin; si no, muestra error
 *   - Cualquier método con sesión válida → context.next() (sirve admin.html)
 *
 * Sin estado ni base de datos: el token HMAC va firmado en la cookie.
 */

import type { Config, Context } from "@netlify/edge-functions";

const COOKIE_NAME = "tf_admin_session";
const SESSION_MS = 8 * 60 * 60 * 1000; // 8 horas

export default async (req: Request, context: Context): Promise<Response> => {
  const password = Deno.env.get("ADMIN_PASSWORD");

  // Si todavía no se configuró la contraseña, mostramos un aviso claro
  // en lugar de un login que jamás aceptará nada.
  if (!password) {
    return new Response(pageNotConfigured(), {
      status: 503,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // POST = intento de inicio de sesión
  if (req.method === "POST") {
    return handleLogin(req, password);
  }

  // GET (u otros) = ¿ya tiene sesión válida?
  const session = context.cookies.get(COOKIE_NAME);
  if (session && (await verifyToken(session, password))) {
    // Sesión correcta: dejamos pasar a admin.html
    return context.next();
  }

  // Sin sesión (o caducada/manipulada): mostramos el login
  return new Response(pageLogin(false), {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};

/**
 * Procesa el formulario de login.
 * Espera un body de tipo application/x-www-form-urlencoded con `password`.
 */
async function handleLogin(req: Request, password: string): Promise<Response> {
  let sent = "";
  try {
    const form = await req.formData();
    sent = (form.get("password") as string) || "";
  } catch {
    sent = "";
  }

  // Comparación en tiempo constante para evitar timing attacks
  const ok = await safeEqual(sent, password);

  if (!ok) {
    // Pequeña pausa para frenar ataques de fuerza bruta
    await new Promise((r) => setTimeout(r, 400));
    return new Response(pageLogin(true), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // Contraseña correcta → creamos el token firmado y la cookie
  const expiresAt = Date.now() + SESSION_MS;
  const token = await makeToken(expiresAt, password);

  return new Response(null, {
    status: 302,
    headers: {
      location: "/admin",
      // Cookie HttpOnly (no accesible por JS), Secure (solo HTTPS),
      // SameSite=Lax, con la caducidad de 8 h.
      "set-cookie": `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}`,
    },
  });
}

// ===== Token HMAC (firma de la caducidad con la contraseña como clave) =====

async function makeToken(expiresAt: number, password: string): Promise<string> {
  const payload = String(expiresAt);
  const key = await hmacKey(password);
  const sig = await crypto.subtle.sign("HMAC", key, enc(payload));
  return `${payload}.${toHex(sig)}`;
}

async function verifyToken(token: string, password: string): Promise<boolean> {
  const dot = token.lastIndexOf(".");
  if (dot < 1) return false;
  const payload = token.slice(0, dot);
  const sigHex = token.slice(dot + 1);

  const expiresAt = Number(payload);
  if (!Number.isFinite(expiresAt) || expiresAt < Date.now()) return false;

  const key = await hmacKey(password);
  const expected = await crypto.subtle.sign("HMAC", key, enc(payload));
  return safeEqualHex(sigHex, toHex(expected));
}

function hmacKey(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    enc(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/** Codifica un string a ArrayBuffer (compatible con BufferSource). */
function enc(s: string): ArrayBuffer {
  const u8 = new TextEncoder().encode(s);
  // Copiamos a un ArrayBuffer puro para evitar problemas de tipos
  // con Uint8Array<ArrayBufferLike> en TS 5.7+ / Web Crypto.
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Comparación de strings en tiempo constante (limita timing attacks). */
async function safeEqual(a: string, b: string): Promise<boolean> {
  const ea = bytes(a);
  const eb = bytes(b);
  if (ea.length !== eb.length) {
    // seguimos hasheando para mantener el tiempo similar
    await crypto.subtle.digest("SHA-256", enc(b));
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i] ^ eb[i];
  return diff === 0;
}

/** Versión Uint8Array de enc() para comparaciones byte a byte. */
function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function safeEqualHex(a: string, b: string): Promise<boolean> {
  return (await safeEqual(a, b)) && a === b;
}

// ===== Páginas HTML (tema Trade Fox, sin dependencias externas) =====

function shell(inner: string, title = "Trade Fox · Admin"): string {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>${title}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
       background:radial-gradient(1200px 600px at 50% -10%, #1a1206 0%, #0d1117 55%);
       color:#e6edf3;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem}
  .card{width:100%;max-width:420px;background:#161b22;border:1px solid rgba(255,107,0,.15);
        border-radius:20px;padding:2.5rem 2rem;box-shadow:0 20px 60px rgba(0,0,0,.5);
        backdrop-filter:blur(10px)}
  .logo{display:flex;align-items:center;justify-content:center;gap:.5rem;margin-bottom:1.25rem}
  .badge{width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,#FF6B00,#ff8533);
         display:flex;align-items:center;justify-content:center;font-size:1.6rem;
         box-shadow:0 8px 24px rgba(255,107,0,.4)}
  .brand{font-size:1.5rem;font-weight:800}
  .brand span{color:#FF6B00}
  .tag{font-size:.65rem;letter-spacing:.25em;text-transform:uppercase;color:#8b949e;text-align:center;margin-bottom:1.75rem}
  label{display:block;font-size:.8rem;color:#8b949e;margin-bottom:.4rem;font-weight:500}
  input{width:100%;padding:.85rem 1rem;background:#0d1117;border:1px solid #30363d;border-radius:10px;
        color:#e6edf3;font-size:1rem;outline:none;transition:border-color .2s,box-shadow .2s}
  input:focus{border-color:#FF6B00;box-shadow:0 0 0 3px rgba(255,107,0,.18)}
  button{width:100%;margin-top:1.25rem;padding:.9rem;border:none;border-radius:10px;cursor:pointer;
         background:linear-gradient(135deg,#FF6B00,#ff8533);color:#fff;font-size:1rem;font-weight:700;
         transition:transform .15s,box-shadow .2s}
  button:hover{transform:translateY(-1px);box-shadow:0 10px 24px rgba(255,107,0,.4)}
  button:active{transform:translateY(0)}
  .err{background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.4);color:#ff7b72;
       padding:.7rem .9rem;border-radius:10px;font-size:.85rem;margin-bottom:1.1rem;text-align:center}
  .alert{background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.4);color:#e3b341;
         padding:1rem 1.1rem;border-radius:12px;font-size:.88rem;line-height:1.5}
  .alert b{color:#f0c33a}
  .alert code{background:#0d1117;padding:.15rem .4rem;border-radius:5px;color:#ff8533;font-size:.85em}
  .hint{text-align:center;margin-top:1.25rem;font-size:.78rem;color:#6e7681}
  .hint a{color:#8b949e;text-decoration:none}
  .hint a:hover{color:#FF6B00}
</style>
</head>
<body>
${inner}
</body>
</html>`;
}

function pageLogin(withError: boolean): string {
  const err = withError
    ? `<div class="err">Contraseña incorrecta. Inténtalo de nuevo.</div>`
    : "";
  return shell(`
  <div class="card">
    <div class="logo">
      <div class="badge">🦊</div>
      <div class="brand">Trade <span>Fox</span></div>
    </div>
    <div class="tag">Panel de administración</div>
    ${err}
    <form method="POST" action="/admin" autocomplete="off">
      <label for="password">Contraseña</label>
      <input id="password" name="password" type="password" autofocus required
             placeholder="Introduce tu contraseña de administrador" />
      <button type="submit">Entrar →</button>
    </form>
    <div class="hint"><a href="/">← Volver a la tienda</a></div>
  </div>`, "Trade Fox · Acceso");
}

function pageNotConfigured(): string {
  return shell(`
  <div class="card">
    <div class="logo">
      <div class="badge">🦊</div>
      <div class="brand">Trade <span>Fox</span></div>
    </div>
    <div class="tag">Panel de administración</div>
    <div class="alert">
      <b>⚠️ Falta configurar la contraseña.</b><br/><br/>
      Para activar el acceso al panel debes crear la variable de entorno
      <code>ADMIN_PASSWORD</code> en Netlify:
      <br/><br/>
      Site settings → Environment variables → Add a variable<br/>
      Key: <code>ADMIN_PASSWORD</code> · Value: tu contraseña<br/><br/>
      Después vuelve a desplegar el sitio.
    </div>
    <div class="hint"><a href="/">← Volver a la tienda</a></div>
  </div>`, "Trade Fox · Sin configurar");
}

export const config: Config = {
  path: ["/admin", "/admin.html"],
};
