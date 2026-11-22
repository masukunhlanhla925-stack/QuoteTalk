// QuoteTalk: the whole app + the Stripe monthly-subscription backend in ONE file.
// Put this file alone at the root of your Vercel project (Vercel Routing Middleware).
//
// Required Vercel Environment Variables (Project -> Settings -> Environment Variables):
//   STRIPE_SECRET_KEY      restricted key (rk_live_...) with READ on: Subscriptions, Checkout Sessions, Customers
//   TOKEN_SECRET           random text, 32+ characters (signs the licence codes)
//   STRIPE_WEBHOOK_SECRET  whsec_... from the webhook you create in Stripe
// Built in (no setting needed): only your QuoteTalk Pro $20/month plan, plan-OFXZh-bZz299EVWr, unlocks Pro.
// Optional (to email each month's licence code and payment notices; uses Resend):
//   RESEND_API_KEY, EMAIL_FROM   e.g. "QuoteTalk <billing@yourdomain.com>"
//
// How access works: Stripe is the source of truth. A licence code is tied to ONE subscription
// and ONE paid billing period. The app asks this backend (every page load and every 30 minutes)
// whether the subscription is still active. Failed/cancelled/expired subscription = Pro stops.
import { createHmac, timingSafeEqual } from "node:crypto";

export const config = { runtime: "nodejs" };

const DAY = 86400;
const env = (k) => process.env[k] || "";
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });

// Fail closed: refuse to run unless the secrets look right.
const ready = () => /^(sk|rk)_(test|live)_/.test(env("STRIPE_SECRET_KEY")) && env("TOKEN_SECRET").length >= 32;

const mac = (s) => createHmac("sha256", env("TOKEN_SECRET")).update(s).digest("hex").slice(0, 20);
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

async function stripeGet(path) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch("https://api.stripe.com/v1/" + path, {
      headers: { Authorization: "Bearer " + env("STRIPE_SECRET_KEY") },
      signal: ctl.signal,
    });
    return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
  } finally {
    clearTimeout(timer);
  }
}

// ---- subscription helpers -------------------------------------------------------------------
// Only this plan unlocks Pro (your QuoteTalk Pro $20/month price). Not a secret, so it lives in the code;
// a STRIPE_PRICE_ID setting in Vercel, if you add one, overrides it.
const PRO_PRICE_ID = "plan-OFXZh-bZz299EVWr";
const priceOk = (sub) => {
  const want = env("STRIPE_PRICE_ID") || PRO_PRICE_ID;
  return ((sub.items && sub.items.data) || []).some((i) => (i.price && i.price.id === want) || (i.plan && i.plan.id === want));
};
const subOk = (sub) => (sub.status === "active" || sub.status === "trialing") && priceOk(sub);
// Works with both older and newer Stripe API versions (period moved onto the subscription item).
const period = (sub) => {
  const it = (sub.items && sub.items.data && sub.items.data[0]) || {};
  return {
    start: Number(sub.current_period_start || it.current_period_start || 0),
    end: Number(sub.current_period_end || it.current_period_end || 0),
  };
};

// ---- licence codes: QT-<subscription>-<period start>-<signature> -----------------------------
const codeFor = (subId, start) => "QT-" + subId.replace(/^sub_/, "") + "-" + start + "-" + mac(subId + "|" + start);
function parseCode(code) {
  const m = /^QT-([A-Za-z0-9]{8,64})-(\d{9,11})-([a-f0-9]{20})$/.exec(code);
  if (!m) return null;
  return { subId: "sub_" + m[1], start: Number(m[2]), mac: m[3] };
}

// ---- GET /api/pro?action=status&code=...  (called by the app) --------------------------------
async function statusRoute(raw) {
  if (!ready()) return json({ enabled: null }, 500);
  const p = parseCode(String(raw || "").trim());
  // Bad codes are rejected here, before Stripe is ever contacted.
  if (!p || !safeEqual(mac(p.subId + "|" + p.start), p.mac)) return json({ enabled: false });
  let r;
  try {
    r = await stripeGet("subscriptions/" + p.subId);
  } catch (e) {
    return json({ enabled: null }, 502);
  }
  if (r.status === 404) return json({ enabled: false });
  if (!r.ok) return json({ enabled: null }, 502);
  const sub = r.data;
  if (!subOk(sub)) return json({ enabled: false }); // past_due, unpaid, canceled, incomplete, paused...
  const per = period(sub);
  if (!per.start) return json({ enabled: false });
  if (p.start === per.start) return json({ enabled: true, code: codeFor(p.subId, per.start), periodEnd: per.end });
  // The customer renewed: last month's code is swapped for this month's new one (at most one cycle back).
  if (p.start < per.start && per.start - p.start <= 40 * DAY)
    return json({ enabled: true, code: codeFor(p.subId, per.start), periodEnd: per.end, renewed: true });
  return json({ enabled: false });
}

// ---- GET /api/pro?action=activate&session_id=cs_...  (customer returns from Stripe checkout) --
async function activateRoute(sidRaw) {
  if (!ready()) return json({ ok: false, error: "not configured" }, 500);
  const sid = String(sidRaw || "").trim();
  if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(sid)) return json({ ok: false }, 400);
  try {
    const s = await stripeGet("checkout/sessions/" + sid);
    if (!s.ok || s.data.mode !== "subscription" || s.data.status !== "complete" || !s.data.subscription) return json({ ok: false });
    if (s.data.payment_status !== "paid" && s.data.payment_status !== "no_payment_required") return json({ ok: false });
    const subId = typeof s.data.subscription === "string" ? s.data.subscription : s.data.subscription.id;
    const r = await stripeGet("subscriptions/" + subId);
    if (!r.ok || !subOk(r.data)) return json({ ok: false });
    const per = period(r.data);
    if (!per.start) return json({ ok: false });
    return json({ ok: true, code: codeFor(subId, per.start), periodEnd: per.end });
  } catch (e) {
    return json({ ok: false, error: true }, 502);
  }
}

// ---- Stripe webhook ---------------------------------------------------------------------------
// Verifies the Stripe-Signature header: HMAC-SHA256 of "<timestamp>.<raw body>", 5-minute tolerance.
function verifySignature(raw, header, secret, nowSec = Date.now() / 1000, tolerance = 300) {
  if (!header || !secret) return false;
  let t = null;
  const v1 = [];
  for (const part of String(header).split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim(), v = part.slice(i + 1).trim();
    if (k === "t") t = v;
    else if (k === "v1") v1.push(v);
  }
  if (!t || !/^\d+$/.test(t) || !v1.length) return false;
  if (Math.abs(nowSec - Number(t)) > tolerance) return false;
  const expected = createHmac("sha256", secret).update(t + "." + raw).digest("hex");
  return v1.some((s) => safeEqual(s, expected));
}

async function sendMail(to, subject, text) {
  if (!env("RESEND_API_KEY") || !env("EMAIL_FROM") || !to) return "skipped";
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + env("RESEND_API_KEY"), "content-type": "application/json" },
    body: JSON.stringify({ from: env("EMAIL_FROM"), to: [to], subject, text }),
  });
  if (!r.ok) throw new Error("email provider returned " + r.status);
  return "sent";
}

const subIdOfInvoice = (inv) => {
  const s = inv.subscription || (inv.parent && inv.parent.subscription_details && inv.parent.subscription_details.subscription);
  return typeof s === "string" ? s : (s && s.id) || null;
};
async function emailOfCustomer(customer) {
  const id = typeof customer === "string" ? customer : customer && customer.id;
  if (!id) return null;
  const r = await stripeGet("customers/" + id);
  return r.ok ? r.data.email || null : null;
}
const niceDate = (s) => new Date(s * 1000).toLocaleDateString("en-NZ", { day: "numeric", month: "long", year: "numeric", timeZone: "Pacific/Auckland" });

// invoice.paid = a payment succeeded (first payment AND every renewal): issue this month's licence code.
async function onInvoicePaid(inv, origin) {
  const subId = subIdOfInvoice(inv);
  if (!subId) return "ignored (not a subscription invoice)";
  const r = await stripeGet("subscriptions/" + subId);
  if (!r.ok || !subOk(r.data)) return "ignored (subscription not active)";
  const per = period(r.data);
  if (!per.start) return "ignored (no period)";
  const code = codeFor(subId, per.start);
  const to = inv.customer_email || (await emailOfCustomer(inv.customer));
  const body =
    "Thanks for your payment. QuoteTalk Pro is active until " + niceDate(per.end) + ".\n\n" +
    "Your licence code for this month:\n\n" + code + "\n\n" +
    "You don't need to do anything: the app updates your code automatically each month while your subscription is paid. " +
    "Keep this email if you want to unlock Pro on another device (open the app and choose \"Already subscribed?\").\n\n" +
    (origin ? origin + "\n" : "");
  return "code issued, email " + (await sendMail(to, "Your QuoteTalk Pro licence code", body));
}

// invoice.payment_failed = Pro stops on its own (Stripe sets the subscription past_due); we just tell the customer.
async function onPaymentFailed(inv, origin) {
  if (!subIdOfInvoice(inv)) return "ignored";
  const to = inv.customer_email || (await emailOfCustomer(inv.customer));
  const body =
    "We couldn't take your latest QuoteTalk Pro payment, so Pro is paused.\n\n" +
    "Please update your payment method" + (inv.hosted_invoice_url ? " here:\n" + inv.hosted_invoice_url : " in your Stripe receipt email") +
    "\n\nPro switches back on automatically, with a new licence code, as soon as the payment succeeds.\n\n" + (origin ? origin + "\n" : "");
  return "notice email " + (await sendMail(to, "QuoteTalk Pro: payment failed", body));
}

// customer.subscription.deleted = the subscription has ended: Pro is already off (status check); tell the customer.
async function onSubscriptionEnded(sub, origin) {
  const to = await emailOfCustomer(sub.customer);
  const body =
    "Your QuoteTalk Pro subscription has ended, so Pro access has stopped. Your saved quotes are still on your device.\n\n" +
    "You can subscribe again any time." + (origin ? "\n\n" + origin + "\n" : "");
  return "notice email " + (await sendMail(to, "Your QuoteTalk Pro subscription has ended", body));
}

async function webhookRoute(request) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const secret = env("STRIPE_WEBHOOK_SECRET");
  if (!ready() || !secret) return json({ error: "not configured" }, 500);
  const raw = await request.text(); // the RAW body, exactly as Stripe sent it
  if (!verifySignature(raw, request.headers.get("stripe-signature"), secret)) return json({ error: "bad signature" }, 400);
  let event;
  try {
    event = JSON.parse(raw);
  } catch (e) {
    return json({ error: "bad payload" }, 400);
  }
  const origin = new URL(request.url).origin;
  const obj = (event.data && event.data.object) || {};
  try {
    let result = "no action";
    if (event.type === "invoice.paid") result = await onInvoicePaid(obj, origin);
    else if (event.type === "invoice.payment_failed") result = await onPaymentFailed(obj, origin);
    else if (event.type === "customer.subscription.deleted") result = await onSubscriptionEnded(obj, origin);
    // customer.subscription.updated: access is read live from Stripe, so nothing to store.
    console.log("stripe webhook", event.type, event.id, "->", result);
    return json({ received: true });
  } catch (e) {
    console.error("stripe webhook failed", event.type, event.id, e && e.message);
    return json({ error: "handler failed" }, 500); // Stripe will retry
  }
}

// ---- routing ------------------------------------------------------------------------------------
const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-cache",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "microphone=(self), camera=(), geolocation=()",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

export default async function middleware(request) {
  const url = new URL(request.url);
  if (url.pathname === "/api/stripe-webhook") return webhookRoute(request);
  if (url.pathname === "/api/pro") {
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    const a = url.searchParams.get("action");
    if (a === "status") return statusRoute(url.searchParams.get("code"));
    if (a === "activate") return activateRoute(url.searchParams.get("session_id"));
    return json({ error: "bad action" }, 400);
  }
  if (url.pathname === "/" || url.pathname === "/index.html") return new Response(PAGE, { headers: PAGE_HEADERS });
  return new Response("Not found", { status: 404 });
}

// ---------------------------------------------------------------- the app page (unchanged design)
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>QuoteTalk – voice quotations</title>
<style>
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);
--bg:#f6f4ef;--card:#fff;--ink:#1d2327;--mut:#667;--line:#e2ded4;--acc:#d9622b;--acc2:#fff;--ok:#2f7d4f}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#17191b;--card:#212427;--ink:#f1efe9;--mut:#9aa0a6;--line:#33383c;--acc:#f08a55;--acc2:#1a1a1a;--ok:#6fcf97}}
:root[data-theme="dark"]{--bg:#17191b;--card:#212427;--ink:#f1efe9;--mut:#9aa0a6;--line:#33383c;--acc:#f08a55;--acc2:#1a1a1a;--ok:#6fcf97}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
*,*:before,*:after{box-sizing:inherit}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:18px 14px 40px}
h1{font-size:1.5rem;margin:0 0 2px}h2{font-size:1rem;margin:0 0 10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.sub{color:var(--mut);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:.8rem;color:var(--mut);margin-bottom:3px}
input,textarea{width:100%;font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:9px}
textarea{min-height:84px;resize:vertical}
button{font:inherit;cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:10px;padding:9px 14px}
button.p{background:var(--acc);color:var(--acc2);border-color:var(--acc);font-weight:600}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
#mic{width:64px;height:64px;border-radius:50%;font-size:1.6rem;padding:0;background:var(--acc);color:var(--acc2);border:none}
#mic.on{animation:pulse 1s infinite}
@keyframes pulse{50%{box-shadow:0 0 0 12px color-mix(in srgb,var(--acc) 25%,transparent)}}
.hint{font-size:.85rem;color:var(--mut)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:520px}
th{font-size:.75rem;text-align:left;color:var(--mut);padding:4px}
td{padding:3px}td input{padding:6px}
.n{text-align:right}
.tot{margin-left:auto;width:min(280px,100%);margin-top:12px}
.tot div{display:flex;justify-content:space-between;padding:3px 0}
.tot .g{font-weight:700;font-size:1.2rem;border-top:2px solid var(--ink);margin-top:4px;padding-top:6px}
.x{border:none;background:none;color:var(--mut);font-size:1.1rem}
#msg{color:var(--ok);font-size:.9rem;min-height:1.2em}

.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}
.top h1{margin:0 0 2px}.top .sub{margin:0}
.pro{display:inline-flex;align-items:center;gap:8px;white-space:nowrap;text-decoration:none;font-weight:700;font-size:.95rem;color:#fff;
background:linear-gradient(135deg,#ff8a3d,#d9382b 55%,#a8208a);padding:11px 18px;border-radius:999px;
box-shadow:0 6px 18px rgba(217,56,43,.35),inset 0 1px 0 rgba(255,255,255,.35);transition:transform .15s,box-shadow .15s}
.pro:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(217,56,43,.45),inset 0 1px 0 rgba(255,255,255,.35)}
.pro:active{transform:translateY(0)}
.pro:focus-visible{outline:3px solid var(--ink);outline-offset:3px}
.pro .st{font-size:1.05rem}
@media(max-width:560px){.top{flex-direction:column}.pro{align-self:flex-start}}
.side{display:flex;flex-direction:column;align-items:flex-end;gap:6px}
.meter{font-size:.8rem;color:var(--mut)}.meter b{color:var(--ink)}
.ov{position:fixed;inset:0;z-index:50;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(10,12,14,.6);backdrop-filter:blur(3px)}
.ov[hidden],.pro[hidden],.lk[hidden]{display:none}
.lk{background:none;border:none;color:var(--mut);text-decoration:underline;padding:0;font-size:.8rem;cursor:pointer}
.md{position:relative;width:min(420px,100%);background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:20px;padding:30px 24px 22px;text-align:center;box-shadow:0 24px 60px rgba(0,0,0,.4);animation:pop .18s ease-out}
@keyframes pop{from{transform:translateY(10px) scale(.97);opacity:0}}
.md .ic{width:56px;height:56px;margin:0 auto 12px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.6rem;color:#fff;background:linear-gradient(135deg,#ff8a3d,#d9382b 55%,#a8208a)}
.md h2{font-size:1.35rem;margin:0 0 6px;text-transform:none;letter-spacing:0;color:var(--ink)}
.md p{margin:0 0 18px;color:var(--mut)}
.md .pro{width:100%;justify-content:center}
.md .later{margin-top:10px;background:none;border:none;color:var(--mut);text-decoration:underline;padding:6px}
.md .cx{position:absolute;top:8px;right:10px;border:none;background:none;font-size:1.2rem;color:var(--mut);padding:6px}
@media(max-width:560px){.side{align-items:flex-start}}
.tabs{display:flex;gap:6px;margin-bottom:14px}
.tab{border-radius:999px;padding:8px 16px;font-weight:600;background:var(--card)}
.tab[aria-current="page"]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.hq .hm{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
.hq b{font-size:1.05rem}
.hq .hr{text-align:right}.hq .ht{font-weight:700;font-size:1.2rem}
.bd{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.bd.gen{color:var(--ok);border-color:var(--ok)}
.empty{text-align:center;padding:26px 14px}.empty p{color:var(--mut);margin:0 0 12px}
@media print{.ov{display:none!important}body.blocked main{display:none}body{background:#fff;color:#000}.noprint{display:none!important}.card{border:none;padding:0}input,textarea{border:none;background:none;color:#000;padding:2px}}
</style>
</head>
<body>
<main>
<header class="top">
<div>
<h1>QuoteTalk</h1>
<p class="sub">Say what the job involves and the prices. Get a clean quotation.</p>
</div>
<div class="side noprint">
<a class="pro" id="upg" href="https://buy.stripe.com/3cIbJ1fTK8g396sacA8k800" target="_blank" rel="noopener noreferrer"><span class="st" aria-hidden="true">★</span>Upgrade to Pro — $20/mo + GST</a>
<div class="meter" id="meter" aria-live="polite"></div>
<button class="lk" id="lk">Already subscribed? Enter your licence code</button>
</div>
</header>
<nav class="tabs noprint" aria-label="Pages">
<button class="tab" id="t-new" aria-current="page">New quote</button>
<button class="tab" id="t-hist" aria-current="false">My quotes</button>
</nav>
<div id="v-edit">

<section class="card noprint">
<h2>1. Speak or type the job</h2>
<div class="row" style="margin-top:0">
<button id="mic" title="Tap to talk" aria-label="Start voice input">🎤</button>
<div class="hint" id="st">Tap the mic and talk, e.g. “Supply and fit 3 taps at 85 each, 4 hours labour at 60, copper pipe for 120.”</div>
</div>
<textarea id="tx" placeholder="Or type here…" style="margin-top:10px"></textarea>
<div class="row">
<button class="p" id="add">Add to quote</button>
<button id="clr">Clear text</button>
</div>
<div class="hint" style="margin-top:8px">Tip: “at” means price each, “for” means line total. Separate items with “and”, commas or full stops. You can edit everything below.</div>
</section>

<section class="card">
<h2>2. Quotation</h2>
<div class="grid">
<div><label>Your business</label><input id="biz" placeholder="e.g. Smith Plumbing Ltd"></div>
<div><label>Quote no.</label><input id="no"></div>
<div><label>Customer</label><input id="cust" placeholder="Customer name"></div>
<div><label>Date</label><input id="dt" type="date"></div>
</div>
<div style="margin-top:10px"><label>Job / site</label><input id="job" placeholder="e.g. Bathroom retrofit, 12 Beach Rd"></div>
<div class="tw" style="margin-top:12px">
<table><thead><tr><th>Description</th><th style="width:70px">Qty</th><th style="width:100px">Unit price</th><th class="n" style="width:100px">Total</th><th class="noprint" style="width:30px"></th></tr></thead>
<tbody id="rows"></tbody></table></div>
<div class="row noprint"><button id="blank">+ Add line</button></div>
<div class="tot">
<div><span>Subtotal</span><span id="sub">$0.00</span></div>
<div class="noprint" style="align-items:center"><span>Markup %</span><input id="mk" type="number" value="0" min="0" step="1" style="width:80px;text-align:right"></div>
<div><span>Tax % <input id="tr" type="number" value="15" min="0" step="0.5" style="width:60px;display:inline;text-align:right"></span><span id="tax">$0.00</span></div>
<div class="g"><span>Total</span><span id="gt">$0.00</span></div>
</div>
<div style="margin-top:12px"><label>Notes / terms</label><textarea id="nt">Quote valid for 30 days. Prices include materials unless stated. Payment due on completion.</textarea></div>
<div class="row noprint">
<button class="p" id="pr">Print / save as PDF</button>
<button id="cp">Copy as text</button>
<button id="nw">New quote</button>
<span id="msg"></span>
</div>
</section>
</div>

<div id="v-hist" class="noprint" hidden>
<section class="card">
<h2>My quotes</h2>
<div class="row" style="margin-top:0">
<input id="hq" type="search" placeholder="Search customer, job or quote no." aria-label="Search quotes" style="flex:1;min-width:200px">
<span class="hint" id="hs"></span>
</div>
</section>
<div id="hl"></div>
</div>
</main>

<div class="ov noprint" id="ov" hidden>
<div class="md" role="dialog" aria-modal="true" aria-labelledby="mt">
<button class="cx" id="mx" aria-label="Close">✕</button>
<div class="ic" aria-hidden="true">★</div>
<h2 id="mt">You’ve used your 3 free quotes!</h2>
<p>Upgrade to Pro for unlimited access.</p>
<a class="pro" id="mup" href="https://buy.stripe.com/3cIbJ1fTK8g396sacA8k800" target="_blank" rel="noopener noreferrer"><span class="st" aria-hidden="true">★</span>Upgrade to Pro — $20/mo + GST</a>
<button class="later" id="ml">Maybe later</button>
<button class="later" id="mlk">Already subscribed? Enter your licence code</button>
</div>
</div>
<div class="ov noprint" id="lov" hidden>
<div class="md" role="dialog" aria-modal="true" aria-labelledby="lt">
<button class="cx" id="lx" aria-label="Close">✕</button>
<div class="ic" aria-hidden="true">★</div>
<h2 id="lt">Unlock Pro</h2>
<p id="lp">Paste the licence code from your Stripe email or confirmation page.</p>
<input id="li" placeholder="QT-…" autocomplete="off" spellcheck="false" aria-label="Licence code" style="text-align:center;margin-bottom:10px">
<button class="p" id="la" style="width:100%">Activate Pro</button>
<div class="hint" id="lm" style="margin-top:10px;min-height:1.3em" aria-live="polite"></div>
</div>
</div>

<script>
(function(){
var $=function(i){return document.getElementById(i)};
var items=[];
var LIMIT=3,KEY="quotetalk_free_v1",mem={used:[]},qid="";
function load(){try{var r=localStorage.getItem(KEY);if(r){var o=JSON.parse(r);if(o&&Array.isArray(o.used))return o}}catch(e){}return mem}
function save(o){mem=o;try{localStorage.setItem(KEY,JSON.stringify(o))}catch(e){}}
function consume(){
  if(isPro()){saveCurrent(true);return true}
  var o=load();
  if(o.used.indexOf(qid)===-1){
    if(o.used.length>=LIMIT)return false;
    o.used.push(qid);save(o);meter();
  }
  saveCurrent(true);return true;
}
function meter(){
  if(isPro()){var pp=getPro();$("meter").innerHTML="<b>Pro</b> · unlimited quotes"+(pp&&pp.until?" · active until "+fmtUntil(pp.until):"");$("upg").hidden=true;$("lk").hidden=false;$("lk").textContent="My Pro licence code";return}
  $("upg").hidden=false;$("lk").hidden=false;$("lk").textContent="Already subscribed? Enter your licence code";
  var n=load().used.length;
  $("meter").innerHTML=n>=LIMIT?"<b>Free limit reached</b> ("+LIMIT+" of "+LIMIT+" used)":"<b>"+n+" of "+LIMIT+"</b> free quotes used";
}
var PK="quotetalk_pro_v1",pmem=null;
function getPro(){try{var r=localStorage.getItem(PK);if(r)return JSON.parse(r)}catch(e){}return pmem}
function setPro(o){pmem=o;try{if(o)localStorage.setItem(PK,JSON.stringify(o));else localStorage.removeItem(PK)}catch(e){}}
function isPro(){var p=getPro();return !!(p&&typeof p.key==="string"&&p.key.indexOf("QT-")===0&&Date.now()-p.ts<24*36e5)}
function fmtUntil(s){var d=new Date(s*1000);return isNaN(d)?"":d.toLocaleDateString("en-NZ",{day:"numeric",month:"short",year:"numeric"})}
function verifyKey(k){return fetch("/api/pro?action=status&code="+encodeURIComponent(k)).then(function(r){return r.json()})}
function saveGood(code,until){setPro({key:code,ts:Date.now(),until:until||0})}
function viewLic(p){
  $("lt").textContent="Your Pro licence";
  $("lp").textContent="Pro is active"+(p.until?" until "+fmtUntil(p.until):"")+". Your code changes every month while your subscription is paid, and this app updates it for you.";
  $("li").style.display="";$("la").style.display="";$("li").readOnly=true;$("li").value=p.key;$("la").textContent="Copy code";
  $("la").onclick=function(){try{navigator.clipboard.writeText(p.key);$("lm").textContent="Copied"}catch(e){$("lm").textContent="Select the code above and copy it."}};
}
function openLic(){
  $("ov").hidden=true;$("lov").hidden=false;$("lm").textContent="";
  if(isPro()){viewLic(getPro());return}
  $("lt").textContent="Unlock Pro";$("lp").textContent="Paste the licence code from your Stripe email or confirmation page.";
  $("li").style.display="";$("la").style.display="";$("li").readOnly=false;$("li").value="";$("la").textContent="Activate Pro";$("la").onclick=activate;$("li").focus();
}
function hideLic(){$("lov").hidden=true}
function activate(){
  var k=$("li").value.trim();
  if(!k){$("lm").textContent="Enter your licence code first.";return}
  $("lm").textContent="Checking…";
  verifyKey(k).then(function(d){
    if(d&&d.enabled===true){saveGood(d.code||k,d.periodEnd);meter();$("lm").textContent="Pro unlocked. Thank you!";setTimeout(hideLic,1000)}
    else $("lm").textContent="That code wasn’t recognised, or the subscription is no longer active. Check it and try again.";
  }).catch(function(){$("lm").textContent="Couldn’t reach the verification service. Please try again."});
}
var lastFocus=null;
function showModal(){lastFocus=document.activeElement;$("ov").hidden=false;$("mup").focus()}
function hideModal(){$("ov").hidden=true;if(lastFocus&&lastFocus.focus)lastFocus.focus()}
$("mx").onclick=hideModal;$("ml").onclick=hideModal;
$("ov").addEventListener("click",function(e){if(e.target===$("ov"))hideModal()});
document.addEventListener("keydown",function(e){if(e.key==="Escape"&&!$("ov").hidden)hideModal()});
window.addEventListener("beforeprint",function(){if(!items.length)return;if(!consume()){document.body.classList.add("blocked");showModal()}});
window.addEventListener("afterprint",function(){document.body.classList.remove("blocked")});
function money(n){return "$"+(Math.round(n*100)/100).toLocaleString("en-NZ",{minimumFractionDigits:2,maximumFractionDigits:2})}
function esc(s){return String(s).replace(/"/g,"&quot;").replace(/</g,"&lt;")}
function newNo(){var d=new Date();return "Q-"+String(d.getFullYear()).slice(2)+String(d.getMonth()+1).padStart(2,"0")+String(d.getDate()).padStart(2,"0")+"-"+Math.floor(100+Math.random()*900)}
function init(){qid="q"+Date.now()+"-"+Math.floor(Math.random()*1e6);$("no").value=newNo();$("dt").value=new Date().toISOString().slice(0,10)}
init();meter();

var N={zero:0,one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,ten:10,eleven:11,twelve:12,thirteen:13,fourteen:14,fifteen:15,sixteen:16,seventeen:17,eighteen:18,nineteen:19,twenty:20,thirty:30,forty:40,fifty:50,sixty:60,seventy:70,eighty:80,ninety:90,hundred:100,thousand:1000,half:.5};
function isNW(w){if(!/^[A-Za-z]/.test(w))return false;var ok=true;w.toLowerCase().split("-").forEach(function(p){if(!(p in N))ok=false});return ok}
function digitize(t){
  var tk=t.match(/[A-Za-z]+(?:-[A-Za-z]+)*|\d+(?:\.\d+)?|\s+|[^\sA-Za-z\d]/g)||[];
  var out=[],i=0,ws=/^\s+$/;
  while(i<tk.length){
    var w=tk[i],start=false;
    if(/^an?$/i.test(w)&&tk[i+1]&&ws.test(tk[i+1])&&tk[i+2]&&/^(hundred|thousand|half)$/i.test(tk[i+2])){i+=2;start=true}
    else if(isNW(w))start=true;
    if(!start){out.push(w);i++;continue}
    var total=0,cur=0,j=i,last=i;
    while(j<tk.length&&isNW(tk[j])){
      var big=false;
      tk[j].toLowerCase().split("-").forEach(function(p){
        if(p==="hundred"){cur=(cur||1)*100;big=true}
        else if(p==="thousand"){total+=(cur||1)*1000;cur=0;big=true}
        else cur+=N[p];
      });
      last=j;j++;
      if(tk[j]&&ws.test(tk[j])&&tk[j+1]){
        if(isNW(tk[j+1])&&!(big===false&&/^(one|two|three|four|five|six|seven|eight|nine)$/i.test(tk[last])&&/^(one|two|three|four|five|six|seven|eight|nine)$/i.test(tk[j+1]))){j++;continue}
        if(big&&/^and$/i.test(tk[j+1])&&tk[j+2]&&ws.test(tk[j+2])&&isNW(tk[j+3]||"")){j+=3;continue}
      }
      break;
    }
    out.push(String(total+cur));i=last+1;
  }
  return out.join("");
}
function parse(text){
  var t=text.replace(/\$/g,"").replace(/(\d),(\d{3})/g,"$1$2").replace(/\b(\d+(?:\.\d+)?)\s*k\b/gi,function(_,n){return String(parseFloat(n)*1000)});
  t=digitize(t).replace(/\b(?:dollars?|bucks|nzd|usd)\b/gi," ");
  var segs=t.split(/(?:\.(?!\d)|[;\n,])+|\b(?:then|plus|also)\b|\band\b(?=\s+(?:\d|an?\b))/i);
  var FL=/^(?:yes|yeah|yep|oh|ok|okay|um|uh|hmm|so|well|and|but|now|next|i need|i'll need|i will need|we need|we'll need|we will need|you'll need|need|there will be|there is|there are|add|include|supply and fit|supply|fit|install|please)\b[\s,]*/i;
  var out=[];
  segs.forEach(function(seg){
    var s=(seg||"").trim();
    while(FL.test(s))s=s.replace(FL,"");
    if(!s)return;
    var dur=null,m=s.match(/\b(?:each|per|every)\s+([a-z]+)\s+for\s+(\d+(?:\.\d+)?)\s+([a-z]+)/i);
    if(m){dur={n:parseFloat(m[2]),per:m[1]};s=s.replace(m[0]," ")}
    var price=null,isTotal=false;
    var pm=s.match(/\b(at|@|costing|costs?|cost of|priced at|charged at|charges?|will be|would be|be|is|are|=|for)\s+(?:about\s+|around\s+|roughly\s+)?(\d+(?:\.\d+)?)/i);
    if(pm){price=parseFloat(pm[2]);isTotal=/^for$/i.test(pm[1])&&!/\beach\b/i.test(s);s=s.replace(pm[0]," ")}
    else{
      var nums=s.match(/\d+(?:\.\d+)?/g)||[];
      if(nums.length>=2||(nums.length===1&&!/^\d/.test(s))){
        var ln=nums[nums.length-1],ix=s.lastIndexOf(ln);
        price=parseFloat(ln);s=s.slice(0,ix)+" "+s.slice(ix+ln.length);
      }
    }
    var qty=1;
    if(dur)qty=dur.n;
    else{var nm=s.match(/\d+(?:\.\d+)?/);if(nm){qty=parseFloat(nm[0]);s=s.replace(nm[0]," ")}}
    var d=s.replace(/\b(each|costing|will be|would be|is|are|about|around|please|yeah|yes|oh|um|uh)\b/gi," ").replace(/[^\w\s&'’\/-]/g," ").replace(/\s+/g," ").trim();
    var pre=/^(?:the|a|an|of|x|for|at)\b\s*/i;
    while(pre.test(d))d=d.replace(pre,"");
    if(!d&&price===null)return;
    d=d?d.charAt(0).toUpperCase()+d.slice(1):"Item";
    if(dur)d+=" (per "+dur.per+")";
    var unit=price===null?0:(isTotal&&qty?price/qty:price);
    out.push({d:d,q:qty,u:Math.round(unit*100)/100});
  });
  return out;
}

function render(){
  var h="";
  items.forEach(function(it,i){
    h+='<tr><td><input data-i="'+i+'" data-k="d" value="'+esc(it.d)+'"></td>'+
    '<td><input data-i="'+i+'" data-k="q" type="number" step="any" value="'+it.q+'"></td>'+
    '<td><input data-i="'+i+'" data-k="u" type="number" step="any" value="'+it.u+'"></td>'+
    '<td class="n" id="lt'+i+'">'+money(it.q*it.u)+'</td>'+
    '<td class="noprint"><button class="x" data-del="'+i+'" aria-label="Remove line">✕</button></td></tr>';
  });
  $("rows").innerHTML=h||'<tr><td colspan="5" class="hint" style="padding:12px 4px">No items yet. Speak or type above, or add a line.</td></tr>';
  totals();
}
function calc(){
  var s=0;items.forEach(function(it){s+=(+it.q||0)*(+it.u||0)});
  var mk=parseFloat($("mk").value)||0,tr=parseFloat($("tr").value)||0;
  var base=s*(1+mk/100),tax=base*tr/100;
  return{s:s,mk:mk,tr:tr,base:base,tax:tax,gt:base+tax};
}
function totals(){
  var c=calc();
  $("sub").textContent=money(c.mk?c.base:c.s);
  $("tax").textContent=money(c.tax);$("gt").textContent=money(c.gt);
}
$("rows").addEventListener("input",function(e){
  var el=e.target,i=el.dataset.i,k=el.dataset.k;if(i===undefined)return;
  items[i][k]=k==="d"?el.value:(parseFloat(el.value)||0);
  var lt=$("lt"+i);if(lt)lt.textContent=money(items[i].q*items[i].u);
  totals();
});
$("rows").addEventListener("click",function(e){
  var d=e.target.dataset.del;if(d===undefined)return;
  items.splice(+d,1);render();
});
$("mk").addEventListener("input",totals);$("tr").addEventListener("input",totals);
$("add").onclick=function(){
  var p=parse($("tx").value);
  if(!p.length){flash("Nothing to add yet");return}
  items=items.concat(p);$("tx").value="";render();flash("Added "+p.length+" line"+(p.length>1?"s":""));
};
$("clr").onclick=function(){$("tx").value=""};
$("blank").onclick=function(){items.push({d:"",q:1,u:0});render()};
$("nw").onclick=function(){if(!isPro()&&load().used.length>=LIMIT&&load().used.indexOf(qid)>-1){showModal();return}saveCurrent(false);items=[];["cust","job"].forEach(function(i){$(i).value=""});init();render()};
$("pr").onclick=function(){if(!items.length){flash("Add at least one item first");return}if(!consume()){showModal();return}try{window.print()}catch(e){flash("Printing isn’t available here")}};
$("cp").onclick=function(){
  if(!items.length){flash("Add at least one item first");return}
  if(!consume()){showModal();return}
  var c=calc(),L=[];
  L.push(($("biz").value||"QUOTATION")+" – Quote "+$("no").value);
  L.push("Date: "+$("dt").value);if($("cust").value)L.push("Customer: "+$("cust").value);
  if($("job").value)L.push("Job: "+$("job").value);L.push("");
  items.forEach(function(it){L.push(it.d+" – "+it.q+" × "+money(it.u)+" = "+money(it.q*it.u))});
  L.push("");L.push("Subtotal: "+money(c.mk?c.base:c.s));L.push("Tax ("+c.tr+"%): "+money(c.tax));L.push("TOTAL: "+money(c.gt));
  if($("nt").value){L.push("");L.push($("nt").value)}
  var txt=L.join("\n");
  function fb(){var a=document.createElement("textarea");a.value=txt;document.body.appendChild(a);a.select();try{document.execCommand("copy");flash("Copied")}catch(e){flash("Copy failed")}a.remove()}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(function(){flash("Copied")},fb)}else fb();
};
function flash(m){$("msg").textContent=m;setTimeout(function(){$("msg").textContent=""},2500)}

// Voice
var SR=window.SpeechRecognition||window.webkitSpeechRecognition,rec=null,on=false,base="";
if(!SR){$("mic").disabled=true;$("mic").style.opacity=.4;$("st").textContent="Voice input isn’t supported in this browser. Type the job below, or try Chrome or Safari."}
else{
  rec=new SR();rec.continuous=true;rec.interimResults=true;rec.lang="en-NZ";
  rec.onresult=function(e){
    var f="",i2="";
    for(var i=e.resultIndex;i<e.results.length;i++){var r=e.results[i];if(r.isFinal)f+=r[0].transcript+". ";else i2+=r[0].transcript}
    if(f)base+=f;$("tx").value=base+i2;
  };
  rec.onerror=function(e){
    on=false;$("mic").classList.remove("on");
    $("st").textContent=(e.error==="not-allowed"||e.error==="service-not-allowed")?"Microphone blocked here. Type the job below instead.":"Voice error ("+e.error+"). You can type instead.";
  };
  rec.onend=function(){on=false;$("mic").classList.remove("on");if($("tx").value.trim())$("st").textContent="Check the text, then tap Add to quote."};
  $("mic").onclick=function(){
    if(on){rec.stop();return}
    base=$("tx").value?$("tx").value.replace(/\s*$/," "):"";
    try{rec.start();on=true;$("mic").classList.add("on");$("st").textContent="Listening… tap again when done."}catch(e){$("st").textContent="Couldn’t start the mic."}
  };
}
render();

// ---------- History (second page)
var QK="quotetalk_quotes_v1",qmem=[];
function loadQ(){try{var r=localStorage.getItem(QK);if(r){var a=JSON.parse(r);if(Array.isArray(a))return a}}catch(e){}return qmem}
function saveQ(a){qmem=a;try{localStorage.setItem(QK,JSON.stringify(a))}catch(e){}}
function tot(its,mk,tr){var s=0;its.forEach(function(it){s+=(+it.q||0)*(+it.u||0)});return s*(1+mk/100)*(1+tr/100)}
function hx(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function saveCurrent(gen){
  if(!items.length)return;
  var L=loadQ(),i=-1;
  for(var k=0;k<L.length;k++)if(L[k].id===qid)i=k;
  var mk=parseFloat($("mk").value)||0,tr=parseFloat($("tr").value)||0;
  var its=items.map(function(x){return{d:x.d,q:x.q,u:x.u}});
  var rec={id:qid,no:$("no").value,date:$("dt").value,cust:$("cust").value,job:$("job").value,biz:$("biz").value,nt:$("nt").value,mk:mk,tr:tr,items:its,ts:Date.now(),gen:!!gen||(i>-1&&!!L[i].gen),total:tot(its,mk,tr)};
  if(i>-1)L[i]=rec;else L.unshift(rec);
  saveQ(L.slice(0,200));navCount();
}
function navCount(){var n=loadQ().length;$("t-hist").textContent="My quotes"+(n?" ("+n+")":"")}
function fmtDate(q){var d=q.date?new Date(q.date+"T00:00:00"):new Date(q.ts);return isNaN(d)?"":d.toLocaleDateString("en-NZ",{day:"numeric",month:"short",year:"numeric"})}
function renderHist(){
  var all=loadQ(),term=($("hq").value||"").toLowerCase().trim();
  var L=all.filter(function(q){return !term||[q.cust,q.job,q.no,q.biz].join(" ").toLowerCase().indexOf(term)>-1});
  var sum=0;L.forEach(function(q){sum+=q.total||0});
  $("hs").textContent=all.length?L.length+" quote"+(L.length===1?"":"s")+" · "+money(sum):"";
  if(!all.length){
    $("hl").innerHTML='<div class="card empty"><p>No quotes yet. Quotes you create show up here automatically.</p><button class="p" id="first">Create your first quote</button></div>';
    $("first").onclick=function(){location.hash=""};return;
  }
  if(!L.length){$("hl").innerHTML='<div class="card empty"><p>No quotes match your search.</p></div>';return}
  $("hl").innerHTML=L.map(function(q){
    var meta=[q.job,q.no,fmtDate(q)].filter(Boolean).map(hx).join(" · ");
    return '<article class="card hq"><div class="hm"><div><b>'+hx(q.cust||"No customer name")+'</b><div class="hint">'+meta+'</div></div>'+
    '<div class="hr"><div class="ht">'+money(q.total||0)+'</div><span class="bd '+(q.gen?"gen":"")+'">'+(q.gen?"Generated":"Draft")+'</span></div></div>'+
    '<div class="hint" style="margin-top:6px">'+q.items.length+' line item'+(q.items.length===1?"":"s")+'</div>'+
    '<div class="row"><button class="p" data-open="'+hx(q.id)+'">Open</button><button data-del="'+hx(q.id)+'">Delete</button></div></article>';
  }).join("");
}
function openQuote(id){
  var q=null;loadQ().forEach(function(x){if(x.id===id)q=x});if(!q)return;
  if(qid!==id)saveCurrent(false);
  qid=q.id;$("no").value=q.no||"";$("dt").value=q.date||"";$("cust").value=q.cust||"";$("job").value=q.job||"";$("biz").value=q.biz||"";$("nt").value=q.nt||"";
  $("mk").value=q.mk||0;$("tr").value=q.tr==null?15:q.tr;
  items=q.items.map(function(i){return{d:i.d,q:i.q,u:i.u}});render();location.hash="";
}
function show(){
  var h=location.hash==="#history";
  if(h)saveCurrent(false);
  $("v-edit").hidden=h;$("v-hist").hidden=!h;
  $("t-new").setAttribute("aria-current",h?"false":"page");$("t-hist").setAttribute("aria-current",h?"page":"false");
  if(h)renderHist();
  window.scrollTo(0,0);
}
$("t-new").onclick=function(){location.hash=""};
$("t-hist").onclick=function(){location.hash="history"};
window.addEventListener("hashchange",show);
$("hq").addEventListener("input",renderHist);
$("hl").addEventListener("click",function(e){
  var b=e.target.closest?e.target.closest("button"):null;if(!b)return;
  if(b.dataset.open){openQuote(b.dataset.open);return}
  if(b.dataset.del){
    if(b.dataset.sure){
      var id=b.dataset.del;
      saveQ(loadQ().filter(function(x){return x.id!==id}));
      if(id===qid){items=[];$("cust").value="";$("job").value="";init();render()}
      navCount();renderHist();return;
    }
    b.dataset.sure="1";b.textContent="Tap again to delete";
    setTimeout(function(){if(b.isConnected){delete b.dataset.sure;b.textContent="Delete"}},3000);
  }
});
document.addEventListener("visibilitychange",function(){if(document.visibilityState==="hidden")saveCurrent(false)});
window.addEventListener("pagehide",function(){saveCurrent(false)});
navCount();show();meter();
$("lk").onclick=openLic;$("mlk").onclick=openLic;$("la").onclick=activate;$("lx").onclick=hideLic;
$("lov").addEventListener("click",function(e){if(e.target===$("lov"))hideLic()});
$("li").addEventListener("keydown",function(e){if(e.key==="Enter")activate()});
document.addEventListener("keydown",function(e){if(e.key==="Escape"&&!$("lov").hidden)hideLic()});
// Returning from Stripe checkout: swap the session id for this month's licence code.
function showResult(ok,p){
  $("ov").hidden=true;$("lov").hidden=false;$("lm").textContent="";
  if(ok){
    viewLic(p);$("lt").textContent="You’re Pro. Thank you!";
    $("lp").textContent="Pro is switched on in this browser"+(p.until?" until "+fmtUntil(p.until):"")+". Your licence code is below. It changes every month while your subscription is paid, and this app updates it for you.";
  }else{
    $("lt").textContent="We couldn’t activate Pro";
    $("lp").textContent="We couldn’t confirm that payment. If you’ve paid, please contact support with your receipt.";
    $("li").style.display="none";$("la").style.display="none";
  }
}
var sid=new URLSearchParams(location.search).get("session_id");
if(sid){
  try{history.replaceState(null,"",location.pathname+location.hash)}catch(e){}
  fetch("/api/pro?action=activate&session_id="+encodeURIComponent(sid)).then(function(r){return r.json()}).then(function(d){
    if(d&&d.ok&&d.code){saveGood(d.code,d.periodEnd);meter();showResult(true,getPro())}else showResult(false)
  }).catch(function(){showResult(false)});
}
function recheck(){var sp=getPro();if(sp&&sp.key){verifyKey(sp.key).then(function(d){if(d&&d.enabled===true)saveGood(d.code||sp.key,d.periodEnd);else if(d&&d.enabled===false)setPro(null);meter()}).catch(function(){})}}
recheck();setInterval(recheck,30*60*1000);
document.addEventListener("visibilitychange",function(){if(document.visibilityState==="visible")recheck()});
})();
</script>
</body>
</html>
`;
