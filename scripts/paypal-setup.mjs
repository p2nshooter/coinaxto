/**
 * PayPal otomatis (tanpa langkah manual pemilik):
 *  1. ambil token OAuth (sandbox/live sesuai PAYPAL_MODE),
 *  2. pastikan webhook https://axto.io/api/paypal/webhook terdaftar (dibuat bila belum) → cetak ID ke stdout,
 *  3. uji: buat order $10 (1 koin) → status harus CREATED.
 * ENV: PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_MODE (sandbox|live), WEBHOOK_URL (default https://axto.io/api/paypal/webhook)
 * Keluaran stdout HANYA id webhook (dipakai workflow untuk `wrangler secret put PAYPAL_WEBHOOK_ID`); log ke stderr.
 */
const API = process.env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
const URL_HOOK = process.env.WEBHOOK_URL || 'https://axto.io/api/paypal/webhook';
const EVENTS = ['PAYMENT.CAPTURE.COMPLETED', 'PAYMENT.CAPTURE.REFUNDED', 'PAYMENT.CAPTURE.REVERSED', 'PAYMENT.CAPTURE.DENIED', 'CHECKOUT.ORDER.APPROVED'];
const log = (...a) => console.error(...a);

const auth = await fetch(`${API}/v1/oauth2/token`, {
  method: 'POST',
  headers: { authorization: `Basic ${Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded' },
  body: 'grant_type=client_credentials',
});
if (!auth.ok) { log(`PayPal OAuth gagal: ${auth.status}`); process.exit(1); }
const { access_token: tok } = await auth.json();
const h = { authorization: `Bearer ${tok}`, 'content-type': 'application/json' };
log(`PayPal ${process.env.PAYPAL_MODE || 'sandbox'}: OAuth OK`);

const list = await (await fetch(`${API}/v1/notifications/webhooks`, { headers: h })).json();
let hook = (list.webhooks || []).find((w) => w.url === URL_HOOK);
if (!hook) {
  const r = await fetch(`${API}/v1/notifications/webhooks`, { method: 'POST', headers: h, body: JSON.stringify({ url: URL_HOOK, event_types: EVENTS.map((name) => ({ name })) }) });
  hook = await r.json();
  if (!r.ok) { log(`buat webhook gagal: ${r.status} ${JSON.stringify(hook).slice(0, 300)}`); process.exit(1); }
  log(`webhook dibuat: ${hook.id}`);
} else log(`webhook sudah ada: ${hook.id}`);

const o = await fetch(`${API}/v2/checkout/orders`, {
  method: 'POST', headers: { ...h, 'paypal-request-id': `axto-selftest-${Date.now()}` },
  body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ custom_id: '0x0000000000000000000000000000000000000001', description: 'AXTO coin × 1 (uji otomatis)', amount: { currency_code: 'USD', value: '10.00' } }] }),
});
const oj = await o.json();
if (!o.ok || oj.status !== 'CREATED') { log(`uji order gagal: ${o.status} ${JSON.stringify(oj).slice(0, 300)}`); process.exit(1); }
log(`uji order OK: ${oj.id} CREATED (link persetujuan pembeli: ${oj.links?.find((l) => l.rel === 'approve')?.href ? 'ada' : 'tidak ada'})`);
console.log(hook.id);
