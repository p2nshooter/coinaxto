/**
 * axto-vault — penjaga kunci AXTO. Tidak punya URL publik (workers_dev=false, tanpa route). Satu-satunya pintu:
 * Service Binding `VAULT.call(method, body, ts, mac)` dari axto-web, dengan HMAC-SHA256 per pesan, jendela 60 detik,
 * dan daftar metode yang diizinkan. Kunci signer & kredensial PayPal hanya ada sebagai secret terenkripsi Cloudflare.
 *
 * Vault memvalidasi sendiri, tidak percaya buta pada worker publik:
 *  - attestResult: tanda tangan Bid pemenang diverifikasi ulang; harga ≤ maxAmount; satu attestasi per lot+pemenang.
 *  - paypalCapture: capture dicek langsung ke PayPal (status COMPLETED, nominal = koin × $10, custom_id = wallet).
 *  - paypalWebhook: diverifikasi ke PayPal (verify-webhook-signature) sebelum dipakai.
 *  - mintVoucher (WD eksklusif): kustodi R2 dicek pemiliknya; satu voucher per token.
 */
import { domain, bidHash, resultHash, coinHash, mintHash, mintBatchHash, sign, recover, keccak, bytesToHex, addressOf } from './sign.js';

const enc = new TextEncoder();
export const ALLOWED = new Set(['setConfig', 'attestResult', 'isSettled', 'paypalCreateOrder', 'paypalCapture', 'paypalWebhook', 'mintVoucher', 'mintBatchVoucher', 'signerAddress']);
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a));

export const createOnce = async (B, key, v) => (await B.put(key, JSON.stringify(v), { httpMetadata: { contentType: 'application/json' }, onlyIf: { etagDoesNotMatch: '*' } })) !== null;
export const read = async (B, key) => { const o = await B.get(key); return o ? o.json() : null; };
export const log = (B, stream, ev) => B.put(`log/${stream}/${new Date().toISOString().slice(0, 10)}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}.json`, JSON.stringify({ at: Date.now(), ...ev }));

/** Sandbox sampai pemilik mengganti PAYPAL_MODE ke "live" (setelah PayPal menyetujui penjualan aset kripto). */
export const ppApi = (env) => (env.PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com');

export async function paypalToken(env) {
  const r = await fetch(`${ppApi(env)}/v1/oauth2/token`, { method: 'POST', headers: { authorization: `Basic ${btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`)}`, 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=client_credentials' });
  if (!r.ok) throw new Error(`paypal auth ${r.status}`);
  return (await r.json()).access_token;
}

async function rpc(env, method, params) {
  const r = await fetch(env.BASE_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

export const methods = {
  /** Alamat kontrak aktif dari portal admin (worker sudah memverifikasi on-chain: ada kode & owner = admin). */
  async setConfig(env, cfg) {
    const ok = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a));
    // desain akhir 23 Nov 2026 (edisi ERC-1155): AuctionHouse/AxtoSale tidak dideploy lagi → boleh kosong bila standard = erc1155
    const editions = cfg.standard === 'erc1155';
    if (![84532, 8453].includes(Number(cfg.chainId)) || !ok(cfg.usdc)) return { error: 'config' };
    if (!editions && (!ok(cfg.auctionHouse) || !ok(cfg.sale))) return { error: 'config' };
    const v = { chainId: Number(cfg.chainId), standard: editions ? 'erc1155' : 'erc721', auctionHouse: editions ? null : cfg.auctionHouse, sale: editions ? null : cfg.sale, usdc: cfg.usdc, rpc: String(cfg.rpc), at: Date.now() };
    await env.VAULT_STORE.put('cfg.json', JSON.stringify(v), { httpMetadata: { contentType: 'application/json' } });
    await log(env.VAULT_STORE, 'config', v);
    return { ok: true };
  },

  signerAddress(env) {
    return { address: addressOf(env.SIGNER_KEY) };
  },

  /** Attestasi hasil lelang untuk AxtoAuctionHouse.claim. */
  async attestResult(env, { result: r, bid }) {
    const dom = domain('AXTO Auction House', Number(env.CHAIN_ID), env.AUCTION_HOUSE);
    if (!isAddr(r.winner) || !isAddr(r.collection) || !isAddr(r.currency)) return { error: 'address' };
    if (![0, 1, 2].includes(Number(r.mode))) return { error: 'mode' };
    const b = { lotId: r.lotId, collection: r.collection, tokenId: r.tokenId, currency: r.currency, maxAmount: BigInt(bid.maxUnits) * (r.currency.toLowerCase() === String(env.USDC ?? '').toLowerCase() ? 10n ** 4n : 10n ** 15n), nonce: bid.nonce, deadline: bid.deadline };
    // unit di sisi web: USDC 0,01 (10^4 base), AXTO 0,001 (10^15 base)
    if (recover(bidHash(dom, b), bid.sig).toLowerCase() !== r.winner.toLowerCase()) return { error: 'bid_signature' };
    if (BigInt(r.price) <= 0n || BigInt(r.price) > b.maxAmount) return { error: 'price' };
    if (Number(r.deadline) * 1000 < Date.now()) return { error: 'deadline' };
    const key = `att/${r.lotId}/${r.winner.toLowerCase()}.json`;
    const prev = await read(env.VAULT_STORE, key);
    if (prev) return { sig: prev.sig }; // idempoten
    const sig = sign(resultHash(dom, r), env.SIGNER_KEY);
    await createOnce(env.VAULT_STORE, key, { r, sig, at: Date.now() });
    await log(env.VAULT_STORE, 'attest', { lotId: r.lotId, winner: r.winner, price: String(r.price) });
    return { sig };
  },

  /** settled(lotId) on-chain (selector 0x... dari mapping publik `settled(bytes32)`). */
  async isSettled(env, { lotId }) {
    const sel = bytesToHex(keccak('settled(bytes32)').slice(0, 4)).slice(2);
    const out = await rpc(env, 'eth_call', [{ to: env.AUCTION_HOUSE, data: `0x${sel}${String(lotId).slice(2)}` }, 'latest']);
    return { settled: BigInt(out) === 1n };
  },

  async paypalCreateOrder(env, { wallet, coins }) {
    if (!isAddr(wallet)) return { error: 'wallet' };
    const n = Number(coins);
    if (!Number.isSafeInteger(n) || n < 1 || n > 5000) return { error: 'amount' };
    const usd = (n * Number(env.COIN_PRICE_USD)).toFixed(2);
    const tok = await paypalToken(env);
    const r = await fetch(`${ppApi(env)}/v2/checkout/orders`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json', 'paypal-request-id': crypto.randomUUID() },
      body: JSON.stringify({ intent: 'CAPTURE', purchase_units: [{ custom_id: wallet.toLowerCase(), description: `AXTO coin × ${n}`, amount: { currency_code: 'USD', value: usd } }], application_context: { brand_name: 'AXTO', shipping_preference: 'NO_SHIPPING', user_action: 'PAY_NOW', return_url: 'https://axto.io/en/coin?paypal=return', cancel_url: 'https://axto.io/en/coin?paypal=cancel' } }),
    });
    const j = await r.json();
    if (!r.ok) return { error: `paypal ${r.status}` };
    await createOnce(env.VAULT_STORE, `pp/order/${j.id}.json`, { wallet: wallet.toLowerCase(), coins: n, usd, at: Date.now() });
    return { id: j.id };
  },

  /** Capture → voucher CoinVoucher (member klaim sendiri di AxtoSale.claimPaid). Satu voucher per order. */
  async paypalCapture(env, { wallet, orderId }) {
    const order = await read(env.VAULT_STORE, `pp/order/${orderId}.json`);
    if (!order || order.wallet !== String(wallet).toLowerCase()) return { error: 'order' };
    const done = await read(env.VAULT_STORE, `pp/voucher/${orderId}.json`);
    if (done) return { ok: true, voucher: done };
    const tok = await paypalToken(env);
    const r = await fetch(`${ppApi(env)}/v2/checkout/orders/${orderId}/capture`, { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json', 'paypal-request-id': `cap-${orderId}` } });
    const j = await r.json();
    const pu = j.purchase_units?.[0];
    const cap = pu?.payments?.captures?.[0];
    if (j.status !== 'COMPLETED' || cap?.status !== 'COMPLETED') return { error: 'not_completed' };
    if (cap.amount?.currency_code !== 'USD' || cap.amount?.value !== order.usd || (pu.custom_id ?? cap.custom_id) !== order.wallet) return { error: 'mismatch' };
    return { ok: true, voucher: await this.issueCoinVoucher(env, orderId, order) };
  },

  async issueCoinVoucher(env, orderId, order) {
    const v = { to: order.wallet, amount: (BigInt(order.coins) * 10n ** 18n).toString(), ref: bytesToHex(keccak(`paypal:${orderId}`)), deadline: String(Math.floor(Date.now() / 1000) + 30 * 86400) };
    v.sig = sign(coinHash(domain('AXTO Sale', Number(env.CHAIN_ID), env.AXTO_SALE), v), env.SIGNER_KEY);
    if (!(await createOnce(env.VAULT_STORE, `pp/voucher/${orderId}.json`, v))) return read(env.VAULT_STORE, `pp/voucher/${orderId}.json`);
    await log(env.VAULT_STORE, 'coin', { orderId, to: v.to, amount: v.amount });
    return v;
  },

  /** Webhook PayPal diverifikasi ke PayPal. PAYMENT.CAPTURE.COMPLETED → voucher (bila member menutup tab sebelum capture). */
  async paypalWebhook(env, { headers, body }) {
    const tok = await paypalToken(env);
    const r = await fetch(`${ppApi(env)}/v1/notifications/verify-webhook-signature`, {
      method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: JSON.stringify({ auth_algo: headers['paypal-auth-algo'], cert_url: headers['paypal-cert-url'], transmission_id: headers['paypal-transmission-id'], transmission_sig: headers['paypal-transmission-sig'], transmission_time: headers['paypal-transmission-time'], webhook_id: env.PAYPAL_WEBHOOK_ID, webhook_event: JSON.parse(body) }),
    });
    const v = await r.json();
    if (v.verification_status !== 'SUCCESS') return { verified: false };
    const ev = JSON.parse(body);
    if (!(await createOnce(env.VAULT_STORE, `pp/event/${ev.id}.json`, { type: ev.event_type, at: Date.now() }))) return { verified: true, type: ev.event_type, duplicate: true };
    if (ev.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
      const orderId = ev.resource?.supplementary_data?.related_ids?.order_id;
      const order = orderId ? await read(env.VAULT_STORE, `pp/order/${orderId}.json`) : null;
      if (order && ev.resource?.amount?.value === order.usd && ev.resource?.amount?.currency_code === 'USD') await this.issueCoinVoucher(env, orderId, order);
    }
    if (ev.event_type === 'PAYMENT.CAPTURE.REFUNDED' || ev.event_type === 'PAYMENT.CAPTURE.REVERSED') await log(env.VAULT_STORE, 'refund', { id: ev.id, resource: ev.resource?.id });
    return { verified: true, type: ev.event_type };
  },

  /** WD eksklusif: voucher MintVoucher untuk pemilik kustodi (dicatat axto-web di R2 axto-data → diteruskan di payload). */
  async mintVoucher(env, { collection, collectionName, tokenId, owner, custodyRef }) {
    if (!isAddr(collection) || !isAddr(owner)) return { error: 'address' };
    const key = `wd/${collection.toLowerCase()}/${tokenId}.json`;
    const prev = await read(env.VAULT_STORE, key);
    if (prev) return prev.to.toLowerCase() === owner.toLowerCase() ? prev : { error: 'withdrawn' };
    const v = { to: owner, tokenId: String(tokenId), ref: bytesToHex(keccak(`wd:${custodyRef}`)), deadline: String(Math.floor(Date.now() / 1000) + 14 * 86400) };
    v.sig = sign(mintHash(domain(collectionName, Number(env.CHAIN_ID), collection), v), env.SIGNER_KEY);
    if (!(await createOnce(env.VAULT_STORE, key, v))) return read(env.VAULT_STORE, key);
    await log(env.VAULT_STORE, 'wd', { collection, tokenId, to: owner });
    return v;
  },

  /**
   * WD eksklusif edisi (AxtoEditions, desain akhir 23 Nov 2026): satuan atau massal dalam SATU voucher → satu transaksi,
   * gas lebih hemat. axto-web lebih dulu mengurangi kustodi member (R2) lalu meminta voucher dengan `wdRef` unik;
   * permintaan ulang dengan wdRef yang sama mengembalikan voucher yang sama (tidak pernah dua voucher untuk satu WD).
   */
  async mintBatchVoucher(env, { collection, collectionName, items, owner, wdRef }) {
    if (!isAddr(collection) || !isAddr(owner)) return { error: 'address' };
    if (!Array.isArray(items) || items.length < 1 || items.length > 50) return { error: 'items' };
    if (typeof wdRef !== 'string' || !/^[0-9a-z:_-]{8,80}$/.test(wdRef)) return { error: 'ref' };
    const ids = [];
    const amounts = [];
    for (const it of items) {
      const id = Number(it.id);
      const a = Number(it.amount);
      if (!Number.isSafeInteger(id) || id < 1 || !Number.isSafeInteger(a) || a < 1 || a > 10) return { error: 'item' };
      ids.push(String(id));
      amounts.push(String(a));
    }
    const ref = bytesToHex(keccak(`wd:${wdRef}`));
    const key = `wd/batch/${collection.toLowerCase()}/${ref}.json`;
    const prev = await read(env.VAULT_STORE, key);
    if (prev) return prev.to.toLowerCase() === owner.toLowerCase() ? prev : { error: 'withdrawn' };
    const v = { to: owner, ids, amounts, ref, deadline: String(Math.floor(Date.now() / 1000) + 14 * 86400) };
    v.sig = sign(mintBatchHash(domain(collectionName, Number(env.CHAIN_ID), collection), v), env.SIGNER_KEY);
    if (!(await createOnce(env.VAULT_STORE, key, v))) return read(env.VAULT_STORE, key);
    await log(env.VAULT_STORE, 'wd', { collection, ids, amounts, to: owner, wdRef });
    return v;
  },
};

