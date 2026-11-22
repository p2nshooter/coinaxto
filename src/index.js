/**
 * axto-vault — penjaga kunci AXTO. Tidak punya URL publik (workers_dev=false, tanpa route). Satu-satunya pintu:
 * Service Binding `VAULT.call(method, body, ts, mac)` dari axto-web, dengan HMAC-SHA256 per pesan, jendela 60 detik,
 * dan daftar metode yang diizinkan. Logika metode ada di ./methods.js (bisa diuji di Node tanpa runtime Cloudflare).
 */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { methods, ALLOWED, log, read } from './methods.js';

const enc = new TextEncoder();
async function verifyMac(env, method, ts, body, mac) {
  if (!ALLOWED.has(method)) return false;
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 60_000) return false;
  if (!/^[0-9a-f]{64}$/.test(String(mac))) return false;
  const k = await crypto.subtle.importKey('raw', enc.encode(env.VAULT_HMAC_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', k, Uint8Array.from(mac.match(/../g), (h) => parseInt(h, 16)), enc.encode(`${method}.${ts}.${body}`));
}

export class Vault extends WorkerEntrypoint {
  async call(method, body, ts, mac) {
    if (!(await verifyMac(this.env, method, Number(ts), String(body), mac))) {
      await log(this.env.VAULT_STORE, 'denied', { method });
      return { error: 'denied' };
    }
    try {
      const cfg = await read(this.env.VAULT_STORE, 'cfg.json');
      const env = cfg ? { ...this.env, CHAIN_ID: String(cfg.chainId), AUCTION_HOUSE: cfg.auctionHouse, AXTO_SALE: cfg.sale, USDC: cfg.usdc, BASE_RPC: cfg.rpc } : this.env;
      return await methods[method].call(methods, env, JSON.parse(body));
    } catch (e) {
      await log(this.env.VAULT_STORE, 'error', { method, e: String(e).slice(0, 500) });
      return { error: 'internal' };
    }
  }
}

/** Tidak ada antarmuka HTTP. */
export default { fetch: () => new Response(null, { status: 404 }) };
