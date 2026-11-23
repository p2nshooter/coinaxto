/** Penandatanganan EIP-712 untuk vault: attestasi hasil lelang, voucher koin (PayPal), voucher mint (WD eksklusif). */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

const enc = new TextEncoder();
export const keccak = (b) => keccak_256(typeof b === 'string' ? enc.encode(b) : b);
export const hexToBytes = (h) => {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error('hex');
  return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
};
export const bytesToHex = (b) => `0x${[...b].map((x) => x.toString(16).padStart(2, '0')).join('')}`;
const concat = (...a) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};
const word = (n) => {
  const b = new Uint8Array(32);
  let x = BigInt(n);
  if (x < 0n) throw new Error('negative');
  for (let i = 31; i >= 0; i -= 1) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
};
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(a);
const addr = (a) => { if (!isAddr(a)) throw new Error(`address ${a}`); return concat(new Uint8Array(12), hexToBytes(a)); };
const b32 = (h) => { const b = hexToBytes(h); if (b.length !== 32) throw new Error('bytes32'); return b; };

const DOMAIN = keccak('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)');
export const domain = (name, chainId, verifyingContract) => keccak(concat(DOMAIN, keccak(name), keccak('1'), word(chainId), addr(verifyingContract)));
const digest = (dom, struct) => keccak(concat(new Uint8Array([0x19, 0x01]), dom, struct));

const T_BID = keccak('Bid(bytes32 lotId,address collection,uint256 tokenId,address currency,uint256 maxAmount,uint256 nonce,uint256 deadline)');
const T_RESULT = keccak('Result(bytes32 lotId,address collection,uint256 tokenId,address winner,address currency,uint256 price,address seller,uint8 mode,uint256 deadline)');
const T_COIN = keccak('CoinVoucher(address to,uint256 amount,bytes32 ref,uint256 deadline)');
const T_MINT = keccak('MintVoucher(address to,uint256 tokenId,bytes32 ref,uint256 deadline)');
/** Desain akhir 23 Nov 2026 (AxtoEditions ERC-1155): satu voucher untuk WD satuan atau massal (array id & jumlah). */
const T_MINT_BATCH = keccak('MintVoucher(address to,uint256[] ids,uint256[] amounts,bytes32 ref,uint256 deadline)');

export const bidHash = (dom, b) => digest(dom, keccak(concat(T_BID, b32(b.lotId), addr(b.collection), word(b.tokenId), addr(b.currency), word(b.maxAmount), word(b.nonce), word(b.deadline))));
export const resultHash = (dom, r) => digest(dom, keccak(concat(T_RESULT, b32(r.lotId), addr(r.collection), word(r.tokenId), addr(r.winner), addr(r.currency), word(r.price), addr(r.seller), word(r.mode), word(r.deadline))));
export const coinHash = (dom, v) => digest(dom, keccak(concat(T_COIN, addr(v.to), word(v.amount), b32(v.ref), word(v.deadline))));
export const mintHash = (dom, v) => digest(dom, keccak(concat(T_MINT, addr(v.to), word(v.tokenId), b32(v.ref), word(v.deadline))));
export const mintBatchHash = (dom, v) => digest(dom, keccak(concat(T_MINT_BATCH, addr(v.to), keccak(concat(...v.ids.map(word))), keccak(concat(...v.amounts.map(word))), b32(v.ref), word(v.deadline))));

export function sign(hash32, keyHex) {
  const s = secp256k1.sign(hash32, hexToBytes(keyHex), { lowS: true });
  return bytesToHex(concat(s.toCompactRawBytes(), new Uint8Array([27 + s.recovery])));
}

export function recover(hash32, sigHex) {
  const sig = hexToBytes(sigHex);
  if (sig.length !== 65) throw new Error('sig');
  let v = sig[64];
  if (v >= 27) v -= 27;
  const s = secp256k1.Signature.fromCompact(sig.slice(0, 64));
  if (s.hasHighS()) throw new Error('high-s');
  const pub = s.addRecoveryBit(v).recoverPublicKey(hash32).toRawBytes(false);
  return bytesToHex(keccak(pub.slice(1)).slice(12));
}

export const addressOf = (keyHex) => bytesToHex(keccak(secp256k1.getPublicKey(hexToBytes(keyHex), false).slice(1)).slice(12));
