// Uji metode vault dengan R2 palsu: voucher WD edisi (satuan/massal) idempoten & tidak bisa dibajak alamat lain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { methods, ALLOWED } from '../src/methods.js';

function fakeR2() {
  const m = new Map();
  return {
    m,
    async get(k) { const v = m.get(k); return v === undefined ? null : { json: async () => JSON.parse(v) }; },
    async put(k, v, o = {}) { if (o.onlyIf?.etagDoesNotMatch === '*' && m.has(k)) return null; m.set(k, v); return { key: k }; },
  };
}
const key = ethers.Wallet.createRandom();
const env = () => ({ VAULT_STORE: fakeR2(), CHAIN_ID: '8453', SIGNER_KEY: key.privateKey });
const COL = '0x' + '12'.repeat(20);
const ME = '0x' + 'ab'.repeat(20);
const OTHER = '0x' + 'cd'.repeat(20);
const types = { MintVoucher: [{ name: 'to', type: 'address' }, { name: 'ids', type: 'uint256[]' }, { name: 'amounts', type: 'uint256[]' }, { name: 'ref', type: 'bytes32' }, { name: 'deadline', type: 'uint256' }] };

test('mintBatchVoucher: tanda tangan valid, idempoten per wdRef, alamat lain ditolak', async () => {
  assert.ok(ALLOWED.has('mintBatchVoucher'));
  const e = env();
  const args = { collection: COL, collectionName: 'AXTO Exclusive Time', items: [{ id: 5, amount: 2 }, { id: 9, amount: 10 }], owner: ME, wdRef: 'wd-member1-0001' };
  const v = await methods.mintBatchVoucher(e, args);
  assert.deepEqual(v.ids, ['5', '9']);
  assert.deepEqual(v.amounts, ['2', '10']);
  const dom = { name: 'AXTO Exclusive Time', version: '1', chainId: 8453, verifyingContract: COL };
  assert.equal(ethers.verifyTypedData(dom, types, { to: v.to, ids: v.ids, amounts: v.amounts, ref: v.ref, deadline: v.deadline }, v.sig), key.address);
  assert.deepEqual(await methods.mintBatchVoucher(e, args), v, 'permintaan ulang → voucher yang sama');
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...args, owner: OTHER }), { error: 'withdrawn' });
});

test('mintBatchVoucher: masukan buruk ditolak', async () => {
  const e = env();
  const base = { collection: COL, collectionName: 'X', owner: ME, wdRef: 'wd-member1-0002' };
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...base, items: [] }), { error: 'items' });
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...base, items: [{ id: 1, amount: 11 }] }), { error: 'item' });
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...base, items: [{ id: 0, amount: 1 }] }), { error: 'item' });
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...base, items: [{ id: 1, amount: 1 }], wdRef: 'x' }), { error: 'ref' });
  assert.deepEqual(await methods.mintBatchVoucher(e, { ...base, items: [{ id: 1, amount: 1 }], owner: 'nope' }), { error: 'address' });
  assert.equal(e.VAULT_STORE.m.size, 0, 'tidak ada yang tersimpan');
});

test('setConfig edisi ERC-1155 tanpa AuctionHouse/AxtoSale', async () => {
  const e = env();
  assert.deepEqual(await methods.setConfig(e, { chainId: 8453, standard: 'erc1155', usdc: COL, rpc: 'https://mainnet.base.org' }), { ok: true });
  assert.equal(JSON.parse(e.VAULT_STORE.m.get('cfg.json')).standard, 'erc1155');
  assert.deepEqual(await methods.setConfig(e, { chainId: 8453, usdc: COL, rpc: 'x' }), { error: 'config' }, 'ERC-721 lama tetap wajib alamat lengkap');
});
