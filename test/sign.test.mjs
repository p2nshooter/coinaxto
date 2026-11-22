import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { domain, resultHash, coinHash, mintHash, bidHash, sign, recover, addressOf, bytesToHex } from '../src/sign.js';

const key = ethers.Wallet.createRandom();
const AH = '0x1111111111111111111111111111111111111111';

test('Result: tanda tangan vault dipulihkan ethers sebagai signer (sama dengan kontrak)', () => {
  const d = { name: 'AXTO Auction House', version: '1', chainId: 8453, verifyingContract: AH };
  const types = { Result: [
    { name: 'lotId', type: 'bytes32' }, { name: 'collection', type: 'address' }, { name: 'tokenId', type: 'uint256' }, { name: 'winner', type: 'address' },
    { name: 'currency', type: 'address' }, { name: 'price', type: 'uint256' }, { name: 'seller', type: 'address' }, { name: 'mode', type: 'uint8' }, { name: 'deadline', type: 'uint256' }] };
  const r = { lotId: ethers.id('axto:time:42'), collection: '0x2222222222222222222222222222222222222222', tokenId: '42', winner: ethers.Wallet.createRandom().address, currency: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', price: '1000000', seller: ethers.ZeroAddress, mode: 0, deadline: '1900000000' };
  const h = resultHash(domain(d.name, d.chainId, AH), r);
  assert.equal(bytesToHex(h), ethers.TypedDataEncoder.hash(d, types, r));
  const sig = sign(h, key.privateKey);
  assert.equal(ethers.verifyTypedData(d, types, r, sig), key.address);
  assert.equal(addressOf(key.privateKey).toLowerCase(), key.address.toLowerCase());
});

test('CoinVoucher & MintVoucher & Bid: hash identik dengan ethers', async () => {
  const sale = { name: 'AXTO Sale', version: '1', chainId: 8453, verifyingContract: AH };
  const v = { to: key.address, amount: (10n ** 19n).toString(), ref: ethers.id('paypal:ABC'), deadline: '1900000000' };
  assert.equal(bytesToHex(coinHash(domain('AXTO Sale', 8453, AH), v)), ethers.TypedDataEncoder.hash(sale, { CoinVoucher: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'ref', type: 'bytes32' }, { name: 'deadline', type: 'uint256' }] }, v));
  const col = { name: 'AXTO Exclusive Time', version: '1', chainId: 8453, verifyingContract: AH };
  const m = { to: key.address, tokenId: '7', ref: ethers.id('wd:x'), deadline: '1900000000' };
  assert.equal(bytesToHex(mintHash(domain(col.name, 8453, AH), m)), ethers.TypedDataEncoder.hash(col, { MintVoucher: [{ name: 'to', type: 'address' }, { name: 'tokenId', type: 'uint256' }, { name: 'ref', type: 'bytes32' }, { name: 'deadline', type: 'uint256' }] }, m));
  const ah = { name: 'AXTO Auction House', version: '1', chainId: 8453, verifyingContract: AH };
  const types = { Bid: [{ name: 'lotId', type: 'bytes32' }, { name: 'collection', type: 'address' }, { name: 'tokenId', type: 'uint256' }, { name: 'currency', type: 'address' }, { name: 'maxAmount', type: 'uint256' }, { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] };
  const b = { lotId: ethers.id('axto:time:1'), collection: AH, tokenId: 1n, currency: AH, maxAmount: 100n, nonce: 5n, deadline: 1900000000n };
  const sig = await key.signTypedData(ah, types, b);
  assert.equal(recover(bidHash(domain(ah.name, 8453, AH), b), sig).toLowerCase(), key.address.toLowerCase());
});
