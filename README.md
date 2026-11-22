# axto-vault (privat)

Worker tersembunyi AXTO: penanda tangan attestasi lelang, voucher koin (PayPal) dan voucher WD eksklusif.
Tanpa route, tanpa domain, `workers_dev = false`; hanya bisa dipanggil `axto-web` lewat Service Binding + HMAC.
Penyimpanan: R2 `axto-vault-data` saja (tidak pernah D1). Rahasia hanya di Cloudflare/GitHub Secrets.

- `npm test` — tanda tangan EIP-712 identik dengan ethers & kontrak.
- Deploy: `.github/workflows/deploy.yml` (butuh secret `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `SIGNER_KEY`,
  `VAULT_HMAC_KEY`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`).

Potret model (wajah + kerudung) **tidak** disimpan di repo ini (repo publik): sudah diunggah ke R2 `axto-nft-data/model/`
dan hanya ditampilkan worker setelah izin tertulis model tercatat (`MODEL_CONSENT`).
