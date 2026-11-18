# Husky_dev CDN

## Deployment

1. Configure `MONGODB_URI` (and optionally `MONGODB_DB`) for MongoDB Atlas.
2. Set `PUBLIC_BASE_URL=https://cdn.huskydev.space` and `SESSION_SECRET` to a random secret with at least 32 characters.
3. Configure SMTP credentials: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and optionally `SMTP_FROM` and `SMTP_SECURE`. Set `ADMIN_EMAIL=alfredojoseamaya4580@gmail.com` in Vercel; this is the inbox for admin sign-in and usage alerts. The admin signs in with a one-time email link that expires after 15 minutes. SMTP must be working for sign-in and usage alerts.
4. Optionally configure `PAYMENT_INSTRUCTIONS` with the manual $5 payment details users should follow.
5. Add `R2_ACCOUNT_ID=d321779fc92cf0ac2d2787f728dc83d1`, `R2_BUCKET=cdnhusky`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_PUBLIC_URL`, and `R2_GATEWAY_URL` to Vercel. Set the last two to the same Worker custom domain, for example `https://files.huskydev.space`. The S3 API endpoint is `https://d321779fc92cf0ac2d2787f728dc83d1.r2.cloudflarestorage.com`; the app uses region `auto`. The direct single-PUT upload default is 5 GB (`MAX_R2_UPLOAD_SIZE` can lower it); files larger than 5 GB need an R2 multipart-upload flow.
6. Configure `CRON_SECRET` as a long random secret. Vercel sends it as a Bearer token to the daily `/api/cleanup` Cron Job in `vercel.json`.
7. In Vercel, add `cdn.huskydev.space` under **Project → Settings → Domains**. Add the exact DNS record Vercel shows at the DNS provider for `huskydev.space`; do not point this hostname at R2 or the Worker.
8. Deploy the project. Local `.env` values are loaded by dotenv; do not commit secrets.

`R2_PUBLIC_URL` must be the custom domain served by the Cloudflare Worker described below, for example `https://files.huskydev.space`. It must not be a direct public R2 or `r2.dev` URL once download limits are enabled.

### Deploy the R2 download gateway

The Worker is required to count public R2 reads and enforce the per-IP and monthly download limits. Deploy it before changing `R2_PUBLIC_URL`:

1. Edit `workers/r2-gateway/wrangler.toml`: confirm `bucket_name = "cdnhusky"` and `APP_USAGE_URL = "https://cdn.huskydev.space/api/r2/usage-event"`. In **R2 → cdnhusky → Metrics/Analytics**, read the current month's Class B count and replace `CLASS_B_BASELINE` and `CLASS_B_BASELINE_MONTH` in the TOML with that count and current `YYYY-MM`. Before the app's first request initializes its counter, set the Vercel variables `R2_CLASS_A_BASELINE`, `R2_CLASS_A_BASELINE_MONTH`, and `R2_UNTRACKED_STORAGE_BYTES` to the current Class A count, current month, and existing R2 bytes not represented in MongoDB, respectively.
2. Generate one long random `R2_USAGE_WEBHOOK_SECRET`. Add it as a **Production** environment variable in Vercel and set the same value as a Worker secret, then deploy:

   ```powershell
   npx wrangler login
   npx wrangler secret put USAGE_WEBHOOK_SECRET --config workers\r2-gateway\wrangler.toml
   npx wrangler deploy --config workers\r2-gateway\wrangler.toml
   ```

3. In Cloudflare, make sure the `huskydev.space` zone is active and its DNS is managed by Cloudflare. Open the deployed Worker under **Workers & Pages → huskycdn-r2-gateway → Settings → Domains & Routes → Add → Custom Domain** and attach `files.huskydev.space`. Cloudflare provisions DNS/TLS. Keep `cdn.huskydev.space` assigned to Vercel. If `files.huskydev.space` is already attached directly to R2, remove that bucket custom-domain association before attaching it to the Worker. Disable public `r2.dev` access and do not share direct S3 endpoint URLs, or those URLs bypass download controls. If DNS is not on Cloudflare, do not change the live `cdn` record; use the assigned `workers.dev` hostname temporarily or migrate the zone's DNS deliberately before adding `files`.
4. In Vercel **Project → Settings → Environment Variables**, set the Production variables below, save, then redeploy the app. Presigned uploads stay disabled until the Worker is available and the two URLs exactly match its custom domain.

| Vercel variable | Value |
|---|---|
| `PUBLIC_BASE_URL` | `https://cdn.huskydev.space` |
| `ADMIN_EMAIL` | `alfredojoseamaya4580@gmail.com` |
| `R2_ACCOUNT_ID` | `d321779fc92cf0ac2d2787f728dc83d1` |
| `R2_BUCKET` | `cdnhusky` |
| `R2_PUBLIC_URL` | `https://files.huskydev.space` |
| `R2_GATEWAY_URL` | `https://files.huskydev.space` |
| `R2_USAGE_WEBHOOK_SECRET` | The same long random secret stored in the Worker |
| `R2_CLASS_A_BASELINE` | Current month's Class A operations from R2 analytics |
| `R2_CLASS_A_BASELINE_MONTH` | Current month as `YYYY-MM` |
| `R2_UNTRACKED_STORAGE_BYTES` | Existing R2 bytes not represented in MongoDB |

Also set `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` using an R2 API token restricted to **Object Read & Write** for bucket `cdnhusky`. Keep these values private; do not put them in browser code or commit them. Configure the existing `MONGODB_URI`, `SESSION_SECRET`, `CRON_SECRET`, and `SMTP_*` variables in the same Vercel Production environment.

The app sends an email at 9.0 GB of tracked R2 objects, 900,000 estimated Class A operations, and 9 million Worker-served Class B reads. It blocks new uploads at 9.5 GB or 950,000 estimated Class A operations, and the Worker blocks reads at 9.5 million Class B operations. Uploads are limited to 20 per IP per 15 minutes and 100 per IP per day; downloads are limited to 300 per IP per 15 minutes and 3,000 per IP per day. Files larger than 1 GB trigger an email before a signed upload URL is issued.

Storage is tracked from this app's R2 file records, active upload reservations, and the one-time `R2_UNTRACKED_STORAGE_BYTES` baseline. Set that value before the app's first request initializes the counter. Class A is deliberately a conservative app-side estimate because direct, presigned R2 PUTs do not pass through the Worker; use Cloudflare analytics as the billing source of truth. The Worker count covers reads through its hostname. The R2 free storage allowance is billed as GB-months, so this 9.5 GB limit is a current-object-size safety cap, not an exact billing meter. Workers and Durable Objects have separate Cloudflare limits and may have separate charges.

### Configure R2 CORS

In the Cloudflare dashboard, open **R2 Object Storage → your bucket → Settings → CORS Policy → Edit CORS policy**. Apply a policy like this, replacing the origins with the exact production app URL and local/preview app URLs you use:

```json
[
  {
    "AllowedOrigins": [
      "https://cdn.huskydev.space",
      "http://localhost:7001"
    ],
    "AllowedMethods": ["PUT", "GET", "HEAD"],
    "AllowedHeaders": ["Content-Type", "Content-Length", "If-None-Match", "x-amz-meta-cdn-expires-at"],
    "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

Add the exact Vercel preview or tunnel origin when testing from one; avoid `*` in production.

For local development, set `PUBLIC_BASE_URL=http://localhost:7001`, `MONGODB_URI`, and `SESSION_SECRET`. SMTP credentials are required for the admin panel; `ADMIN_EMAIL` is optional and defaults to the address above.

## Accounts and admin

- Temporary website uploads are public and do not require an account. An account is only required for the $5/month permanent-storage plan. Public registration uses email and a password of at least 12 characters.
- The admin panel is at `/admin`. The allowed admin email is `ADMIN_EMAIL` (set it to `alfredojoseamaya4580@gmail.com`); signing in requires SMTP access to that mailbox.
- The dashboard lists recent accounts, payment requests, R2 usage, and files. The admin can approve a manual payment for 30 days, grant or revoke access, disable accounts, revoke API keys, delete files, and change a file's lifetime (including making it permanent).
- The monthly permanent-storage permission costs **$5 USD** and is confirmed manually by the admin. There is no payment processor integration.
- If permission expires or is revoked, existing permanent files are retained, but new permanent uploads are blocked.
- Each account has a **100 GB** storage quota. Direct-to-R2 browser uploads default to the 5 GB single-PUT maximum (`MAX_R2_UPLOAD_SIZE`). The legacy server-side API remains limited by `MAX_FILE_SIZE` and Vercel's request limits.

## File lifetime and API

The website's direct-to-R2 flow preserves the uploaded filename (including spaces and Unicode) in the public R2 URL and file listings. It uses a unique internal ID so multiple uploads can have the same original filename:

1. `POST /api/presign` with JSON fields `filename`, `contentType`, `size`, and optional `expiresIn`. The app enforces storage, monthly operation safety caps, and persistent IP upload limits before issuing the URL.
2. Browser sends the file bytes with `PUT` to the returned `uploadUrl`, which is size-bound and create-only to prevent overwrites/replays after the first successful upload.
3. `POST /api/files` with the returned `intentId`; the server checks R2's actual size and content type and saves metadata to MongoDB. Object expiry is also signed into R2 metadata so the Worker can reject expired files.

Supported lifetimes are `30m`, `2h`, `12h`, `2d`, `30d`, `1y`, and `never`. Temporary uploads are public. Permanent uploads require an account with active permission; API clients use their account API key. The default lifetime is `12h`.

- `POST /api/upload` and `GET /api/upload/to` remain legacy server-side upload endpoints and are subject to Vercel request/function limits. Use the website's direct-to-R2 flow for larger files.
- API keys are created in `/account`, shown once, and can be rotated or revoked from the account page or admin dashboard.
- File bytes live in R2; MongoDB stores file metadata and short-lived upload intents. Expired objects are removed by the daily Cron Job, so physical deletion can be delayed until it runs.
- Existing files in GridFS remain readable and manageable as legacy files.

## Local development

```bash
npm install
npm start
```

In VS Code, start **Husky_dev CDN (Express)** from the Run and Debug panel (F5). This runs the Express app and opens its local URL (port 7001 by default). Do not use Live Server or open files under `views/` directly: static preview servers do not process EJS templates.
