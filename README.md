# Husky_dev CDN

## Deployment

1. Configure `MONGODB_URI` (and optionally `MONGODB_DB`) for MongoDB Atlas.
2. Set `PUBLIC_BASE_URL=https://cdn.huskydev.space` and `SESSION_SECRET` to a random secret with at least 32 characters.
3. Configure `ADMIN_EMAIL` and SMTP credentials: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and optionally `SMTP_FROM` and `SMTP_SECURE`. The admin signs in with a one-time email link that expires after 15 minutes.
4. Optionally configure `PAYMENT_INSTRUCTIONS` with the manual $5 payment details users should follow.
5. Configure `CRON_SECRET` as a long random secret. Vercel sends it as a Bearer token to the daily `/api/cleanup` Cron Job in `vercel.json`.
6. Add `cdn.huskydev.space` to the Vercel project domains and configure the DNS record Vercel provides. Domain/DNS activation must be completed in Vercel and the DNS provider.
7. Deploy the project. Local `.env` values are loaded by dotenv; do not commit secrets.

For local development, set `PUBLIC_BASE_URL=http://localhost:7001` in `.env`, along with `MONGODB_URI` and `SESSION_SECRET`. SMTP, `ADMIN_EMAIL`, and admin settings are needed for the admin panel.

## Accounts and admin

- Temporary website uploads are public and do not require an account. An account is only required for the $5/month permanent-storage plan. Public registration uses email and a password of at least 12 characters.
- The admin panel is at `/admin`. The allowed admin email is set by `ADMIN_EMAIL`; signing in requires SMTP access to that mailbox.
- The dashboard lists recent accounts, payment requests, and files. The admin can approve a manual payment for 30 days, grant or revoke access, disable accounts, revoke API keys, and delete files.
- The monthly permanent-storage permission costs **$5 USD** and is confirmed manually by the admin. There is no payment processor integration.
- If permission expires or is revoked, existing permanent files are retained, but new permanent uploads are blocked.
- Each account has a **100 GB** storage quota. The current per-request upload limit remains 4 MB by default (`MAX_FILE_SIZE`).

## File lifetime and API

The website and APIs support `30m`, `2h`, `12h`, `2d`, `30d`, `1y`, and `never`. Temporary uploads through the website and API are available without login; permanent website uploads require an account and active permission, and permanent API uploads require a user API key and active permanent-storage permission.

- `POST /api/upload`: multipart fields `file` and optional `expiresIn`.
- `GET /api/upload/to`: query parameters `url`, `namefile`, and optional `expiresIn`.
- To upload permanently through the API, create an API key in `/account` and send it as `Authorization: Bearer hdev_...`. Keys are only shown once and can be rotated or revoked from the account page or admin dashboard.
- The default lifetime when `expiresIn` is omitted is `12h`.
- API responses include `expiresAt`; permanent files return `null`.
- Expired files stop being served immediately when accessed. The daily Cron Job physically removes expired GridFS files; cleanup may be delayed until that job runs.
- Files uploaded before account ownership and expiration were introduced remain in GridFS and appear as legacy/anonymous files in the admin panel.

## Local development

```bash
npm install
npm start
```

In VS Code, start **Husky_dev CDN (Express)** from the Run and Debug panel (F5). This runs the Express app and opens its local URL (port 7001 by default). Do not use Live Server or open files under `views/` directly: static preview servers do not process EJS templates, and will display template tags instead of the rendered page.
