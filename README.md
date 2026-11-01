# I'm at 1 Percent V5 — Live Battery Assistance (100% free to run)

Node.js + WebSocket server and a single-page front-end. No paid services, no Firebase.

## Run locally
```bash
npm install
npm start        # http://localhost:3000
```
Data is saved to `data.json` next to the server.

## Free hosting that keeps your data
Render's free plan wipes its disk whenever the app sleeps or redeploys, so V5 saves its data to a **private GitHub Gist** instead (free). Everything is **encrypted (AES-256-GCM)** before upload with a key derived from `JWT_SECRET`.

| Env var | What it is |
|---|---|
| `JWT_SECRET` | **Required in production.** Long random string. Also the encryption key. Never change it or old data can't be read. |
| `GIST_ID` | ID of your secret gist (the last part of its URL) |
| `GITHUB_TOKEN` | Classic token with only the `gist` scope |
| `ADMIN_EMAIL` | Optional. Your account email(s), comma separated → unlocks the Moderation panel in Profile |
| `DATA_DIR` | Optional. Local folder for `data.json` when not using a Gist |

The gist must contain one file named `imat1-data.txt` with the text `init`. If the stored data can't be read at startup the server refuses to start rather than overwrite it.

**Keep-alive (free):** Render's free plan sleeps after ~15 min of no traffic (first visit then takes ~30–60 s). To keep it awake, create a free UptimeRobot monitor for `https://YOUR-APP.onrender.com/healthz` at a 5-minute interval.

## Features
- Accounts (bcrypt + JWT), change password, delete account, rate limiting, CSP + security headers, input validation
- Live map centered on you with three selectable search radii only: 100 m, 500 m, and 1 km; 3 CDN fallbacks for the map library, tile fallback, Google/Apple Maps links when routing is unavailable
- Location permission handling for iOS / Android / desktop, HTTPS and in-app-browser checks, manual "pin on map" fallback
- Requests (Pending → Accepted → Resolved / Cancelled / auto-Expired) for power banks, chargers, laptop chargers, USB-C/Lightning/Micro-USB cables, wall chargers, charging adapters, universal travel adapters, and charging outlets; helper alerts, chat with unread badges, read receipts, typing indicator
- Block / report users, admin moderation panel (remove & ban), automatic clean-up of old data
- Installable PWA, offline banner, reconnect resync
- Location and presence are memory-only (never saved) and expire ~90 s after a user goes quiet

## API summary
| Method | Path | Purpose |
|---|---|---|
| POST | /api/auth/register · /login | `{token,user}` |
| GET / PUT / DELETE | /api/me | profile · update · delete account |
| POST | /api/me/password | change password |
| POST | /api/location · /heartbeat · /offline | presence |
| GET | /api/users | others' public profile/presence |
| GET / POST | /api/requests | visible requests · create |
| POST | /api/requests/:id/accept · /resolve · /cancel | lifecycle |
| GET | /api/conversations · /api/messages?with= | chat |
| POST | /api/messages · /api/messages/read | send · mark read |
| POST | /api/block · /api/report · GET /api/blocked | safety |
| GET | /api/admin/reports · POST /api/admin/dismiss · /remove | moderation (admin only) |
| GET | /healthz | health check |
| WS | /ws?token=… | realtime events |

## Not included
Password reset by email (removed on purpose — needs an email service), automated tests.

## V5 updates
- Added laptop charger and compatible charging accessories to request choices.
- Restricted the location search radius to 100 m, 500 m, or 1 km (default: 500 m). The radius is applied to nearby map markers and helper/request lists whenever your location is available.
