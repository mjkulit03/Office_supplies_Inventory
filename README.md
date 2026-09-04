# SupplyOps — Office Supplies & Asset Inventory (Local Network App)

Multi-user inventory system: **Node.js + Express backend** with a shared JSON-file
database (`data/db.json`), so every computer on your network sees the same data.

## Quick start (on the "server" PC)

1. Install [Node.js](https://nodejs.org) (LTS version is fine).
2. Open a terminal in this folder and run:

```bash
npm install
npm start
```

The console will print something like:

```
On this PC:   http://localhost:3001
On your LAN:  http://192.168.1.15:3001
```

3. On any other PC/phone in the same network, open the **LAN address** (e.g.
   `http://192.168.1.15:3001`) in a browser.

## Default login

| Username     | Password       | Role          |
|--------------|----------------|---------------|
| `admin`      | `adminpassword`| Admin         |
| `staff_john` | `userpassword` | Standard User |

⚠️ **Change these immediately** via *User Profiles* after first login
(edit each user and set a new password).

## Windows Firewall (one-time)

If other PCs can't connect, allow Node.js through the firewall for **Private networks**:
the first time you run `npm start`, Windows will show a firewall prompt — click **Allow**.
Or add a rule manually:

```powershell
netsh advfirewall firewall add rule name="SupplyOps" dir=in action=allow protocol=TCP localport=3001 profile=private
```

## Security features

- Passwords hashed with scrypt + per-user salt; never stored or sent in plaintext.
- Session tokens (12h expiry); all data endpoints require authentication.
- User management & audit trail enforced **server-side** — Admin role can't be bypassed from the browser.
- Last-Admin protection: you can't demote/delete the only remaining Admin.
- XSS-hardened rendering (all user data escaped before insertion into HTML).

## Data & backup

- All shared data lives in `data/db.json` on the server PC.
- Back it up by copying that file (or use 💾 Export JSON inside the app).
- 📂 Import JSON restores items/suppliers/POs/audit. Users are deliberately NOT
  restored (old exports contained plaintext passwords) — manage users in-app.
- Stop the server with `Ctrl+C`.

## Project layout

```
server.js          Express API + static hosting + JSON-file DB
public/index.html  Frontend SPA (talks to the REST API)
data/db.json       Shared database (auto-created on first run)
```
