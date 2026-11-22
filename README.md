# Godown Ledger (with your MongoDB Atlas database)

Stock, route sales, customer credit, reports and Excel downloads. Data is saved in your MongoDB Atlas database.
Three people types: owner (everything), staff (add entries only), viewer (look only).

## Open in VS Code and run (5 steps)
1. Install **Node.js 18 or newer** from nodejs.org.
2. Unzip this folder, then in VS Code: **File > Open Folder** and choose it.
3. Open the terminal in VS Code (**Terminal > New Terminal**) and run:  `npm install`
4. Make your settings file:
   - Copy `.env.example` and name the copy `.env`
   - In `.env`, replace `<db_password>` with the password of your Atlas database user `jyothidalli925_db_user`
   - Replace the three keys with your own long random texts. Give staff only the STAFF key and viewers only the VIEW key.
5. Run `npm start`, then open **http://localhost:3000** in Chrome and type your owner key when asked.

## Atlas settings you must check
- **Database Access:** the user needs read and write permission for the database.
- **Network Access:** add the IP address of the computer or host that runs this server. (If it changes often, "Allow access
  from anywhere" works, but then the database password is your only protection, so make it long.)
- If the password has special characters, URL-encode them in `.env` (@ becomes %40, # becomes %23, / becomes %2F).

## Putting it online so staff can use it
Run the same folder on a host (Render, Railway, a VPS). Add the values from `.env` as "Environment variables" there instead of
uploading `.env`. Use HTTPS. Staff open the host's web address and type the staff key.

## Files
- `server.js`   the server. It holds the database URL and enforces who may do what.
- `public/index.html`   the whole app (search, Godown, Sales, Customers, Lines, Reports, downloads).
- `.env`   your secrets (you create it; never share it or upload it to GitHub).

## How safety works
- The Atlas URL is only in `.env` on the server. It is never sent to the browser.
- Staff can add but cannot change or delete existing entries. The server refuses it even if someone tries to bypass the app.
- When the owner changes or deletes something, the old copy is kept in the `history` and `deleted` collections.
- Every write is recorded in the `audit` collection, and the activity log in the app cannot be deleted.
- Wrong keys are slowed down: 30 wrong tries from one address blocks it for 10 minutes.
- Keep regular backups: Atlas can schedule them, and the app has Download buttons (Excel and full backup).
