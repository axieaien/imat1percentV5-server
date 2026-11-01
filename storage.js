// Storage layer. Two modes, no extra dependencies:
//  - local file  (default; fine for your own computer / paid disks)
//  - GitHub Gist (free, survives Render free-tier restarts). The data is AES-256-GCM encrypted before upload.
"use strict";
const crypto = require("crypto"), fs = require("fs"), path = require("path");

function createStorage({ dataDir, gistId, token, secret, apiBase = "https://api.github.com", fileName = "imat1-data.txt" }) {
  const remote = !!(gistId && token);
  const localFile = path.join(dataDir, "data.json");
  const key = crypto.createHash("sha256").update("imat1-storage:" + secret).digest();
  let lastPlain = null, saving = false, pending = null;

  const encrypt = (str) => {
    const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([c.update(str, "utf8"), c.final()]);
    return ["v1", iv.toString("base64"), c.getAuthTag().toString("base64"), ct.toString("base64")].join(".");
  };
  const decrypt = (blob) => {
    const [v, iv, tag, ct] = blob.trim().split(".");
    if (v !== "v1") throw new Error("Unknown storage format");
    const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
    d.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8");
  };
  const gh = async (url, opts = {}) => {
    const r = await fetch(url, { ...opts, headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github+json", "User-Agent": "imat1-server", "X-GitHub-Api-Version": "2022-11-28", ...(opts.headers || {}) } });
    if (!r.ok) throw new Error(`GitHub ${r.status}: ${(await r.text()).slice(0, 200)}`);
    return r;
  };

  async function load() { // returns the saved object, or null when nothing has been saved yet. Throws on real errors (never guess).
    if (remote) {
      const g = await (await gh(`${apiBase}/gists/${gistId}`)).json(), f = g.files && g.files[fileName];
      if (!f) throw new Error(`Gist has no file named "${fileName}". Create it (content: init).`);
      const text = f.truncated ? await (await gh(f.raw_url)).text() : f.content;
      if (!text || text.trim() === "init") return null;
      try { const plain = decrypt(text); lastPlain = plain; return JSON.parse(plain); } catch (e) { throw new Error("Could not decrypt the Gist data — is JWT_SECRET/STORAGE_KEY the same as before? (" + e.message + ")"); }
    }
    if (!fs.existsSync(localFile)) return null;
    try { return JSON.parse(fs.readFileSync(localFile, "utf8")); }
    catch (e) { try { fs.copyFileSync(localFile, localFile + ".corrupt-" + Date.now()); } catch (_) {} console.error("data.json unreadable, backed up and starting fresh:", e.message); return null; }
  }

  async function save(db) { // serialised; skips the network call if nothing changed
    const json = JSON.stringify(db);
    if (saving) { pending = json; return; }
    saving = true;
    try {
      let cur = json;
      while (cur) {
        if (remote) {
          if (lastPlain !== cur) { // random IV makes ciphertext differ every time, so compare plaintext
            await gh(`${apiBase}/gists/${gistId}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ files: { [fileName]: { content: encrypt(cur) } } }) });
            lastPlain = cur;
          }
        } else {
          fs.writeFileSync(localFile + ".tmp", cur); fs.renameSync(localFile + ".tmp", localFile);
        }
        cur = pending; pending = null;
      }
    } finally { saving = false; }
  }
  return { remote, load, save, encrypt, decrypt, mode: remote ? "github-gist (encrypted)" : "local file" };
}
module.exports = { createStorage };
