import os
import sys
import json
import time
import argparse
import base64
import hmac
import hashlib
import asyncio
from typing import Dict, Optional
from getpass import getpass
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, HTMLResponse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_PATH = os.path.join("lock", "vault.bin")
SERVER_TOKEN_PATH = os.path.join("lock", "server_token.txt")
AUDIT_LOG = os.path.join("lock", "audit.log")
KDF_ITER = 300_000
SALT_SIZE = 16
NONCE_SIZE = 12
RATE_LIMIT_WINDOW = 60   
RATE_LIMIT_MAX = 30     

# In-memory rate state
rate_state: Dict[str, Dict[str, int]] = {}
_rate_lock = asyncio.Lock()

app = FastAPI(title="Skid Vault Server (minimal)")

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITER,
    )
    return kdf.derive(password)

def decrypt_vault_blob(blob: bytes, password: str) -> Dict:
    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("vault file corrupted or too small")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ct = blob[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

def encrypt_vault_blob(data: Dict, password: str) -> bytes:
    """Return blob = salt | nonce | ciphertext"""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct

def write_vault_blob_atomic(blob: bytes) -> None:
    tmp = VAULT_PATH + ".tmp"
    os.makedirs(os.path.dirname(VAULT_PATH), exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, VAULT_PATH)
    try:
        os.chmod(VAULT_PATH, 0o600)
    except Exception:
        pass

# server token management
def create_server_token_if_missing():
    if not os.path.isdir("lock"):
        os.makedirs("lock", exist_ok=True)
    if os.path.exists(SERVER_TOKEN_PATH):
        return
    token = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    with open(SERVER_TOKEN_PATH, "w") as f:
        f.write(token)
    try:
        os.chmod(SERVER_TOKEN_PATH, 0o600)
    except Exception:
        pass
    print(f"[INFO] Created server token at {SERVER_TOKEN_PATH}. Copy it to your phone app and keep it secret.")

def read_server_token() -> str:
    if not os.path.exists(SERVER_TOKEN_PATH):
        raise SystemExit("Server token missing. Start server once to auto-create it.")
    return open(SERVER_TOKEN_PATH, "r").read().strip()

#audit logging
def audit_event(token_id_masked: str, action: str, entry_name: Optional[str], client_ip: str, status: str, note: str = ""):
    ev = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "token": token_id_masked,
        "action": action,
        "entry": entry_name,
        "client_ip": client_ip,
        "status": status,
        "note": note
    }
    line = json.dumps(ev, separators=(",", ":"))
    with open(AUDIT_LOG, "a") as f:
        f.write(line + "\n")
    try:
        os.chmod(AUDIT_LOG, 0o600)
    except Exception:
        pass

def mask_token(token: str) -> str:
    if not token:
        return ""
    return token[:4] + "..." + token[-4:]

#rate limiter
async def check_rate_limit(token: str):
    now = int(time.time())
    async with _rate_lock:
        state = rate_state.get(token)
        if not state:
            rate_state[token] = {"window_start": now, "count": 1}
            return
        win_start = state["window_start"]
        if now - win_start >= RATE_LIMIT_WINDOW:
            rate_state[token] = {"window_start": now, "count": 1}
            return
        if state["count"] >= RATE_LIMIT_MAX:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        state["count"] += 1
        rate_state[token] = state

#auth helper
def constant_time_compare(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

async def require_bearer_token(authorization: str = Header(None), request: Request = None):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    token = authorization.split(None, 1)[1].strip()
    server_token = read_server_token()
    client_ip = request.client.host if request and request.client else "unknown"
    if not constant_time_compare(token, server_token):
        audit_event(mask_token(token), "auth", None, client_ip, "failed", note="invalid_token")
        raise HTTPException(status_code=403, detail="Invalid token")
    await check_rate_limit(token)
    return token

#vault access helpers
def read_vault_file() -> bytes:
    if not os.path.exists(VAULT_PATH):
        raise HTTPException(status_code=500, detail="Vault file not found on server")
    with open(VAULT_PATH, "rb") as f:
        return f.read()

#(READ)
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/entries")
async def list_entries(authorization: str = Header(None), request: Request = None):
    token = await require_bearer_token(authorization, request)
    client_ip = request.client.host if request and request.client else "unknown"
    try:
        blob = read_vault_file()
        data = decrypt_vault_blob(blob, app.state.master_password)
    except Exception as ex:
        audit_event(mask_token(token), "list", None, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to decrypt vault")
    names = sorted(list(data.get("entries", {}).keys()))
    audit_event(mask_token(token), "list", None, client_ip, "ok")
    return {"entries": names}

@app.get("/entry/{name}")
async def get_entry(name: str, authorization: str = Header(None), request: Request = None):
    token = await require_bearer_token(authorization, request)
    client_ip = request.client.host if request and request.client else "unknown"
    try:
        blob = read_vault_file()
        data = decrypt_vault_blob(blob, app.state.master_password)
    except Exception as ex:
        audit_event(mask_token(token), "get", name, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to decrypt vault")
    entry = data.get("entries", {}).get(name)
    if not entry:
        audit_event(mask_token(token), "get", name, client_ip, "not_found")
        raise HTTPException(status_code=404, detail="Entry not found")
    safe_entry = {
        "user": entry.get("user",""),
        "secret": entry.get("secret",""),
        "notes": entry.get("notes",""),
    }
    audit_event(mask_token(token), "get", name, client_ip, "ok")
    return safe_entry

#(CREATE/UPDATE/DELETE)
@app.put("/entry/{name}")
async def put_entry(name: str, request: Request, authorization: str = Header(None)):
    token = await require_bearer_token(authorization, request)
    client_ip = request.client.host if request and request.client else "unknown"
    payload = await request.json()
    user = payload.get("user", "")
    secret = payload.get("secret", "")
    notes = payload.get("notes", "")
    try:
        blob = read_vault_file()
        data = decrypt_vault_blob(blob, app.state.master_password)
    except Exception as ex:
        audit_event(mask_token(token), "put", name, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to decrypt vault")
    is_new = name not in data.get("entries", {})
    entry = {
        "user": user,
        "secret": secret,
        "notes": notes,
        "updated": time.ctime(),
    }
    if is_new:
        entry["created"] = time.ctime()
    data.setdefault("entries", {})[name] = entry
    try:
        new_blob = encrypt_vault_blob(data, app.state.master_password)
        write_vault_blob_atomic(new_blob)
    except Exception as ex:
        audit_event(mask_token(token), "put", name, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to write vault")
    audit_event(mask_token(token), "put", name, client_ip, "ok", note=("created" if is_new else "updated"))
    return {"ok": True, "created": is_new}

@app.delete("/entry/{name}")
async def delete_entry(name: str, authorization: str = Header(None), request: Request = None):
    token = await require_bearer_token(authorization, request)
    client_ip = request.client.host if request and request.client else "unknown"
    try:
        blob = read_vault_file()
        data = decrypt_vault_blob(blob, app.state.master_password)
    except Exception as ex:
        audit_event(mask_token(token), "delete", name, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to decrypt vault")
    if name not in data.get("entries", {}):
        audit_event(mask_token(token), "delete", name, client_ip, "not_found")
        raise HTTPException(status_code=404, detail="Entry not found")
    del data["entries"][name]
    try:
        new_blob = encrypt_vault_blob(data, app.state.master_password)
        write_vault_blob_atomic(new_blob)
    except Exception as ex:
        audit_event(mask_token(token), "delete", name, client_ip, "failed", note=str(ex))
        raise HTTPException(status_code=500, detail="Failed to write vault")
    audit_event(mask_token(token), "delete", name, client_ip, "ok")
    return {"ok": True}

#frontend
@app.get("/", response_class=HTMLResponse)
def frontend():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Skid Vault</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: system-ui, sans-serif; background: #f9fafb; color: #111; max-width: 800px; margin: 2rem auto; padding: 1rem; }
    .card { background: white; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 1rem; margin-top: 1rem; }
    input, textarea, button { padding: 0.6rem; font-size: 0.95rem; border-radius: 6px; border: 1px solid #ddd; width:100%; box-sizing:border-box; }
    button { background:#2563eb; color:#fff; border:none; cursor:pointer; }
    button.ghost { background:transparent; border:1px solid #ccc; color:#333; }
    .row { display:flex; gap:8px; }
    .col { flex:1; }
    .entries { margin-top:12px; display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:8px; }
    .entry { padding:8px; border-radius:6px; background:#f3f4f6; cursor:pointer; }
    pre { background:#f3f4f6; padding:12px; border-radius:6px; overflow:auto; }
    label { font-size:0.85rem; color:#444; display:block; margin-bottom:6px; }
  </style>
</head>
<body>
  <h1>🔒 SKID VAULT</h1>

  <div class="card">
    <label>API Token (paste from server_token.txt):</label>
    <input id="token" type="password" placeholder="Enter API token (saved to localStorage)"/>
    <div style="margin-top:8px;" class="row">
      <button onclick="saveToken()">Save token</button>
      <button class="ghost" onclick="clearToken()">Clear token</button>
      <div id="tokenMask" style="margin-left:auto;color:#666;"></div>
    </div>
  </div>

  <div class="card">
    <div style="display:flex;gap:8px;align-items:center">
      <button onclick="listEntries()">📂 List entries</button>
      <button class="ghost" onclick="healthCheck()">Health</button>
      <div id="status" style="margin-left:auto;color:#666">idle</div>
    </div>

    <div class="entries" id="entries"></div>

    <div id="empty" style="margin-top:12px;color:#666">No entries yet – click "List entries".</div>
  </div>

  <div class="card">
    <h3>Entry (create / update)</h3>
    <label>Entry name</label>
    <input id="ename" placeholder="unique name (e.g. github)"/>
    <label>User</label>
    <input id="euser" placeholder="username / email"/>
    <label>Secret</label>
    <input id="esecret" placeholder="password or token"/>
    <label>Notes</label>
    <textarea id="enotes" rows="3"></textarea>
    <div style="margin-top:8px" class="row">
      <button onclick="saveEntry()">Save Entry</button>
      <button class="ghost" onclick="deleteEntry()">Delete Entry</button>
      <button class="ghost" onclick="clearForm()">Clear</button>
    </div>
    <div style="margin-top:12px">
      <h4>Output</h4>
      <pre id="output">Select or create an entry. Secrets are shown on-screen – handle carefully.</pre>
    </div>
  </div>

<script>
function mask(s){ if(!s) return ""; return s.slice(0,4) + "..." + s.slice(-4); }
function saveToken(){ const t=document.getElementById("token").value.trim(); if(!t){ alert("Enter token"); return;} localStorage.setItem("skid_token", t); document.getElementById("tokenMask").innerText = mask(t); alert("Token saved locally."); }
function clearToken(){ localStorage.removeItem("skid_token"); document.getElementById("tokenMask").innerText = ""; alert("Token cleared."); }
function getToken(){ return localStorage.getItem("skid_token") || ""; }
function setStatus(s){ document.getElementById("status").innerText = s; }

async function healthCheck(){ setStatus("checking..."); try{ const res=await fetch("/health"); if(res.ok) setStatus("ok"); else setStatus("bad"); }catch(e){ setStatus("unreachable"); } setTimeout(()=>setStatus("idle"),1200); }

async function listEntries(){
  const t = getToken(); if(!t){ alert("Save token first"); return; }
  setStatus("loading...");
  document.getElementById("entries").innerHTML = "";
  try{
    const res = await fetch("/entries", { headers: { "Authorization": "Bearer " + t }});
    if(!res.ok){ const txt = await res.text(); document.getElementById("output").innerText = "Error: "+res.status+" - "+txt; setStatus("error"); return; }
    const data = await res.json();
    const list = data.entries || [];
    const entriesDiv = document.getElementById("entries");
    if(list.length === 0){ document.getElementById("empty").style.display = "block"; entriesDiv.innerHTML = ""; }
    else {
      document.getElementById("empty").style.display = "none";
      entriesDiv.innerHTML = "";
      list.forEach(name => {
        const d = document.createElement("div");
        d.className = "entry";
        d.innerText = name;
        d.onclick = ()=> loadEntry(name);
        entriesDiv.appendChild(d);
      });
    }
    setStatus("loaded");
  }catch(e){
    document.getElementById("output").innerText = "Network error: "+e;
    setStatus("unreachable");
  } finally { setTimeout(()=>setStatus("idle"),900); }
}

async function loadEntry(name){
  const t = getToken(); if(!t){ alert("Save token first"); return; }
  setStatus("loading entry...");
  try{
    const res = await fetch("/entry/" + encodeURIComponent(name), { headers: { "Authorization": "Bearer " + t }});
    if(!res.ok){ const txt = await res.text(); document.getElementById("output").innerText = "Error: "+res.status+" - "+txt; setStatus("error"); return; }
    const data = await res.json();
    document.getElementById("ename").value = name;
    document.getElementById("euser").value = data.user || "";
    document.getElementById("esecret").value = data.secret || "";
    document.getElementById("enotes").value = data.notes || "";
    document.getElementById("output").innerText = JSON.stringify(data, null, 2);
    setStatus("ok");
  }catch(e){
    document.getElementById("output").innerText = "Network error: "+e;
    setStatus("unreachable");
  } finally { setTimeout(()=>setStatus("idle"),900); }
}

async function saveEntry(){
  const t = getToken(); if(!t){ alert("Save token first"); return; }
  const name = document.getElementById("ename").value.trim();
  if(!name){ alert("Entry name required"); return; }
  const payload = {
    user: document.getElementById("euser").value,
    secret: document.getElementById("esecret").value,
    notes: document.getElementById("enotes").value
  };
  setStatus("saving...");
  try{
    const res = await fetch("/entry/" + encodeURIComponent(name), {
      method: "PUT",
      headers: { "Authorization": "Bearer " + t, "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if(!res.ok){ const txt = await res.text(); document.getElementById("output").innerText = "Error: "+res.status+" - "+txt; setStatus("error"); return; }
    const data = await res.json();
    document.getElementById("output").innerText = "Saved. " + JSON.stringify(data);
    await listEntries();
    setStatus("saved");
  }catch(e){
    document.getElementById("output").innerText = "Network error: "+e;
    setStatus("unreachable");
  } finally { setTimeout(()=>setStatus("idle"),900); }
}

async function deleteEntry(){
  const t = getToken(); if(!t){ alert("Save token first"); return; }
  const name = document.getElementById("ename").value.trim();
  if(!name){ alert("Entry name required"); return; }
  if(!confirm("Delete '"+name+"'? This cannot be undone.")) return;
  setStatus("deleting...");
  try{
    const res = await fetch("/entry/" + encodeURIComponent(name), {
      method: "DELETE",
      headers: { "Authorization": "Bearer " + t }
    });
    if(!res.ok){ const txt = await res.text(); document.getElementById("output").innerText = "Error: "+res.status+" - "+txt; setStatus("error"); return; }
    document.getElementById("output").innerText = "Deleted.";
    await listEntries();
    clearForm();
    setStatus("deleted");
  }catch(e){
    document.getElementById("output").innerText = "Network error: "+e;
    setStatus("unreachable");
  } finally { setTimeout(()=>setStatus("idle"),900); }
}

function clearForm(){ document.getElementById("ename").value = ""; document.getElementById("euser").value = ""; document.getElementById("esecret").value = ""; document.getElementById("enotes").value = ""; document.getElementById("output").innerText = "Select or create an entry."; }

document.addEventListener("DOMContentLoaded", ()=>{ const t = getToken(); if(t) document.getElementById("tokenMask").innerText = mask(t); });
</script>
</body>
</html>
"""

#server setup
def run_server(host: str, port: int, master_password: str):
    app.state.master_password = master_password
    import uvicorn
    print(f"[INFO] Starting Skid server on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1", help="Host to bind (use 0.0.0.0 for all interfaces)")
    p.add_argument("--port", default=8080, type=int)
    p.add_argument("--master-password", default=None, help="Master password (prefer prompt)")
    return p.parse_args()

if __name__ == "__main__":

    args = parse_args()
    create_server_token_if_missing()
    mp = args.master_password
    if not mp:
        mp = getpass("Master password to decrypt vault (will not be stored): ")
    try:
        blob = read_vault_file()
        _ = decrypt_vault_blob(blob, mp)
    except Exception as ex:
        print("[ERROR] Failed to decrypt vault with provided master password:", ex)
        sys.exit(1)
    run_server(args.host, args.port, mp)