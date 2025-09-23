import argparse, json, os, sys, base64, time
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_PATH = os.path.join("lock", "vault.bin")  # binary file
KDF_ITER = 300_000
SALT_SIZE = 16
NONCE_SIZE = 12

# --- helpers ---
def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITER,
    )
    return kdf.derive(password)

def encrypt_vault(data: dict, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct  # blob = salt | nonce | ciphertext

def decrypt_vault(blob: bytes, password: str) -> dict:
    if len(blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("vault file corrupted or too small")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ct = blob[SALT_SIZE+NONCE_SIZE:]
    key = derive_key(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))

def ensure_vault_dir():
    if not os.path.isdir("lock"):
        raise SystemExit("Folder 'lock' not found in current working directory. Create it and re-run.")

def write_vault_blob(blob: bytes):
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, VAULT_PATH)
    try:
        os.chmod(VAULT_PATH, 0o600)
    except Exception:
        pass

def load_vault_interactive():
    if not os.path.exists(VAULT_PATH):
        raise SystemExit("Vault not found. Run 'init' first.")
    pw = getpass("Enter master password: ")
    with open(VAULT_PATH, "rb") as f:
        blob = f.read()
    try:
        data = decrypt_vault(blob, pw)
    except Exception:
        raise SystemExit("Failed to decrypt vault. Wrong password or corrupted file.")
    return data, pw

# --- commands ---
def cmd_init(args):
    ensure_vault_dir()
    if os.path.exists(VAULT_PATH):
        print("Vault already exists. If you want to reinitialize, delete lock/vault.bin first.")
        return
    pw = getpass("Choose a strong master password: ")
    pw2 = getpass("Confirm master password: ")
    if pw != pw2 or len(pw) < 8:
        print("Passwords don't match or too short (min 8). Aborting.")
        return
    empty = {"entries": {}}
    blob = encrypt_vault(empty, pw)
    write_vault_blob(blob)
    print("Initialized vault at lock/vault.bin. Keep your master password safe.")

def cmd_add(args):
    ensure_vault_dir()
    data, pw = load_vault_interactive()
    name = args.name
    if name in data["entries"]:
        confirm = input(f"Entry '{name}' exists – overwrite? (y/N): ").lower()
        if confirm != "y":
            print("Aborted.")
            return
    entry = {
        "user": args.user or "",
        "secret": args.secret or "",
        "notes": args.notes or "",
        "created": time.ctime(),
    }
    data["entries"][name] = entry
    blob = encrypt_vault(data, pw)
    write_vault_blob(blob)
    print(f"Saved entry '{name}'.")

def cmd_get(args):
    data, _ = load_vault_interactive()
    name = args.name
    e = data["entries"].get(name)
    if not e:
        print("No such entry.")
        return
    print(f"Name: {name}")
    print(f"User: {e.get('user','')}")
    print(f"Secret: {e.get('secret','')}")
    notes = e.get("notes","")
    if notes:
        print(f"Notes: {notes}")

def cmd_list(args):
    data, _ = load_vault_interactive()
    names = sorted(data["entries"].keys())
    for n in names:
        print(n)
    print(f"Total: {len(names)}")

def cmd_delete(args):
    data, pw = load_vault_interactive()
    name = args.name
    if name not in data["entries"]:
        print("No such entry.")
        return
    confirm = input(f"Delete '{name}'? This cannot be undone. (y/N): ").lower()
    if confirm != "y":
        print("Aborted.")
        return
    del data["entries"][name]
    blob = encrypt_vault(data, pw)
    write_vault_blob(blob)
    print("Deleted.")

def cmd_change_master(args):
    data, old_pw = load_vault_interactive()
    new_pw = getpass("New master password: ")
    new_pw2 = getpass("Confirm new master password: ")
    if new_pw != new_pw2 or len(new_pw) < 8:
        print("Passwords don't match or too short. Aborting.")
        return
    blob = encrypt_vault(data, new_pw)
    write_vault_blob(blob)
    print("Master password changed.")

def cmd_backup(args):
    if not os.path.exists(VAULT_PATH):
        print("No vault to backup.")
        return
    out = args.out
    if not out:
        print("Provide output path with --out")
        return
    with open(VAULT_PATH, "rb") as fr, open(out, "wb") as fw:
        fw.write(fr.read())
    print(f"Backed up encrypted vault to {out}")

def cmd_restore(args):
    ensure_vault_dir()
    src = args.src
    if not os.path.exists(src):
        print("Backup file not found.")
        return
    if os.path.exists(VAULT_PATH):
        confirm = input("Vault already exists. Overwrite with backup? (y/N): ").lower()
        if confirm != "y":
            print("Aborted.")
            return
    with open(src, "rb") as fr, open(VAULT_PATH, "wb") as fw:
        fw.write(fr.read())
    print(f"Restored vault from {src}")

# --- main ---
def main():
    p = argparse.ArgumentParser(prog="skid_vault")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("init")

    a_add = sub.add_parser("add")
    a_add.add_argument("--name", required=True)
    a_add.add_argument("--user", default="")
    a_add.add_argument("--secret", default="")
    a_add.add_argument("--notes", default="")

    a_get = sub.add_parser("get")
    a_get.add_argument("--name", required=True)

    sub.add_parser("list")

    a_del = sub.add_parser("delete")
    a_del.add_argument("--name", required=True)

    sub.add_parser("change-master")

    a_backup = sub.add_parser("backup")
    a_backup.add_argument("--out", required=True)

    a_restore = sub.add_parser("restore")
    a_restore.add_argument("--src", required=True)

    args = p.parse_args()
    cmd = args.cmd
    try:
        if cmd == "init":
            cmd_init(args)
        elif cmd == "add":
            cmd_add(args)
        elif cmd == "get":
            cmd_get(args)
        elif cmd == "list":
            cmd_list(args)
        elif cmd == "delete":
            cmd_delete(args)
        elif cmd == "change-master":
            cmd_change_master(args)
        elif cmd == "backup":
            cmd_backup(args)
        elif cmd == "restore":
            cmd_restore(args)
        else:
            p.print_help()
    except SystemExit:
        raise
    except Exception as ex:
        print("Error:", ex)

if __name__ == "__main__":
    main()