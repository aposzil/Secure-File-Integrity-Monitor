import hashlib, os, json, base64, sys, requests, getpass, shutil
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Configuration & Stealth Setup ---
PREFIX = "." if os.name != 'nt' else ""
DB_FILE = f"{PREFIX}integrity_vault.dat"
SALT_FILE = f"{PREFIX}user.salt"
META_FILE = f"{PREFIX}app.meta"
BACKUP_FILE = f"{PREFIX}integrity_vault.bak"

def set_hidden(filepath, hide=True):
    """Handles Windows Hidden attribute to prevent PermissionError."""
    if os.name == 'nt' and os.path.exists(filepath):
        mode = "+h" if hide else "-h"
        os.system(f'attrib {mode} "{filepath}"')

def hide_all():
    for f in [DB_FILE, SALT_FILE, META_FILE, BACKUP_FILE]:
        if os.path.exists(f): set_hidden(f, True)

def show_all():
    for f in [DB_FILE, SALT_FILE, META_FILE, BACKUP_FILE]:
        if os.path.exists(f): set_hidden(f, False)

def get_sha256(filepath):
    if not os.path.exists(filepath): return None
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): sha.update(chunk)
        return sha.hexdigest().upper()
    except: return None

# --- Integrity & Recovery ---
def verify_self_and_recovery():
    if not os.path.exists(META_FILE): 
        return True # Επιτρέπουμε τη συνέχεια αν είναι η πρώτη φορά
    
    show_all()
    current_db_hash = get_sha256(DB_FILE)
    success = True
    
    try:
        with open(META_FILE, "r") as f: 
            meta = json.load(f)
        
        if meta.get("db_hash") != current_db_hash:
            print("\n" + "!"*45 + "\n⚠️ CRITICAL: Database integrity breach detected!")
            if os.path.exists(BACKUP_FILE):
                if input("🔄 Backup found. Restore now? (y/n): ").lower() == 'y':
                    shutil.copy(BACKUP_FILE, DB_FILE)
                    os.remove(BACKUP_FILE)
                    print("✅ Restored. Please restart the app.")
                    sys.exit()
                else:
                    success = False
            else:
                print("❌ NO BACKUP! Database is corrupted or tampered.")
                success = False
    except:
        success = False
    finally:
        hide_all()
    
    if not success:
        input("Press Enter to exit...")
        sys.exit() # Τερματισμός αν κάτι πήγε στραβά
    return True

# --- Cryptography Logic ---
def derive_key(password: str):
    show_all()
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f: f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f: salt = f.read()
    hide_all()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def authenticate():
    for i in range(3):
        pwd = getpass.getpass(f"🔑 Password ({i+1}/3): ")
        key = derive_key(pwd)
        cipher = Fernet(key)
        if os.path.exists(DB_FILE):
            try:
                show_all()
                with open(DB_FILE, "rb") as f: data = f.read()
                cipher.decrypt(data)
                hide_all(); return cipher
            except: 
                hide_all(); print("❌ Incorrect password.")
        else: return cipher
    sys.exit("🔒 Lockdown initiated.")

# --- Database Operations ---
def load_db(cipher):
    if not os.path.exists(DB_FILE): return {}
    show_all()
    data = json.loads(cipher.decrypt(open(DB_FILE, "rb").read()).decode())
    hide_all(); return data

def save_db(db, cipher):
    show_all()
    with open(DB_FILE, "wb") as f: f.write(cipher.encrypt(json.dumps(db).encode()))
    hide_all()

# --- Main Logic ---
def run_scan(folder, cipher):
    db = load_db(cipher)
    found = False
    for r, _, fs in os.walk(folder):
        for n in fs:
            if n in [DB_FILE, SALT_FILE, META_FILE, BACKUP_FILE, "hashchecka.py"]: continue
            found = True
            p = os.path.abspath(os.path.join(r, n))
            h = get_sha256(p)
            if not h: continue
            if p in db:
                if db[p]["hash"] == h:
                    db[p]["status"] = "OK"; print(f"🟢 OK: {n}")
                else:
                    print(f"🔴 ALERT: {n} changed!")
                    ans = input("   Update(y)/Alert(n)/Skip(Enter): ").lower()
                    if ans == 'y': db[p] = {"hash": h, "date": datetime.now().strftime("%Y-%m-%d %H:%M"), "status": "OK"}
                    elif ans == 'n': db[p]["status"] = "ATTENTION"
                    else: db[p]["status"] = "CHANGED"
            else:
                db[p] = {"hash": h, "date": datetime.now().strftime("%Y-%m-%d %H:%M"), "status": "OK"}
                print(f"🆕 NEW: {n}")
    if not found: print("❓ Folder empty or contains no files to scan.")
    save_db(db, cipher)

def show_view(cipher):
    db = load_db(cipher)
    if not db:
        print("🔍 Η βάση είναι άδεια.")
        return

    # Η διόρθωση: x[0] είναι το path, x[1] είναι το dictionary με τις πληροφορίες
    res = sorted(db.items(), key=lambda x: 1 if x[1].get("status")=="ATTENTION" 
                                          else 2 if x[1].get("status")=="CHANGED" 
                                          else 3)
    
    print("\n" + "="*70)
    for path, i in res:
        s = i.get("status", "OK")
        icon = "⚠️" if s=="ATTENTION" else "🔴" if s=="CHANGED" else "🟢"
        print(f"{icon} {s:<10} | {os.path.basename(path)} | Last verified: {i.get('date', 'N/A')}")


if __name__ == "__main__":
    verify_self_and_recovery()
    c = authenticate()
    while True:
        warn = " [⚠️ NO BACKUP!]" if not os.path.exists(BACKUP_FILE) else ""
        print(f"\n--- INTEGRITY TOOL v22{warn} ---")
        print("1. Scan Folder\n2. View DB\n3. Create Backup\n4. Cleanup DB\n5. Exit & Validate")
        cmd = input("Choice: ")
        if cmd == "1":
            p = input("Path: ").strip('"').strip("'")
            if os.path.isdir(p): run_scan(p, c)
            else: print("❌ Invalid folder path.")
        elif cmd == "2": show_view(c)
        elif cmd == "3":
            show_all(); shutil.copy(DB_FILE, BACKUP_FILE); hide_all()
            print("💾 Backup created.")
        elif cmd == "4":
            db = load_db(c); db = {p: i for p, i in db.items() if os.path.exists(p)}
            save_db(db, c); print("✅ Cleanup complete.")
        elif cmd == "5":
            show_all()
            with open(META_FILE, "w") as f:
                json.dump({"db_hash": get_sha256(DB_FILE), "salt_hash": get_sha256(SALT_FILE)}, f)
            hide_all(); print("🔒 State validated. Goodbye!"); break
