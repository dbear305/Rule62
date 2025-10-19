#!/usr/bin/env python3
# Rule 62 — “Don’t take yourself so damn serious.”
# Simple, unbranded, open-source companion for 12-Step style work.
# 100% free. No money to this project. If people want to help, they donate
# DIRECTLY to vetted mental-health charities (fiat or crypto) listed in a SIGNED file.
#
# One file includes:
#  - The app (journal, inventory, step progress, sponsor).
#  - Signed donations display (fiat/crypto) with tamper detection.
#  - Local tamper log (tamper_log.json). No telemetry, no tracking.
#  - Maintainer utilities:
#       py -3.11 rule62.py --init-keys
#       py -3.11 rule62.py --sign-donations
#
# MIT License © 2025 Daniel Burial

import os, sys, json, datetime, textwrap, hashlib, urllib.request

# ---------- dependency for signatures ----------
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    sys.exit("Missing dependency 'cryptography'. Install with: py -3.11 -m pip install cryptography")

# ===================== App constants =====================
APP_NAME  = "Rule 62"
WRAP      = 90
DATA_FILE = "rule62_data.json"
TAMPER_LOG= "tamper_log.json"

# Donations manifest (preferred: JSON + detached sig)
DONATIONS_JSON = "donations.json"
DONATIONS_SIG  = "donations.json.sig"

# Fallback: plain text list + sig (optional)
CHARITY_TXT = "charity_list.txt"
CHARITY_SIG = "charity_list.txt.sig"

# Optional signed remote manifest (advanced, optional). Leave None to disable.
REMOTE_MANIFEST_URL = None
# Example: REMOTE_MANIFEST_URL = "https://example.org/rule62/manifest.json"

# PUBLIC KEY: you may embed it here OR simply put a file named rule62_public.pem alongside this script.
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
REPLACE_WITH_YOUR_RSA_PUBLIC_KEY_PEM
-----END PUBLIC KEY-----
"""

# ===================== Step text & copy =====================
TITLES = {
    1:"Honesty & Manageability", 2:"Hope in a Power Beyond Self", 3:"Decision to Align Will",
    4:"Searching & Fearless Inventory", 5:"Admit Wrongs to Self, God, Another",
    6:"Ready for Character Change", 7:"Humbly Ask to Remove Shortcomings",
    8:"List Those Harmed; Become Willing", 9:"Make Direct Amends (When Right)",
    10:"Continue Inventory; Admit Promptly", 11:"Prayer & Meditation; Conscious Contact",
    12:"Carry the Message; Practice Principles"
}

QUOTE = (
    "Don’t take yourself so damn serious.\n"
    "Wear your recovery like a loose garment."
)

DISCLAIMER_BASE = "This helper is not a sponsor, therapist, or medical service. Step 5 needs another human."
DISCLAIMER_LIFE = "Sobriety is life-or-death for many of us. If you’re in crisis in the U.S., call or text 988."
DISCLAIMER_HABIT= "Change is hard, but possible. Keep it simple, keep it honest, keep showing up."

DEFAULT_DATA = {
    "vice": "alcohol",
    "mode": "substance",          # 'substance' (life-or-death line) or 'habit'
    "created": None,
    "last_opened": None,
    "current_step": 1,
    "completed_steps": [],
    "journal": [],
    "inventory": [],
    "sponsor": {"name": "", "phone": ""},
    "custom_step_text_file": "steps.txt"
}

SUBSTANCE_KEYWORDS = {
    "alcohol","booze","drinking","liquor","beer","wine",
    "drug","drugs","dope","opioid","opiates","heroin","fentanyl","pill","pills",
    "cocaine","crack","meth","methamphetamine","benzo","benzodiazepine",
    "weed","marijuana","cannabis","xanax","adderall","kratom","ketamine"
}

# ===================== Small utils =====================
def now_iso(): return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
def w(s): return textwrap.fill(s, WRAP)
def println(s=""): print(w(s))
def ask(msg): return input(msg + " ").strip()

def load_json(path):
    try:
        with open(path,"r",encoding="utf-8") as f: return json.load(f)
    except Exception: return None

def save_json(path,data):
    with open(path,"w",encoding="utf-8") as f: json.dump(data,f,indent=2,ensure_ascii=False)

def sha256_hex(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def fetch(url, timeout=6):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None

def file_bytes(path):
    if not os.path.exists(path): return None
    with open(path,"rb") as f: return f.read()

# ===================== Key / signature helpers =====================
def load_public_key_pem():
    """Return a PEM public key. If placeholder is present, try rule62_public.pem file."""
    if b"REPLACE_WITH_YOUR_RSA_PUBLIC_KEY_PEM" not in PUBLIC_KEY_PEM:
        return PUBLIC_KEY_PEM
    # try external PEM file
    ext = "rule62_public.pem"
    if os.path.exists(ext):
        with open(ext,"rb") as f: return f.read()
    # No key found
    return None

def verify_sig(pub_pem: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem, backend=default_backend())
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def log_tamper(event, details):
    entry={"ts":now_iso(),"event":event,"details":details}
    buf=load_json(TAMPER_LOG) or []
    buf.append(entry); save_json(TAMPER_LOG,buf)

# ===================== Donations (fiat + crypto) =====================
def load_signed_donations(pub_pem):
    """Preferred structured donations.json + .sig (fiat + crypto)."""
    doc=file_bytes(DONATIONS_JSON); sig=file_bytes(DONATIONS_SIG)
    if not doc or not sig: return None
    if not verify_sig(pub_pem, doc, sig):
        log_tamper("donations_json_sig_invalid", {"sha256": hashlib.sha256(doc).hexdigest()})
        return None
    try:
        data=json.loads(doc.decode("utf-8"))
        if not isinstance(data.get("charities",[]), list): return None
        return data
    except Exception:
        return None

def load_signed_charities_text(pub_pem):
    """Fallback plain text charity list (one per line) + .sig."""
    txt=file_bytes(CHARITY_TXT); sig=file_bytes(CHARITY_SIG)
    if not txt or not sig: return None
    if not verify_sig(pub_pem, txt, sig):
        log_tamper("charity_txt_sig_invalid", {"sha256": hashlib.sha256(txt).hexdigest()})
        return None
    try:
        return txt.decode("utf-8").strip()
    except Exception:
        return None

def render_donations_block(pub_pem):
    """Return lines to print; None if nothing verified."""
    data = load_signed_donations(pub_pem)
    if data:
        lines=[]
        note=data.get("note","Donate DIRECTLY to these vetted mental-health charities (never to this project):")
        lines.append(note); lines.append("")
        for ch in data.get("charities",[]):
            name=ch.get("name","(charity)")
            lines.append(f"• {name}")
            fiat=ch.get("fiat",{}); url=fiat.get("url")
            if url: lines.append(f"    fiat: {url}")
            crypto=ch.get("crypto",{})
            for coin in sorted(crypto.keys()):
                addr=crypto[coin]
                if coin.upper()=="BTC":
                    uri=f"bitcoin:{addr}"
                elif coin.upper()=="ETH":
                    uri=f"ethereum:{addr}"
                else:
                    uri=addr
                lines.append(f"    {coin}: {uri}")
            lines.append("")
        return lines
    # fallback
    txt=load_signed_charities_text(pub_pem)
    if txt:
        lines=["Donate DIRECTLY to these vetted mental-health charities (never to this project):",""]
        for line in txt.splitlines():
            if line.strip(): lines.append("• " + line.strip())
        lines.append("")
        return lines
    log_tamper("donations_missing_or_unverified", {})
    return None

# ===================== Optional remote manifest =====================
def verify_remote_manifest(pub_pem):
    if not REMOTE_MANIFEST_URL: return True
    man = fetch(REMOTE_MANIFEST_URL)
    sig = fetch(REMOTE_MANIFEST_URL + ".sig")
    if not man or not sig:
        log_tamper("manifest_fetch_failed", {"url": REMOTE_MANIFEST_URL}); return False
    if not verify_sig(pub_pem, man, sig):
        log_tamper("manifest_sig_invalid", {"url": REMOTE_MANIFEST_URL}); return False
    try:
        manifest=json.loads(man.decode("utf-8")); files=manifest.get("files",{})
    except Exception:
        log_tamper("manifest_parse_error", {"url": REMOTE_MANIFEST_URL}); return False
    mismatches={}; ok=True
    for fname, expected in files.items():
        if not os.path.exists(fname):
            mismatches[fname]="missing"; ok=False; continue
        local=sha256_hex(fname)
        if local.lower()!=expected.lower():
            mismatches[fname]={"expected":expected,"actual":local}; ok=False
    if not ok: log_tamper("manifest_mismatch", {"mismatches":mismatches})
    return ok

# ===================== App core =====================
def load_data():
    d=load_json(DATA_FILE)
    if not d:
        d=DEFAULT_DATA.copy(); d["created"]=now_iso(); save_json(DATA_FILE,d)
    # fill missing keys
    for k,v in DEFAULT_DATA.items():
        if k not in d: d[k]=v
    if not d.get("created"): d["created"]=now_iso()
    save_json(DATA_FILE,d)
    return d

def detect_mode_from_focus(focus:str)->str:
    t=focus.lower()
    for kw in SUBSTANCE_KEYWORDS:
        if kw in t: return "substance"
    for hint in ("nicotine","vape","smoke","sugar","food","eating","porn","sex","gambl",
                 "anger","shopping","spending","screen","scroll","gaming","work","code",
                 "coffee","caffeine"):
        if hint in t: return "habit"
    return "habit"

def banner(d, pub_pem):
    os.system("")  # ANSI reset (Windows)
    print("\n"+APP_NAME); print("─"*len(APP_NAME))
    println(QUOTE); print()

    # Donations block (only if verified)
    if pub_pem:
        donation_lines = render_donations_block(pub_pem)
        if donation_lines:
            for line in donation_lines: println(line)
        else:
            println("(Donations: no verified list found. Nothing to donate here.)")
    else:
        println("(Donations: public key not found; cannot verify list.)")
    print()

    println(DISCLAIMER_BASE)
    println(DISCLAIMER_LIFE if d.get("mode")=="substance" else DISCLAIMER_HABIT)
    print()
    println(f"Focus: {d['vice']}  |  Mode: {d['mode']}")
    println(f"Step {d['current_step']}: {TITLES.get(d['current_step'],'')}")
    if d.get("created"): println(f"Created: {d['created']}")
    sp=d.get("sponsor",{})
    if sp.get("name"): println(f"Sponsor: {sp.get('name')}  {sp.get('phone')}")
    print()

def show_step(d):
    steps=None
    try:
        path=d.get("custom_step_text_file","steps.txt")
        if os.path.exists(path):
            with open(path,"r",encoding="utf-8") as f:
                lines=[ln.strip() for ln in f if ln.strip()]
            if len(lines)>=12: steps={i+1:lines[i] for i in range(12)}
    except Exception: steps=None
    s=d.get("current_step",1)
    println("\nToday’s Step")
    println(TITLES.get(s) if not steps else steps.get(s))
    input("\nPress Enter to return… ")

def add_journal(d):
    println("\nJournal entry (end with a blank line):")
    lines=[]
    while True:
        ln=input()
        if not ln.strip(): break
        lines.append(ln)
    if not lines: println("Empty — canceled."); return
    d["journal"].append({"ts":now_iso(),"text":"\n".join(lines)})
    save_json(DATA_FILE,d); println("Saved.")

def add_inventory(d):
    dom=ask("Domain (resentment, fear, selfishness, other):") or "other"
    txt=ask("What happened (1–3 sentences)?")
    fix=ask("Correction / repair action?")
    d["inventory"].append({"ts":now_iso(),"domain":dom,"text":txt,"correction":fix})
    save_json(DATA_FILE,d); println("Saved.")

def summary(d):
    println("\nSummary")
    println(f"Focus: {d['vice']}  |  Step {d['current_step']}")
    if d["inventory"]:
        println("Recent inventory:")
        for it in d["inventory"][-3:]:
            println(f" • [{it['ts']}] {it['domain']}: {it['text']} → {it['correction']}")
    if d["journal"]:
        println("Recent journal:")
        for j in d["journal"][-3:]:
            println(f" • [{j['ts']}] {j['text'].splitlines()[0][:70]}")
    input("\nPress Enter to return… ")

def mark_step(d):
    s=d.get("current_step",1)
    if s not in d.get("completed_steps",[]): d["completed_steps"].append(s)
    d["current_step"]=10 if s==12 else s+1
    save_json(DATA_FILE,d); println(f"Marked step {s} complete.")

def set_sponsor(d):
    name=ask("Sponsor name (blank to keep):")
    phone=ask("Sponsor phone (blank to keep):")
    if name: d["sponsor"]["name"]=name
    if phone: d["sponsor"]["phone"]=phone
    save_json(DATA_FILE,d); println("Saved.")

def set_focus(d):
    f=ask("Focus (vice/issue):")
    if f:
        d["vice"]=f
        suggested=detect_mode_from_focus(f)
        if ask(f"Switch mode to '{suggested}'? (y/N):").lower().startswith("y"):
            d["mode"]=suggested
        save_json(DATA_FILE,d); println("Saved.")

def set_mode(d):
    m=ask("Mode — 'substance' (life-or-death) or 'habit':").lower()
    if m in ("substance","habit"):
        d["mode"]=m; save_json(DATA_FILE,d); println("Saved.")
    else:
        println("No change.")

def about_traditions():
    println("\nAbout & Traditions")
    println("• This project is free and self-supporting (Seventh Tradition spirit).")
    println("• No money is accepted by this project. If you wish to help, donate DIRECTLY to vetted mental-health charities.")
    println("• Privacy: local JSON only. No analytics, no cloud, no tracking.")
    println("• Integrity: donation list is signed; tampering is logged locally.")
    println("• Tamper log: " + os.path.abspath(TAMPER_LOG))
    input("\nPress Enter to return… ")

def app_menu():
    pub_pem = load_public_key_pem()
    if REMOTE_MANIFEST_URL and pub_pem and not verify_remote_manifest(pub_pem):
        println("WARNING: Unable to verify remote release manifest. See tamper_log.json.\n")

    d=load_data()
    if not d.get("last_opened"):
        d["last_opened"]=now_iso(); save_json(DATA_FILE,d)

    while True:
        banner(d, pub_pem)
        println("[1] Today’s Step   [2] Journal   [3] Inventory")
        println("[4] Summary        [5] Mark Step Complete")
        println("[6] Set Sponsor    [7] Set Mode   [8] About/Traditions   [9] Set Focus   [Q] Quit\n")
        c=ask("Choice:")
        if   c=="1": show_step(d)
        elif c=="2": add_journal(d)
        elif c=="3": add_inventory(d)
        elif c=="4": summary(d)
        elif c=="5": mark_step(d)
        elif c=="6": set_sponsor(d)
        elif c=="7": set_mode(d)
        elif c=="8": about_traditions()
        elif c=="9": set_focus(d)
        elif c.lower()=="q":
            println("Good work today. Keep it simple — one day at a time."); break
        else:
            println("Invalid choice.")
        d["last_opened"]=now_iso(); save_json(DATA_FILE,d)

# ===================== Maintainer utilities =====================
def util_init_keys():
    """Generate RSA-4096 keypair in current folder: rule62_private.pem (secret), rule62_public.pem (safe)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open("rule62_private.pem","wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # for simplicity; consider a passphrase
        ))
    pub = priv.public_key()
    with open("rule62_public.pem","wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("\nGenerated:\n  rule62_private.pem  (KEEP SECRET — do NOT commit)\n  rule62_public.pem   (safe — embed or place next to this script)\n")
    print("Next steps:")
    print("1) Open rule62_public.pem and paste its full contents into PUBLIC_KEY_PEM in this file")
    print("   OR simply keep rule62_public.pem next to rule62.py so it loads automatically.")
    print("2) Create donations.json, then sign it with: py -3.11 rule62.py --sign-donations\n")

def util_sign_donations():
    """Sign donations.json with rule62_private.pem -> donations.json.sig"""
    if not os.path.exists("rule62_private.pem"):
        sys.exit("Missing rule62_private.pem. Run: py -3.11 rule62.py --init-keys")
    if not os.path.exists(DONATIONS_JSON):
        sys.exit(f"Missing {DONATIONS_JSON}. Create it first.")
    with open("rule62_private.pem","rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    data = file_bytes(DONATIONS_JSON)
    sig  = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    with open(DONATIONS_SIG,"wb") as f: f.write(sig)
    print(f"Created {DONATIONS_SIG}. Keep rule62_private.pem OFFLINE and OUT of GitHub.")

# ===================== Entry =====================
if __name__=="__main__":
    # Maintainer flags
    if len(sys.argv) > 1:
        if sys.argv[1] == "--init-keys":
            util_init_keys(); sys.exit(0)
        if sys.argv[1] == "--sign-donations":
            util_sign_donations(); sys.exit(0)
    # Normal app
    try:
        app_menu()
    except KeyboardInterrupt:
        print("\nExit. Keep it light.\n")
