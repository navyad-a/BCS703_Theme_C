#!/usr/bin/env python3
"""
BCS703 Experiential Learning - Theme C: Password Security
Compare password strength and demonstrate secure password hashing / verification.

Safe-use note: every password below is a DUMMY test value. All hashing and
"cracking" is done on a LOCAL demo database that this script creates itself.
No real account, network or third-party system is touched.

Usage:  python3 pw_lab.py <env|strength|weak|secure|openssl|tests|bench|all>
"""
import sys, os, time, math, json, hmac, base64, hashlib, secrets, platform, subprocess, unicodedata

RESULTS = "results.json"

def save(section, data):
    d = json.load(open(RESULTS)) if os.path.exists(RESULTS) else {}
    d[section] = data
    json.dump(d, open(RESULTS, "w"), indent=2)

def load():
    return json.load(open(RESULTS)) if os.path.exists(RESULTS) else {}

def b64(b): return base64.b64encode(b).decode()
def unb64(s): return base64.b64decode(s.encode())

# ----------------------------------------------------------------------------
# 1. Password strength analysis
# ----------------------------------------------------------------------------
COMMON = ["123456","123456789","12345678","1234567","12345","password","password1","passw0rd","p@ssw0rd",
          "p@ssw0rd!","qwerty","qwerty123","qwertyuiop","111111","abc123","iloveyou","admin","admin123",
          "welcome","welcome1","letmein","monkey","dragon","football","master","login","princess","sunshine",
          "trustno1","changeme","test123","1q2w3e4r","zaq12wsx","abcd1234","summer2024","summer2023","winter2024","india123"]
BASE_WORDS = ["password","summer","winter","welcome","admin","letmein","dragon","monkey","troubadour","troubador",
              "football","india","qwerty","iloveyou","master","login","sunshine","princess"]
LEET = str.maketrans({"@":"a","4":"a","0":"o","3":"e","1":"i","!":"i","$":"s","5":"s","7":"t","&":""})

def charset_size(pw):
    n = 0
    if any(c.islower() for c in pw): n += 26
    if any(c.isupper() for c in pw): n += 26
    if any(c.isdigit() for c in pw): n += 10
    if any(not c.isalnum() for c in pw): n += 33
    return n

def analyse(pw, kind_hint=None):
    """Return (naive_bits, effective_bits, note). Effective bits are an ESTIMATE."""
    naive = len(pw) * math.log2(charset_size(pw))
    low = pw.lower()
    if low in COMMON:
        return naive, math.log2(len(COMMON)), "found in common-password list"
    norm = "".join(ch for ch in low.translate(LEET) if ch.isalpha())
    for w in BASE_WORDS:
        if w in norm:
            # ~100,000-word dictionary + ~10 bits for capital/leet/suffix mutations
            return naive, math.log2(100000) + 10, f"dictionary word '{w}' + simple mutation"
    if kind_hint == "passphrase":
        words = pw.count("-") + 1
        return naive, words * math.log2(7776), f"{words} random words (Diceware 7776-word list ASSUMED)"
    return naive, naive, "no pattern found (assumes truly random choice)"

def rating(bits):
    if bits < 28: return "Very weak"
    if bits < 40: return "Weak"
    if bits < 60: return "Moderate"
    if bits < 80: return "Strong"
    return "Very strong"

def human_time(sec):
    if sec < 1: return "instant (<1 s)"
    for name, s in (("years", 31557600), ("days", 86400), ("hours", 3600), ("minutes", 60)):
        if sec >= s:
            v = sec / s
            if name == "years":
                if v >= 1e9: return ">1 billion years"
                if v >= 1e6: return f"{v/1e6:,.1f} million years"
                if v >= 1e3: return f"{v:,.0f} years"
            return f"{v:,.1f} {name}"
    return f"{sec:,.0f} seconds"

SAMPLES = [
    ("123456", None), ("password", None), ("Summer2024", None), ("Ab1!xy", None),
    ("P@ssw0rd!", None), ("Tr0ub4dor&3", None),
    ("river-copper-lantern-orbit-maple", "passphrase"), ("k9#Vz!2qLm@8Xw4P", None),
]

def pbkdf2_rate(iters=600_000, n=3):
    t = time.perf_counter()
    for _ in range(n):
        hashlib.pbkdf2_hmac("sha256", b"benchmark", b"saltsaltsaltsalt", iters, 32)
    return n / (time.perf_counter() - t)

def cmd_env():
    print(f"OS            : {platform.platform()}")
    print(f"Python        : {platform.python_version()}")
    ssl = subprocess.run(["openssl","version"],capture_output=True,text=True).stdout.strip()
    print(f"OpenSSL       : {ssl}")
    print(f"hashlib algos : md5, sha256, sha512, pbkdf2_hmac={hasattr(hashlib,'pbkdf2_hmac')}, scrypt={hasattr(hashlib,'scrypt')}")
    print("Test data     : dummy passwords and a local demo database only")
    save("env", {"os": platform.platform(), "python": platform.python_version(), "openssl": ssl})

def cmd_strength():
    rate_pbkdf2 = pbkdf2_rate()
    FAST = 1e10
    SLOW = rate_pbkdf2 * 10_000
    print("Assumptions (estimates, not measurements of any real attacker):")
    print(f"  Fast unsalted hash (MD5/SHA-256) attacker : {FAST:.0e} guesses/s")
    print(f"  PBKDF2-600k attacker = {rate_pbkdf2:.1f} H/s per core x 10,000 cores = {SLOW:,.0f} guesses/s")
    print("  Average guesses needed = 2^(effective_bits - 1)\n")
    print(f"{'Password':<34}{'Len':>4} {'Naive':>6} {'Eff.':>6}  {'Rating':<13}{'vs fast hash':<18}{'vs PBKDF2'}")
    print("-" * 100)
    rows = []
    for pw, hint in SAMPLES:
        naive, eff, note = analyse(pw, hint)
        guesses = 2 ** (eff - 1)
        t_fast, t_slow = guesses / FAST, guesses / SLOW
        r = rating(eff)
        shown = pw if len(pw) <= 32 else pw[:31] + "~"
        print(f"{shown:<34}{len(pw):>4} {naive:>6.1f} {eff:>6.1f}  {r:<13}{human_time(t_fast):<18}{human_time(t_slow)}")
        rows.append({"pw": pw, "len": len(pw), "naive": round(naive,1), "eff": round(eff,1), "rating": r,
                     "note": note, "t_fast": human_time(t_fast), "t_slow": human_time(t_slow)})
    print("\nNotes: 'Naive' = length x log2(character set). 'Eff.' lowers it when a common password,")
    print("dictionary word, or predictable pattern is detected. Higher bits = more guesses needed.")
    save("strength", {"rows": rows, "pbkdf2_rate_1core": round(rate_pbkdf2,2), "fast_rate": FAST, "slow_rate": round(SLOW)})

# ----------------------------------------------------------------------------
# 2. Insecure storage and why it fails
# ----------------------------------------------------------------------------
DEMO_USERS = {"alice":"123456", "bob":"123456", "carol":"password", "dave":"Summer2024", "erin":"k9#Vz!2qLm@8Xw4P"}

def candidates():
    seen, out = set(), []
    words = set(COMMON) | set(BASE_WORDS)
    for w in words:
        for v in (w, w.capitalize()):
            for suf in ("", "1", "123", "!", "2020","2021","2022","2023","2024","2025","2026"):
                c = v + suf
                if c not in seen: seen.add(c); out.append(c)
    return out

def cmd_weak():
    print("=== A. Plain-text storage ===")
    for u, p in DEMO_USERS.items(): print(f"  {u:<6} | {p}")
    print("  -> anyone who steals this table reads every password immediately.\n")
    print("=== B. Unsalted SHA-256 storage ===")
    sha = {u: hashlib.sha256(p.encode()).hexdigest() for u, p in DEMO_USERS.items()}
    for u, h in sha.items(): print(f"  {u:<6} | {h[:32]}...")
    print(f"  alice == bob hash? {sha['alice']==sha['bob']}   (equal passwords are visible at once)\n")
    print("=== C. Dictionary attack on the LOCAL demo table (unsalted) ===")
    t0 = time.perf_counter()
    cands = candidates()
    table = {hashlib.sha256(c.encode()).hexdigest(): c for c in cands}
    t_build = time.perf_counter() - t0
    t1 = time.perf_counter()
    cracked = {u: table[h] for u, h in sha.items() if h in table}
    t_look = time.perf_counter() - t1
    print(f"  candidate list : {len(cands):,} guesses, table built in {t_build*1000:.1f} ms")
    for u in DEMO_USERS:
        print(f"  {u:<6} -> {'CRACKED: ' + cracked[u] if u in cracked else 'not cracked'}")
    print(f"  lookup of all {len(DEMO_USERS)} users took {t_look*1000:.3f} ms; cracked {len(cracked)}/{len(DEMO_USERS)}\n")
    print("=== D. Same attack when each password has a random salt (SHA-256, still fast) ===")
    salts = {u: os.urandom(8) for u in DEMO_USERS}
    salted = {u: hashlib.sha256(salts[u] + p.encode()).hexdigest() for u, p in DEMO_USERS.items()}
    print(f"  alice == bob hash? {salted['alice']==salted['bob']}   (salt hides duplicates)")
    print(f"  pre-built table still useful? {any(h in table for h in salted.values())}")
    t2 = time.perf_counter(); c2 = 0; tries = 0
    for u in DEMO_USERS:
        for c in cands:
            tries += 1
            if hashlib.sha256(salts[u] + c.encode()).hexdigest() == salted[u]: c2 += 1; break
    t_s = time.perf_counter() - t2
    print(f"  per-user guessing: {tries:,} hashes, {t_s*1000:.0f} ms, cracked {c2}/{len(DEMO_USERS)}")
    print("  -> salt defeats pre-computed tables, but a FAST hash is still cheap to guess against.\n")
    print("=== E. Same guessing against PBKDF2-600k (first 5 guesses only) ===")
    s = os.urandom(16); target = hashlib.pbkdf2_hmac("sha256", b"Summer2024", s, 600_000, 32)
    t3 = time.perf_counter()
    for g in ["password","Password1","Summer2023","Summer2022","Summer2024"]:
        hit = hashlib.pbkdf2_hmac("sha256", g.encode(), s, 600_000, 32) == target
        print(f"  guess {g:<12} -> {'MATCH' if hit else 'no'}")
    el = time.perf_counter() - t3
    print(f"  5 guesses took {el:.2f} s  (~{el/5*1000:.0f} ms each) vs ~{t_s/tries*1e6:.2f} microseconds each for plain SHA-256")
    save("weak", {"candidates": len(cands), "build_ms": round(t_build*1000,1), "cracked_unsalted": len(cracked),
                  "cracked_users": sorted(cracked), "salted_table_useful": any(h in table for h in salted.values()),
                  "salted_cracked": c2, "salted_tries": tries, "salted_ms": round(t_s*1000),
                  "pbkdf2_ms_per_guess": round(el/5*1000), "sha_us_per_guess": round(t_s/tries*1e6, 2)})

# ----------------------------------------------------------------------------
# 3. Secure hashing and verification
# ----------------------------------------------------------------------------
PBKDF2_ITERS = 600_000
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1

def norm(pw): return unicodedata.normalize("NFKC", pw).encode("utf-8")

def hash_password(pw, algo="pbkdf2"):
    salt = secrets.token_bytes(16)
    if algo == "pbkdf2":
        dk = hashlib.pbkdf2_hmac("sha256", norm(pw), salt, PBKDF2_ITERS, 32)
        return f"pbkdf2_sha256${PBKDF2_ITERS}${b64(salt)}${b64(dk)}"
    if algo == "scrypt":
        dk = hashlib.scrypt(norm(pw), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=128*1024*1024, dklen=32)
        return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(dk)}"
    raise ValueError(algo)

def verify_password(pw, stored):
    try:
        parts = stored.split("$")
        if parts[0] == "pbkdf2_sha256":
            _, it, s, h = parts
            dk = hashlib.pbkdf2_hmac("sha256", norm(pw), unb64(s), int(it), 32)
            return hmac.compare_digest(dk, unb64(h))
        if parts[0] == "scrypt":
            _, n, r, p, s, h = parts
            dk = hashlib.scrypt(norm(pw), salt=unb64(s), n=int(n), r=int(r), p=int(p), maxmem=128*1024*1024, dklen=32)
            return hmac.compare_digest(dk, unb64(h))
    except Exception:
        return False
    return False

def cmd_secure():
    print("=== Registration: store only salted, slow hashes ===")
    db = {}
    for u, p in [("alice","123456"), ("bob","123456"), ("erin","k9#Vz!2qLm@8Xw4P")]:
        db[u] = hash_password(p, "pbkdf2")
        print(f"  {u:<6} -> {db[u][:46]}...")
    db["frank"] = hash_password("river-copper-lantern-orbit-maple", "scrypt")
    print(f"  frank  -> {db['frank'][:46]}...   (scrypt)")
    json.dump(db, open("users_db.json","w"), indent=2)
    print("  saved to users_db.json (no plain-text passwords stored)")
    print(f"  alice and bob used the SAME password. Stored values equal? {db['alice']==db['bob']}\n")
    print("=== Login attempts ===")
    attempts = [("alice","123456"), ("alice","1234567"), ("erin","k9#Vz!2qLm@8Xw4P"), ("erin","K9#Vz!2qLm@8Xw4P"),
                ("frank","river-copper-lantern-orbit-maple"), ("frank","river-copper-lantern-orbit-mapl")]
    out = []
    for u, p in attempts:
        ok = verify_password(p, db[u])
        shown = p if len(p) < 20 else p[:17] + "..."
        print(f"  login {u:<6} with {shown:<22} -> {'ACCESS GRANTED' if ok else 'ACCESS DENIED'}")
        out.append({"user": u, "pw": shown, "ok": ok})
    save("secure", {"stored_equal": db['alice']==db['bob'], "attempts": out,
                    "format": "algorithm$parameters$salt$hash", "example": db['alice'][:60]})

# ----------------------------------------------------------------------------
# 4. Cross-check with OpenSSL
# ----------------------------------------------------------------------------
def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout.strip()

def cmd_openssl():
    print("$ openssl version"); print(sh("openssl version"))
    print("\n[1] Unsalted SHA-256 of '123456' - OpenSSL vs Python")
    o = sh("printf '123456' | openssl dgst -sha256").split()[-1]
    p = hashlib.sha256(b"123456").hexdigest()
    print(f"  openssl : {o}\n  python  : {p}\n  match   : {o == p}")
    print("\n[2] OpenSSL salted SHA-512-crypt ($6$) - same salt gives same output, new salt gives new output")
    a = sh("openssl passwd -6 -salt 'Zq8x3KpL' 'Summer2024'")
    b = sh("openssl passwd -6 -salt 'Zq8x3KpL' 'Summer2024'")
    c = sh("openssl passwd -6 -salt 'Mn4v7RtW' 'Summer2024'")
    print(f"  salt Zq8x3KpL : {a[:56]}...\n  salt Zq8x3KpL : {b[:56]}...  (identical: {a==b})")
    print(f"  salt Mn4v7RtW : {c[:56]}...  (different: {a!=c})")
    print("\n[3] PBKDF2-HMAC-SHA256 (600,000 iterations): OpenSSL kdf vs Python hashlib")
    salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cmd = ("openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:Summer2024 "
           f"-kdfopt hexsalt:{salt.hex()} -kdfopt iter:600000 PBKDF2")
    print(f"  $ {cmd}")
    ossl = sh(cmd).replace(":", "").lower()
    py = hashlib.pbkdf2_hmac("sha256", b"Summer2024", salt, 600000, 32).hex()
    print(f"  openssl : {ossl}\n  python  : {py}\n  match   : {ossl == py}")
    save("openssl", {"sha_match": o == p, "crypt_same_salt_equal": a == b, "crypt_diff_salt_differs": a != c,
                     "pbkdf2_match": ossl == py, "crypt_example": a[:40]})

# ----------------------------------------------------------------------------
# 5. Test cases
# ----------------------------------------------------------------------------
def cmd_tests():
    results = []
    def check(tid, desc, expected, actual):
        ok = expected == actual
        results.append({"id": tid, "desc": desc, "expected": str(expected), "actual": str(actual), "pass": ok})
        print(f"  {tid:<4}{desc:<58}exp={str(expected):<6}got={str(actual):<6}{'PASS' if ok else 'FAIL'}")
    good = "Tr1cky-Sample#Pass"
    h1 = hash_password(good)
    print(f"  {'ID':<4}{'Test':<58}{'Expected / Actual':<20}Result")
    print("-" * 92)
    check("T1", "Correct password verifies (PBKDF2)", True, verify_password(good, h1))
    check("T2", "Wrong password is rejected", False, verify_password("Tr1cky-Sample#Pas", h1))
    check("T3", "Case change is rejected (case sensitive)", False, verify_password(good.lower(), h1))
    check("T4", "Extra trailing space is rejected", False, verify_password(good + " ", h1))
    check("T5", "Empty password is rejected", False, verify_password("", h1))
    h2 = hash_password(good)
    check("T6", "Same password hashed twice gives different stored values", True, h1 != h2)
    check("T7", "Both of those different stored values still verify", True, verify_password(good, h2) and verify_password(good, h1))
    parts = h1.split("$"); bad = bytearray(unb64(parts[3])); bad[0] ^= 1; parts[3] = b64(bytes(bad))
    check("T8", "Tampered stored hash (1 bit flipped) is rejected", False, verify_password(good, "$".join(parts)))
    hs = hash_password(good, "scrypt")
    check("T9", "Correct password verifies (scrypt)", True, verify_password(good, hs))
    check("T10", "Wrong password rejected (scrypt)", False, verify_password("wrong", hs))
    check("T11", "Malformed stored string handled safely (no crash)", False, verify_password(good, "garbage"))
    check("T12", "Unicode (NFC vs NFD form of same text) treated equal", True,
          verify_password(unicodedata.normalize("NFC", "caf\u00e9Pass!9"), hash_password(unicodedata.normalize("NFD", "caf\u00e9Pass!9"))))
    p = sum(r["pass"] for r in results)
    print("-" * 92); print(f"  {p}/{len(results)} tests passed")
    save("tests", {"results": results, "passed": p, "total": len(results)})

# ----------------------------------------------------------------------------
# 6. Benchmark
# ----------------------------------------------------------------------------
def cmd_bench():
    pw, salt = b"Summer2024", b"saltsaltsaltsalt"
    def timeit(fn, n):
        fn(); t = time.perf_counter()
        for _ in range(n): fn()
        return (time.perf_counter() - t) / n
    algos = [
        ("MD5",                  lambda: hashlib.md5(pw).digest(), 200000),
        ("SHA-256",              lambda: hashlib.sha256(pw).digest(), 200000),
        ("SHA-512",              lambda: hashlib.sha512(pw).digest(), 200000),
        ("PBKDF2-SHA256 (600k)", lambda: hashlib.pbkdf2_hmac("sha256", pw, salt, 600000, 32), 3),
        ("scrypt (N=2^15,r=8)",  lambda: hashlib.scrypt(pw, salt=salt, n=2**15, r=8, p=1, maxmem=128*1024*1024, dklen=32), 3),
    ]
    print(f"{'Algorithm':<24}{'Time per hash':>16}{'Hashes/second':>18}{'Slower than SHA-256':>22}")
    print("-" * 80)
    rows = []; base = None
    for name, fn, n in algos:
        t = timeit(fn, n)
        if name == "SHA-256": base = t
        rows.append({"name": name, "t": t})
    for r in rows:
        t = r["t"]
        tt = f"{t*1e6:,.2f} us" if t < 1e-3 else f"{t*1000:,.1f} ms"
        ratio = f"{t/base:,.2f}x" if t/base < 10 else f"{t/base:,.0f}x"
        print(f"{r['name']:<24}{tt:>16}{1/t:>18,.1f}{ratio:>22}")
        r["hps"] = 1/t; r["ratio"] = t/base
    save("bench", rows)

SECTIONS = {"env": cmd_env, "strength": cmd_strength, "weak": cmd_weak, "secure": cmd_secure,
            "openssl": cmd_openssl, "tests": cmd_tests, "bench": cmd_bench}
if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    if arg == "all":
        for k, f in SECTIONS.items():
            print(f"\n######## {k} ########"); f()
    elif arg in SECTIONS: SECTIONS[arg]()
    else: print(__doc__)
