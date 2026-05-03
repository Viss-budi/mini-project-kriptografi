import os
import json
import hashlib
import hmac
import argparse

BASELINE_FILE = "baseline.json"

# ==============================
# HASH FILE (SHA-256)
# ==============================
def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ==============================
# SCAN FOLDER
# ==============================
def scan_folder(folder):
    result = {}
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            result[path] = hash_file(path)
    return result

# ==============================
# HMAC
# ==============================
def generate_hmac(data_str, password):
    return hmac.new(password.encode(), data_str.encode(), hashlib.sha256).hexdigest()

# ==============================
# INIT
# ==============================
def init(folder, password):
    data = scan_folder(folder)
    print(f"[INIT] Memindai {len(data)} file...")

    data_str = json.dumps(data, sort_keys=True)
    mac = generate_hmac(data_str, password)

    baseline = {
        "data": data,
        "hmac": mac
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"[INIT] Baseline disimpan: {BASELINE_FILE} (HMAC dilindungi)")

# ==============================
# CHECK
# ==============================
def check(folder, password):
    if not os.path.exists(BASELINE_FILE):
        print("[ERROR] Baseline tidak ditemukan!")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    data_old = baseline["data"]
    mac_old = baseline["hmac"]

    data_str = json.dumps(data_old, sort_keys=True)
    mac_check = generate_hmac(data_str, password)

    # 🔴 CEK HMAC (WAJIB DULU)
    if not hmac.compare_digest(mac_old, mac_check):
        print("[ERROR] Baseline dimodifikasi! HMAC tidak valid — baseline tidak dipercaya.")
        return

    # lanjut scan
    data_new = scan_folder(folder)
    print(f"[CHECK] Memindai {len(data_new)} file...")

    old_files = set(data_old.keys())
    new_files = set(data_new.keys())

    unchanged = 0

    # cek file lama
    for file in old_files:
        if file not in new_files:
            print(f"[HAPUS] {file}")
        else:
            if data_old[file] == data_new[file]:
                unchanged += 1
            else:
                print(f"[UBAH] {file}")
                print(f"Baseline: {data_old[file][:16]}...")
                print(f"Sekarang: {data_new[file][:16]}...")

    # cek file baru
    for file in new_files - old_files:
        print(f"[BARU] {file}")

    print(f"[OK] {unchanged} file tidak berubah")

# ==============================
# CLI
# ==============================
def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("command", choices=["init", "check"])
    parser.add_argument("folder")
    parser.add_argument("--password", required=True)

    args = parser.parse_args()

    if args.command == "init":
        init(args.folder, args.password)
    elif args.command == "check":
        check(args.folder, args.password)

if __name__ == "__main__":
    main()