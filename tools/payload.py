#!/usr/bin/env python3
"""Decrypt and re-encrypt the password-protected part of index.html.

index.html on main is the single source of truth for the protected content
(program, readings, participant list). There is no other copy to keep in sync:
decrypt a working copy, edit it, encrypt it back, commit index.html.

    pip install cryptography
    python3 tools/payload.py decrypt     # index.html -> private/content.html
    $EDITOR private/content.html
    python3 tools/payload.py diff        # review the change
    python3 tools/payload.py encrypt     # private/content.html -> index.html
    git commit index.html

The password is read from $FOA_PASSWORD, or prompted for. It is never written
anywhere; do not put it in commits, scripts or command-line arguments.

private/ is gitignored, so the plaintext working copy is never committed.

Safeguards:
  * encrypt checks the password against the current payload, so a typo cannot
    lock readers out.
  * encrypt refuses if index.html changed after the working copy was decrypted
    (someone else's edit landed in between); decrypt again and redo the edit,
    or pass --force if you really mean to replace it.
  * salt, iteration count and id are kept, so the derived key is unchanged and
    browsers that already unlocked the page stay unlocked; only the IV is new.
"""
import argparse
import base64
import difflib
import getpass
import json
import os
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

ROOT = Path(__file__).resolve().parent.parent
PAYLOAD_RE = re.compile(r"/\*__PAYLOAD__\*/(\{.*?\});")


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode()


def parse(src):
    m = PAYLOAD_RE.search(src)
    if not m:
        sys.exit("No /*__PAYLOAD__*/ block found in index.html")
    return src, m, json.loads(m.group(1))


def load(index):
    return parse(index.read_text(encoding="utf-8"))


def password():
    pw = os.environ.get("FOA_PASSWORD") or getpass.getpass("Page password: ")
    if not pw:
        sys.exit("No password given.")
    return pw


def derive(pw, payload):
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, b64d(payload["salt"]), payload["iter"])
    return kdf.derive(pw.encode())


def decrypt_payload(key, payload):
    try:
        return AESGCM(key).decrypt(b64d(payload["iv"]), b64d(payload["ct"]), None).decode()
    except Exception:
        sys.exit("Wrong password (or corrupted payload); nothing was changed.")


def base_file(plain):
    return plain.with_name("." + plain.name + ".base")


def show_diff(old, new, a="index.html", b="working copy"):
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), a, b, lineterm=""))
    print("\n".join(lines) if lines else "No changes.")
    return bool(lines)


def cmd_decrypt(args):
    _, _, payload = load(args.index)
    text = decrypt_payload(derive(password(), payload), payload)
    args.plain.parent.mkdir(parents=True, exist_ok=True)
    args.plain.write_text(text, encoding="utf-8")
    base_file(args.plain).write_text(payload["iv"], encoding="utf-8")
    print(f"Decrypted to {args.plain}")


def cmd_diff(args):
    _, _, payload = load(args.index)
    current = decrypt_payload(derive(password(), payload), payload)
    show_diff(current, args.plain.read_text(encoding="utf-8"))


def cmd_encrypt(args):
    src, m, payload = load(args.index)
    if not args.plain.exists():
        sys.exit(f"{args.plain} not found; run decrypt first.")
    base = base_file(args.plain)
    if not args.force and (not base.exists() or base.read_text().strip() != payload["iv"]):
        sys.exit("index.html changed since the working copy was decrypted (or it was not made "
                 "by decrypt). Decrypt again and redo the edit, or pass --force to replace it.")

    key = derive(password(), payload)
    current = decrypt_payload(key, payload)  # also verifies the password
    new = args.plain.read_text(encoding="utf-8")
    if not show_diff(current, new):
        return

    iv = os.urandom(12)  # fresh 96-bit nonce for every encryption under the same key
    ct = AESGCM(key).encrypt(iv, new.encode(), None)
    updated = dict(payload, iv=b64e(iv), ct=b64e(ct))
    out = src[:m.start(1)] + json.dumps(updated, separators=(",", ":")) + src[m.end(1):]

    if decrypt_payload(key, parse(out)[2]) != new:
        sys.exit("Round-trip check failed; nothing was changed.")
    args.index.write_text(out, encoding="utf-8")
    base.write_text(updated["iv"], encoding="utf-8")
    print(f"Re-encrypted into {args.index}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--index", type=Path, default=ROOT / "index.html")
    ap.add_argument("--plain", type=Path, default=ROOT / "private" / "content.html")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("decrypt", help="index.html -> working copy")
    sub.add_parser("diff", help="show changes in the working copy against index.html")
    enc = sub.add_parser("encrypt", help="working copy -> index.html")
    enc.add_argument("--force", action="store_true",
                     help="encrypt even if index.html changed since decrypt")
    args = ap.parse_args()
    {"decrypt": cmd_decrypt, "diff": cmd_diff, "encrypt": cmd_encrypt}[args.cmd](args)


if __name__ == "__main__":
    main()
