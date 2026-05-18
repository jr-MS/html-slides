#!/usr/bin/env python3
"""Encrypt an HTML slide with AES-256-GCM so it requires a password to view.

Usage:
    python3 scripts/protect_slide.py SOURCE_HTML PASSWORD [--title TITLE]

The encrypted file is written to  protected/<slug>.html  inside the repo.
A matching entry is upserted into slides.json with  "protected": true.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
from datetime import date
from pathlib import Path

# ── crypto helpers ──────────────────────────────────────────────────────────

def encrypt_aes_gcm(plaintext: bytes, password: str) -> dict:
    """Return {salt, iv, ciphertext} all base64-encoded."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(password.encode("utf-8"))
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }

# ── HTML gate template ──────────────────────────────────────────────────────

GATE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{TITLE}} — Protected</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:"Avenir Next","PingFang SC","Segoe UI",sans-serif;
  color:#eef3ff;
  background:
    radial-gradient(circle at 18% 22%,rgba(100,160,230,.22),transparent 28%),
    radial-gradient(circle at 78% 20%,rgba(160,130,255,.18),transparent 26%),
    radial-gradient(circle at 60% 82%,rgba(130,220,200,.14),transparent 24%),
    linear-gradient(155deg,#060d1a 0%,#0b1428 44%,#101d38 100%);
  display:flex;align-items:center;justify-content:center;
  overflow:hidden;
}
body::before{
  content:"";position:fixed;inset:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px);
  background-size:68px 68px;
  mask-image:radial-gradient(circle,black 50%,transparent 86%);
  opacity:.6;
}
.gate{
  position:relative;z-index:1;
  width:min(440px,calc(100vw - 48px));
  border-radius:32px;
  padding:42px 36px 38px;
  background:
    linear-gradient(180deg,rgba(255,255,255,.08),rgba(255,255,255,.03)),
    rgba(8,14,30,.82);
  border:1px solid rgba(255,255,255,.1);
  box-shadow:0 32px 80px rgba(0,0,0,.45);
  backdrop-filter:blur(24px);
  text-align:center;
}
.lock{
  display:inline-flex;align-items:center;justify-content:center;
  width:64px;height:64px;border-radius:20px;
  background:linear-gradient(135deg,rgba(130,180,255,.16),rgba(160,130,255,.14));
  border:1px solid rgba(255,255,255,.1);
  margin-bottom:22px;
  font-size:28px;
}
h1{
  font-size:26px;letter-spacing:-.03em;margin-bottom:8px;
  font-weight:700;
}
.sub{color:rgba(228,237,255,.6);font-size:15px;line-height:1.5;margin-bottom:26px}
.field{
  display:flex;gap:10px;margin-bottom:14px;
}
input{
  flex:1;
  padding:16px 18px;
  border-radius:18px;
  border:1px solid rgba(255,255,255,.12);
  background:rgba(255,255,255,.06);
  color:#fff;
  font:inherit;font-size:16px;
  outline:none;
  transition:border-color .2s;
}
input:focus{border-color:rgba(130,180,255,.5)}
input::placeholder{color:rgba(228,237,255,.38)}
button{
  padding:16px 22px;
  border-radius:18px;
  border:none;
  background:linear-gradient(135deg,#4a8adf,#6c6cf0);
  color:#fff;font:inherit;font-size:16px;font-weight:700;
  cursor:pointer;letter-spacing:.02em;
  transition:transform .15s,box-shadow .15s;
  box-shadow:0 8px 24px rgba(74,138,223,.3);
}
button:hover{transform:translateY(-1px);box-shadow:0 12px 28px rgba(74,138,223,.4)}
button:active{transform:translateY(0)}
.error{
  color:#ff8a8a;font-size:14px;min-height:20px;
  opacity:0;transition:opacity .25s;
}
.error.show{opacity:1}
.note{
  margin-top:18px;color:rgba(228,237,255,.36);font-size:12px;
  letter-spacing:.06em;text-transform:uppercase;
}
</style>
</head>
<body>
<div class="gate">
  <div class="lock">🔒</div>
  <h1>{{TITLE}}</h1>
  <p class="sub">This slide is password-protected.<br>Enter the password to continue.</p>
  <div class="field">
    <input id="pw" type="password" placeholder="Password" autofocus autocomplete="off"/>
    <button id="go">Open</button>
  </div>
  <div id="err" class="error"></div>
  <div class="note">AES-256-GCM · client-side decryption</div>
</div>

<script>
const ENCRYPTED = {{ENCRYPTED_JSON}};

async function deriveKey(password, saltB64) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function decrypt(password) {
  try {
    const key = await deriveKey(password, ENCRYPTED.salt);
    const iv = Uint8Array.from(atob(ENCRYPTED.iv), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(ENCRYPTED.data), c => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

async function unlock() {
  const pw = document.getElementById('pw').value;
  if (!pw) return;
  const errEl = document.getElementById('err');
  errEl.classList.remove('show');
  const html = await decrypt(pw);
  if (html) {
    document.open();
    document.write(html);
    document.close();
  } else {
    errEl.textContent = 'Wrong password. Please try again.';
    errEl.classList.add('show');
  }
}

document.getElementById('go').addEventListener('click', unlock);
document.getElementById('pw').addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
</script>
</body>
</html>"""

# ── helpers ─────────────────────────────────────────────────────────────────

def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return re.sub(r"-{2,}", "-", slug) or "protected-slide"


def extract_title(html_text: str, fallback: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
    if not m:
        return fallback
    import html as htmlmod
    return htmlmod.unescape(re.sub(r"\s+", " ", m.group(1)).strip()) or fallback


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt an HTML slide with a password.")
    parser.add_argument("source", help="Path to the plain HTML file.")
    parser.add_argument("password", help="Password required to view the slide.")
    parser.add_argument("--title", help="Override the card title.")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent),
                        help="Path to the html-slides repo.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    source = Path(args.source).expanduser().resolve()
    repo = Path(args.repo).expanduser().resolve()
    if not source.exists():
        print(f"ERROR: source not found: {source}", file=sys.stderr)
        return 1

    plaintext = source.read_bytes()
    title = args.title or extract_title(plaintext.decode("utf-8", errors="replace"),
                                         source.stem.replace("-", " ").replace("_", " ").title())
    slug = slugify(source.stem)
    target = repo / "protected" / f"{slug}.html"

    print(f"Encrypting: {source.name}")
    print(f"Title:      {title}")
    print(f"Target:     protected/{slug}.html")

    encrypted = encrypt_aes_gcm(plaintext, args.password)
    gate_html = (
        GATE_TEMPLATE
        .replace("{{TITLE}}", title.replace('"', "&quot;"))
        .replace("{{ENCRYPTED_JSON}}", json.dumps(encrypted))
    )

    if args.dry_run:
        print("Dry run — no files written.")
        return 0

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(gate_html, encoding="utf-8")
    print(f"Written:    {target}")

    # upsert into slides.json
    slides_path = repo / "slides.json"
    items = json.loads(slides_path.read_text("utf-8")) if slides_path.exists() else []
    item_id = f"protected-{slug}"
    items = [i for i in items if i.get("id") != item_id]
    items.append({
        "id": item_id,
        "title": f"🔒 {title}",
        "description": "Password-protected slide. Click to unlock.",
        "category": "Protected",
        "tags": ["Protected"],
        "audience": "team",
        "visibility": "protected",
        "path": f"protected/{slug}.html",
        "featured": False,
        "protected": True,
        "updated": str(date.today()),
    })
    slides_path.write_text(json.dumps(items, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print(f"Updated:    slides.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
