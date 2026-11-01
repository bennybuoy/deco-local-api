#!/usr/bin/env python3
"""Deco X50 local API client: AES-128-CBC + RSA PKCS#1 v1.5 envelope.

Implements the handshake documented in tplink-deco-api and re-derived from
the Deco X50 v1.30 web UI source (frame.js / tpEncrypt.js / encrypt.js):

  * POST /login?form=auth   -> result.key = [sign_mod, e], result.seq
  * POST /login?form=keys   -> result.password = [pwd_mod, e]
  * login body: AES(JSON({"operation":"login","params":{"password": Rsa(pwd)}}))
                sign = Rsa(sign_key, "k=..&i=..&h=<md5(user+pwd)>&s=<seq+len(b64)>")
  * every later request: same envelope, same seq, stok in URL path.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from base64 import b64decode, b64encode
from urllib.parse import quote_plus

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIGITS = "0123456789"


# --------------------------------------------------------------------------- crypto
def aes_encrypt(key: str, iv: str, plaintext: str) -> str:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    enc = cipher.encryptor()
    return b64encode(enc.update(padded) + enc.finalize()).decode()


def aes_decrypt(key: str, iv: str, ciphertext_b64: str) -> str:
    ct = b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def _rsa_block(n: int, e: int, k: int, block: bytes) -> str:
    if len(block) > k - 11:
        raise ValueError(f"RSA block too long: {len(block)} > {k - 11}")
    pad = b""
    while len(pad) < k - len(block) - 3:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            pad += b
    em = b"\x00\x02" + pad + b"\x00" + block
    return format(pow(int.from_bytes(em, "big"), e, n), f"0{k * 2}x")


def rsa_encrypt(n_hex: str, e_hex: str, plaintext: bytes) -> str:
    """PKCS#1 v1.5, split into (k-11)-byte blocks; lowercase hex out."""
    n = int(n_hex, 16)
    e = int(e_hex, 16)
    k = (n.bit_length() + 7) // 8
    step = k - 11
    return "".join(
        _rsa_block(n, e, k, plaintext[i:i + step]) for i in range(0, len(plaintext), step)
    )


def gen_aes_pair() -> tuple[str, str]:
    return (
        "".join(secrets.choice(DIGITS) for _ in range(16)),
        "".join(secrets.choice(DIGITS) for _ in range(16)),
    )


# --------------------------------------------------------------------------- client
class DecoClient:
    def __init__(self, host: str = "192.168.68.1", scheme: str = "http", timeout: float = 10.0):
        self.host = host
        self.scheme = scheme
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.cookie: str | None = None
        self.stok = ""
        self.aes_key = ""
        self.aes_iv = ""
        self.hash = ""
        self.seq = 0
        self.sign_key: tuple[str, str] | None = None
        self.pwd_key: tuple[str, str] | None = None

    # ---- transport
    def _post(self, path: str, body: str, ctype: str = "application/json"):
        url = f"{self.scheme}://{self.host}{path}"
        headers = {"Content-Type": ctype}
        if self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(url, data=body.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                self._grab_cookie(r)
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            self._grab_cookie(e)
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def _grab_cookie(self, resp):
        for k, v in getattr(resp, "headers", {}).items():
            if k.lower() == "set-cookie" and "sysauth=" in v:
                for part in v.split(";"):
                    if part.strip().startswith("sysauth="):
                        self.cookie = part.strip()

    # ---- handshake
    def fetch_keys(self):
        st, body, _ = self._post("/cgi-bin/luci/;stok=/login?form=auth",
                                 json.dumps({"operation": "read"}))
        j = json.loads(body)
        self.sign_key = (j["result"]["key"][0], j["result"]["key"][1])
        self.seq = int(j["result"]["seq"])
        st, body, _ = self._post("/cgi-bin/luci/;stok=/login?form=keys",
                                 json.dumps({"operation": "read"}))
        j = json.loads(body)
        self.pwd_key = (j["result"]["password"][0], j["result"]["password"][1])
        return self.sign_key, self.pwd_key, self.seq

    def _envelope(self, obj) -> str:
        data_b64 = aes_encrypt(self.aes_key, self.aes_iv,
                               json.dumps(obj, separators=(",", ":")))
        sig_str = (f"k={self.aes_key}&i={self.aes_iv}"
                   f"&h={self.hash}&s={self.seq + len(data_b64)}")
        sign = rsa_encrypt(self.sign_key[0], self.sign_key[1], sig_str.encode())
        return f"sign={sign}&data={quote_plus(data_b64)}"

    def _open(self, raw: str):
        j = json.loads(raw)
        if isinstance(j.get("data"), str) and j["data"]:
            return json.loads(aes_decrypt(self.aes_key, self.aes_iv, j["data"]))
        return j

    def login(self, username: str, password: str):
        self.fetch_keys()
        self.aes_key, self.aes_iv = gen_aes_pair()
        self.hash = hashlib.md5((username + password).encode()).hexdigest()
        pwd_enc = rsa_encrypt(self.pwd_key[0], self.pwd_key[1], password.encode())
        payload = {"operation": "login", "params": {"password": pwd_enc}}
        body = self._envelope(payload)
        st, raw, hdrs = self._post("/cgi-bin/luci/;stok=/login?form=login", body)
        return st, raw, hdrs, body

    def call(self, path: str, form: str, payload):
        body = self._envelope(payload)
        st, raw, hdrs = self._post(f"/cgi-bin/luci/;stok={self.stok}/{path}?form={form}", body)
        try:
            return st, self._open(raw), raw
        except Exception as exc:  # noqa: BLE001
            return st, {"_decrypt_error": f"{type(exc).__name__}: {exc}"}, raw


def main():
    user = "admin"
    pwd = "W@lbk051"
    c = DecoClient()
    sk, pk, seq = c.fetch_keys()
    print(f"sign_key={sk[0][:16]}..({len(sk[0])}hex) pwd_key={pk[0][:16]}..({len(pk[0])}hex) seq={seq}")
    st, raw, hdrs, body = c.login(user, pwd)
    print(f"LOGIN status={st} content-type={hdrs.get('Content-Type')} len(body)={len(body)}")
    print(f"raw[:800]={raw[:800]}")
    try:
        j = c._open(raw)
        print(f"decoded={json.dumps(j)[:800]}")
        if isinstance(j.get("result"), dict) and j["result"].get("stok"):
            c.stok = j["result"]["stok"]
            print(f"STOK={c.stok}  usrLvl={j['result'].get('usrLvl')}")
    except Exception as exc:  # noqa: BLE001
        print(f"decode failed: {exc}")


if __name__ == "__main__":
    main()
