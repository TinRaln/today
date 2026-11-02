#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Upstream 账号服务（account.xfinfr.com）客户端 —— 签名 + 短信登录 + 签到。

协议逆向自 Upstream 桌面客户端（Electron），签名算法 HMAC-SHA1，
stringToSign 固定 9 行。
"""

import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
import urllib.request
import uuid

AK_ID = "2thryby66wxi53sk"
AK_SECRET = "zsak6eadrbawz683wf5r3m2snrwj868r"
BASE = "https://account.xfinfr.com"
UA_STR = "Upstream|Desktop|Electron|macOS"

_EXTRA = {"!": "%21", "'": "%27", "(": "%28", ")": "%29", "*": "%2A"}


def escape(s: str) -> str:
    out = urllib.parse.quote(s, safe="")
    out = out.replace("+", "%20")
    for raw, enc in _EXTRA.items():
        out = out.replace(raw, enc)
    return out


def escape_path(p: str) -> str:
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return "/".join(escape(seg) if seg else "" for seg in p.split("/"))


def content_md5(body: str) -> str:
    if not body:
        return ""
    return base64.b64encode(hashlib.md5(body.encode()).digest()).decode()


def string_to_sign(method, path, body, content_type, date, nonce, custom=None):
    custom = custom or {}
    picked = {k.lower(): v.strip() for k, v in custom.items() if k.lower().startswith("x-")}
    signed = ";".join(sorted(picked))
    canon = "\n".join(f"{k}:{picked[k]}" for k in sorted(picked))
    lines = [
        method.upper(),
        escape_path(path),
        "",                      # query 为空
        content_md5(body),
        content_type,
        date,
        nonce,
        signed,
        canon,
    ]
    return "\n".join(lines)


def sign(secret, method, path, body, content_type, date, nonce, custom=None):
    sts = string_to_sign(method, path, body, content_type, date, nonce, custom)
    mac = hmac.new(secret.encode(), sts.encode(), hashlib.sha1)
    return base64.b64encode(mac.digest()).decode(), sts


def build_headers(method, path, body, auth_prefix="hmac "):
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    nonce = str(uuid.uuid4())
    ctype = "application/json"
    sig, sts = sign(AK_SECRET, method, path, body, ctype, date, nonce)
    headers = {
        "Authorization": f"{auth_prefix}{AK_ID}:{sig}",
        "Date": date,
        "Nonce": nonce,
        "Content-Type": ctype,
        "Accept": "application/json",
        "User-Agent": "Upstream/0.9.38",
    }
    md5s = content_md5(body)
    if md5s:
        headers["Content-MD5"] = md5s
    return headers, sts


def envelope(param: dict) -> str:
    return json.dumps({
        "base": {
            "appid": "GM3UPSTREAM",
            "modelid": "Web",
            "version": "1.0.0",
            "devid": "web",
            "ua": UA_STR,
            "traceid": uuid.uuid4().hex,
        },
        "param": param,
    }, ensure_ascii=False)


def call(path, param, auth_prefix="hmac "):
    body = envelope(param)
    headers, sts = build_headers("POST", path, body, auth_prefix)
    req = urllib.request.Request(BASE + path, data=body.encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"EXC {type(e).__name__}: {e}"


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "signcheck"
    prefix = sys.argv[2] if len(sys.argv) > 2 else "hmac "

    if action == "signcheck":
        print(f"== 签名自检（prefix={prefix!r}）==")
        body = envelope({"phone": "YOUR_PHONE_NUMBER"})
        h, sts = build_headers("POST", "/login/phone/sendMsgCode", body, prefix)
        print("  stringToSign（9 行）:")
        for i, line in enumerate(sts.split("\n")):
            print(f"    {i+1}: {line!r}")
        print("  Authorization:", h["Authorization"][:60] + "...")
        print("  Content-MD5:", h.get("Content-MD5"))

    elif action == "send":
        phone = sys.argv[3] if len(sys.argv) > 3 else "YOUR_PHONE_NUMBER"
        code, resp = call("/login/phone/sendMsgCode", {"phone": phone}, prefix)
        print(f"  HTTP {code}")
        print("  ", resp[:400])

    elif action == "check":
        phone, msgid, code6 = sys.argv[3], sys.argv[4], sys.argv[5]
        c, resp = call("/login/phone/checkCode",
                       {"phone": phone, "msgid": msgid, "code": code6}, prefix)
        print(f"  HTTP {c}")
        print("  ", resp[:600])
