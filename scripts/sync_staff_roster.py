#!/usr/bin/env python3
"""Produce public headcounts and AES-GCM encrypted named roster from the authoritative XLSX.
No staff names, shifts, workbook URL, or decryption code may enter the public plaintext feed.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from openpyxl import load_workbook
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

TOKYO = ZoneInfo("Asia/Tokyo")
SHIFT = re.compile(r"^(\d{1,2})(?:\.(5))?\s*-\s*(\d{1,2})(?:\.(5))?$")

def describe(value):
    if value is None:
        return None
    raw = str(value).strip()
    if not raw or raw in {"休","有給","公休","欠","-","×","OFF","振休"}:
        return None
    if raw == "A":
        return "終日勤務（A）"
    match = SHIFT.fullmatch(raw)
    if match:
        h1, half1, h2, half2 = match.groups()
        start = int(h1) * 60 + (30 if half1 else 0)
        end = int(h2) * 60 + (30 if half2 else 0)
        if start < end <= 24*60:
            fmt = lambda n: f"{n // 60:02d}:{n % 60:02d}"
            return f"{fmt(start)}〜{fmt(end)}"
    # Preserve any other scheduled code verbatim: avoid silently inventing times.
    return raw

def parse_roster(path, month):
    wb = load_workbook(path, data_only=True, read_only=True)
    target = f"{month.month}月{month.year%100:02d}"
    if target not in wb.sheetnames:
        raise RuntimeError(f"Current-month sheet is missing: {target}")
    ws = wb[target]
    rows = list(ws.iter_rows(min_row=1, max_row=48, min_col=1, max_col=35, values_only=True))
    dates = []
    for col in range(4,35):
        v = rows[1][col]
        if isinstance(v, (dt.datetime,dt.date)) and v.year == month.year and v.month == month.month:
            dates.append((col, v.date() if isinstance(v,dt.datetime) else v))
    if len(dates) not in (28,29,30,31):
        raise RuntimeError(f"Suspicious number of dates {len(dates)}")
    output = {}
    counts = {}
    for col, date in dates:
        key = date.isoformat()
        morning,evening = rows[3][col],rows[4][col]
        if not all(isinstance(k,(int,float)) and 0 <= k <= 30 for k in (morning,evening)):
            raise RuntimeError(f"Missing or invalid headcounts on {key}")
        scheduled = []
        for row in rows[5:]:
            name = row[2]
            if not isinstance(name,str) or not name.strip() or len(name)>20 or "【" in name or "メモ" in name:
                continue
            formatted = describe(row[col])
            if formatted:
                scheduled.append({"name": name.strip(), "time": formatted})
        if len(scheduled) > 25:
            raise RuntimeError(f"Unusually many named shifts on {key}")
        counts[key] = [int(morning),int(evening)]
        output[key] = {"people":scheduled}
    return counts,output

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--input",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--passcode-file",required=True)
    args=parser.parse_args()
    source=Path(args.input).read_bytes()
    digest=hashlib.sha256(source).hexdigest()
    month=dt.datetime.now(TOKYO).date().replace(day=1)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    count_path=out/"staffing-counts.json"
    cipher_path=out/"staffing-private.json"
    if count_path.exists() and cipher_path.exists():
        try:
            existing=json.loads(count_path.read_text("utf-8"))
            if existing.get("sourceHash")==digest and existing.get("month")==month.strftime("%Y-%m"):
                print("UNCHANGED")
                return
        except (ValueError,OSError):
            pass
    passcode=Path(args.passcode_file).read_text("utf-8").strip()
    if len(passcode)<12:
        raise RuntimeError("A strong access code of at least 12 characters is required")
    counts,dates=parse_roster(args.input,month)
    when=dt.datetime.now(TOKYO).isoformat(timespec="seconds")
    public={"version":1,"month":month.strftime("%Y-%m"),"updatedAt":when,"sourceHash":digest,"counts":counts}
    plaintext=json.dumps({"version":1,"month":public["month"],"dates":dates,"sourceHash":digest},ensure_ascii=False,separators=(",",":")).encode()
    salt=os.urandom(16)
    iv=os.urandom(12)
    iterations=310000
    kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=iterations)
    key=kdf.derive(passcode.encode("utf-8"))
    ciphertext=AESGCM(key).encrypt(iv,plaintext,None)
    b64=lambda b: base64.b64encode(b).decode("ascii")
    private={"version":1,"month":public["month"],"updatedAt":when,"iterations":iterations,"salt":b64(salt),"iv":b64(iv),"ciphertext":b64(ciphertext)}
    # Atomic files, but both updated in the same Git commit by launcher.
    for filename,obj in [(count_path,public),(cipher_path,private)]:
        temp=filename.with_suffix(filename.suffix+".tmp")
        temp.write_text(json.dumps(obj,ensure_ascii=False,separators=(",",":"))+"\n",encoding="utf-8")
        temp.replace(filename)
    print(f"UPDATED month={public['month']} days={len(counts)} staffEntries={sum(len(x['people']) for x in dates.values())} time={when}")

if __name__=="__main__":
    main()
