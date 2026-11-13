#!/usr/bin/env python3
"""End-to-end flow tests for the secure gateway API.

Usage: python3 scripts/test_flows.py [api_base] [adapter_control]
Defaults: http://127.0.0.1:8000 and http://127.0.0.1:8080

Covers: clean upload+download, infected block, 413, 503 at 4 in flight,
cancel semantics, 5s deadline + reconnect, drop recovery, out-of-order
replies. Requires the adapter control endpoint for fault injection.
"""
import json
import sys
import time
import urllib.request
import urllib.error
import uuid

API = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
CTL = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8080"

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CLEAN = b"harmless demo payload " * 8

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS {name}")
    else:
        failed += 1
        print(f"  FAIL {name} {extra}")


def req(method, url, body=None, headers=None, expect=None):
    r = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r) as resp:
            code, data = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        code, data = e.code, e.read()
    if expect is not None and code != expect:
        raise AssertionError(f"{method} {url} -> {code}, expected {expect}: {data[:200]}")
    return code, data


def upload(name, payload, expect=202):
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    code, data = req("POST", f"{API}/files", body,
                     {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    if expect is not None and code != expect:
        return code, None
    return code, json.loads(data)


def status(fid):
    _, data = req("GET", f"{API}/files/{fid}", expect=200)
    return json.loads(data)


def wait_status(fid, want, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = status(fid)
        if rec["status"] in (want if isinstance(want, tuple) else (want,)):
            return rec
        time.sleep(0.1)
    return status(fid)


def set_config(**cfg):
    _, data = req("POST", f"{CTL}/config", json.dumps(cfg).encode(),
                  {"Content-Type": "application/json"}, expect=200)
    return json.loads(data)


def main():
    print(f"API={API} CTL={CTL}")

    print("== clean upload -> clean -> download ==")
    _, rec = upload("clean.bin", CLEAN)
    rec = wait_status(rec["id"], "clean")
    check("status clean", rec["status"] == "clean", rec)
    code, data = req("GET", f"{API}/files/{rec['id']}/download")
    check("download 200 + content", code == 200 and data == CLEAN, f"code={code}")

    print("== infected upload -> infected -> download blocked ==")
    _, rec = upload("eicar.bin", EICAR)
    rec = wait_status(rec["id"], "infected")
    check("status infected + signature", rec["status"] == "infected"
          and rec["signature"] == "Eicar-Test-Signature", rec)
    code, _ = req("GET", f"{API}/files/{rec['id']}/download")
    check("download blocked 403", code == 403, f"code={code}")

    print("== 8 MiB limit ==")
    code, _ = upload("toobig.bin", b"x" * (8 * 1024 * 1024 + 1), expect=None)
    check("oversize -> 413", code == 413, f"code={code}")

    print("== 4 in flight -> 503 ==")
    set_config(delay_min_ms=1500, delay_max_ms=1500)
    ids = [upload(f"hold{i}.bin", CLEAN)[1]["id"] for i in range(4)]
    code, _ = upload("fifth.bin", CLEAN, expect=None)
    check("5th upload -> 503", code == 503, f"code={code}")
    for fid in ids:
        check("held scan completes clean", wait_status(fid, "clean")["status"] == "clean")

    print("== cancel on the wire ==")
    set_config(delay_min_ms=1500, delay_max_ms=1500)
    _, rec = upload("cancel.bin", CLEAN)
    fid = rec["id"]
    code, data = req("POST", f"{API}/files/{fid}/cancel")
    check("cancel -> 200 cancelled", code == 200 and json.loads(data)["status"] == "cancelled")
    code, _ = req("POST", f"{API}/files/{fid}/cancel")
    check("re-cancel -> 409", code == 409, f"code={code}")
    code, _ = req("GET", f"{API}/files/{fid}/download")
    check("cancelled download -> 403", code == 403, f"code={code}")
    # slot held until the (discarded) reply arrives: only 3 free slots now
    ids = [upload(f"post{c}.bin", CLEAN)[1]["id"] for c in range(3)]
    code, _ = upload("overflow.bin", CLEAN, expect=None)
    check("cancelled scan still holds slot -> 503", code == 503, f"code={code}")
    time.sleep(2.0)  # discarded reply arrives, slot released
    code, rec2 = upload("after.bin", CLEAN, expect=None)
    check("slot released after discarded reply", code == 202, f"code={code}")
    if code == 202:
        wait_status(rec2["id"], "clean")
    for fid2 in ids:
        wait_status(fid2, "clean")
    check("cancelled stays cancelled", status(fid)["status"] == "cancelled")

    print("== 5s total deadline + connection recycle ==")
    set_config(delay_min_ms=10000, delay_max_ms=10000)
    _, r1 = upload("slow1.bin", CLEAN)
    _, r2 = upload("slow2.bin", CLEAN)
    t0 = time.time()
    rec1 = wait_status(r1["id"], "failed", timeout=8)
    rec2 = wait_status(r2["id"], "failed", timeout=8)
    elapsed = time.time() - t0
    check("both failed near 5s deadline", rec1["status"] == "failed"
          and rec2["status"] == "failed" and elapsed < 8, f"elapsed={elapsed:.1f}")
    check("deadline error reported", "deadline" in (rec1["error"] or ""), rec1)
    set_config(delay_min_ms=0, delay_max_ms=200)
    time.sleep(1.0)  # allow reconnect
    _, rec = upload("reconnected.bin", CLEAN)
    check("works after reconnect", wait_status(rec["id"], "clean")["status"] == "clean")

    print("== connection drop -> fail unfinished -> recover ==")
    set_config(drop_after_replies=1, delay_min_ms=0, delay_max_ms=0)
    _, ra = upload("drop-a.bin", CLEAN)
    _, rb = upload("drop-b.bin", CLEAN)
    reca = wait_status(ra["id"], ("clean", "failed"))
    recb = wait_status(rb["id"], ("clean", "failed"))
    check("exactly one reply delivered before drop",
          sorted([reca["status"], recb["status"]]) == ["clean", "failed"],
          f"{reca['status']} {recb['status']}")
    set_config(drop_after_replies=0, delay_min_ms=0, delay_max_ms=200)
    time.sleep(1.0)
    _, rec = upload("post-drop.bin", CLEAN)
    check("works after drop recovery", wait_status(rec["id"], "clean")["status"] == "clean")

    print("== out-of-order replies ==")
    set_config(delay_min_ms=0, delay_max_ms=1500)
    ids = [upload(f"ooo{i}.bin", CLEAN)[1]["id"] for i in range(4)]
    ok = all(wait_status(fid, "clean")["status"] == "clean" for fid in ids)
    check("all out-of-order replies matched by reqid", ok)

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
