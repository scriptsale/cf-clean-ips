#!/usr/bin/env python3
"""Cloudflare clean IP scanner - runs on Android (Termux), Windows, Linux.

Usage:
  python cf_whitelist.py            # default: 4 IPs per CIDR, SNI www.cloudflare.com
  python cf_whitelist.py 8          # 8 IPs per CIDR
  python cf_whitelist.py 8 panel.yourdomain.com
"""
import concurrent.futures
import random
import socket
import ssl
import sys
import urllib.request

CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"
TIMEOUT = 3
WORKERS = 32


def get_cidrs():
    req = urllib.request.Request(CF_RANGES_URL, headers={"User-Agent": "curl/8.5.0"})
    data = urllib.request.urlopen(req, timeout=15).read().decode()
    return [l.strip() for l in data.splitlines() if "/" in l and "." in l]


def rand_ip(cidr):
    ip, pre = cidr.split("/")
    pre = int(pre)
    o = [int(x) for x in ip.split(".")]
    base = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
    size = 1 << (32 - pre)
    if size <= 2:
        return ip
    v = base + random.randrange(1, size - 1)
    return ".".join(str((v >> s) & 255) for s in (24, 16, 8, 0))


def test_ip(ip, sni, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as s:
                req = (
                    "GET /cdn-cgi/trace HTTP/1.1\r\n"
                    "Host: %s\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n" % sni
                )
                s.sendall(req.encode())
                data = s.recv(64)
                return len(data) > 9 and data[:5] == b"HTTP/" and data[9:10] in b"23"
    except Exception:
        return False


def main():
    per = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    sni = sys.argv[2] if len(sys.argv) > 2 else "www.cloudflare.com"

    print("Fetching Cloudflare ranges...")
    cidrs = get_cidrs()
    candidates = sorted({rand_ip(c) for _ in range(per) for c in cidrs})
    print("Testing %d IPs from %d CIDRs (SNI %s)..." % (len(candidates), len(cidrs), sni))

    ok = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for ip, good in zip(candidates, ex.map(lambda i: test_ip(i, sni), candidates)):
            if good:
                ok.append(ip)
                print("  [OK] %s" % ip)

    print("\nWorking IPs: %d / %d" % (len(ok), len(candidates)))
    for ip in sorted(ok, key=lambda x: tuple(int(p) for p in x.split("."))):
        print(ip)


if __name__ == "__main__":
    main()
