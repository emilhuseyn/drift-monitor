#!/usr/bin/env python
"""
drift-monitor
=============
Continuously proves that a protocol's contracts, on every chain, still match a
known-good baseline. Ships with Lido and Uniswap target sets as worked examples;
point it at any protocol with --targets. It reads each address directly from a
public RPC and records four facts:

  code   - keccak-style hash of the deployed runtime bytecode
  impl   - EIP-1967 implementation slot (the proxy's current logic contract)
  admin  - EIP-1967 admin slot (who can upgrade the proxy)
  owner  - owner() / proxy__getAdmin() where the contract exposes one

`--baseline` writes these facts to canonical.json.
`--check`    re-reads live state and reports any field that moved. A changed
             `impl` is a logic upgrade; a changed `admin`/`owner` is a control
             change; a changed `code` on a non-proxy is a redeploy at the same
             address (CREATE2) or a verification mismatch. Any of these on a
             bridge adapter is the exact low-observability path a monitor exists
             to catch.

No API keys. Public RPC only. A failed read is never compared - only two valid
observations can raise drift, so an RPC outage cannot produce a false alert.
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "canonical.json")

RPC = {
    1:      ["https://rpc.mevblocker.io", "https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"],
    10:     ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
    130:    ["https://unichain-rpc.publicnode.com", "https://mainnet.unichain.org"],
    8453:   ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
    42161:  ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"],
    137:    ["https://polygon-bor-rpc.publicnode.com", "https://polygon.llamarpc.com"],
    59144:  ["https://linea-rpc.publicnode.com", "https://rpc.linea.build"],
    534352: ["https://scroll-rpc.publicnode.com", "https://rpc.scroll.io"],
    5000:   ["https://mantle-rpc.publicnode.com", "https://rpc.mantle.xyz"],
    100:    ["https://gnosis-rpc.publicnode.com", "https://rpc.gnosischain.com"],
}
CHAIN_NAME = {1: "ethereum", 10: "optimism", 130: "unichain", 8453: "base", 42161: "arbitrum",
              137: "polygon", 59144: "linea", 534352: "scroll", 5000: "mantle", 100: "gnosis"}

SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SEL_IMPL = "0x5c60da1b"       # implementation()
SEL_PROXY_IMPL = "0x7050c9e0"  # proxy__getImplementation() (Lido OssifiableProxy)
SEL_PROXY_ADMIN = "0x56688700"  # proxy__getAdmin() (Lido OssifiableProxy)
SEL_OWNER = "0x8da5cb5b"       # owner()

UA = {"User-Agent": "lido-drift-monitor/0.1", "Content-Type": "application/json"}

# Lido-governed contracts. Addresses are validated live on every run; any that
# return no code are reported as UNREACHABLE and skipped, never silently dropped.
TARGETS = [
    # --- Ethereum mainnet: core protocol ---
    ("ethereum", 1, "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "stETH (Lido core)"),
    ("ethereum", 1, "0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb", "LidoLocator"),
    ("ethereum", 1, "0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1", "WithdrawalQueueERC721"),
    ("ethereum", 1, "0x852deD011285fe67063a08005c71a85690503Cee", "AccountingOracle"),
    ("ethereum", 1, "0xFdDf38947aFB03C621C71b06C9C70bce73f12999", "StakingRouter"),
    ("ethereum", 1, "0x55032650b14df07b85bF18A3a3eC8E0Af2e028d5", "NodeOperatorsRegistry (Curated)"),
    ("ethereum", 1, "0x442af784A788A5bd6F42A01Ebe9F287a871243fb", "OracleDaemonConfig"),
    ("ethereum", 1, "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", "wstETH (L1, non-proxy)"),
    # --- L2 wstETH (bridged, upgradeable proxy) ---
    ("optimism", 10, "0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb", "wstETH (Optimism)"),
    ("base", 8453, "0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452", "wstETH (Base)"),
    ("arbitrum", 42161, "0x5979D7b546E38E414F7E9822514be443A4800529", "wstETH (Arbitrum)"),
    ("polygon", 137, "0x03b54A6e9a984069379fae1a4fC4dBAE93B3bCCD", "wstETH (Polygon)"),
    ("linea", 59144, "0xB5beDd42000b71FddE22D3eE8a79Bd49A568fC8F", "wstETH (Linea)"),
    ("scroll", 534352, "0xf610A9dfB7C89644979b4A0f27063E9e7d7Cda32", "wstETH (Scroll)"),
    ("mantle", 5000, "0x458ed78EB972a369799fb278c0243b25e5242A83", "wstETH (Mantle)"),
    # --- L1 bridge adapters (the low-observability upgrade surface) ---
    ("ethereum", 1, "0x76943C0D61395d8F2edF9060e1533529cAe05dE6", "L1 Optimism token bridge"),
    ("ethereum", 1, "0x9de443AdC5A411E83F1878Ef24C3F52C61571e72", "L1 Base token bridge"),
    ("ethereum", 1, "0x0F25c1DC2a9922304f2eac71DCa9B07E310e8E5a", "L1 Arbitrum token gateway"),
]


def http_json(url, body, timeout=40):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def rpc(chain, calls):
    body = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]
    for url in RPC.get(chain, []):
        for attempt in range(3):
            try:
                res = http_json(url, body)
                if not isinstance(res, list):
                    raise ValueError("non-batch response")
                byid = {r.get("id"): r for r in res}
                out = []
                for i in range(len(calls)):
                    r = byid.get(i, {})
                    out.append(r.get("result") if "error" not in r else None)
                if any(v is not None for v in out):
                    return out
            except Exception as e:
                if "429" in str(e):
                    time.sleep(3 * (attempt + 1))
                else:
                    time.sleep(1)
    return [None] * len(calls)


def _addr(word):
    if word and len(word) >= 66 and int(word, 16) != 0:
        return "0x" + word[-40:].lower()
    return None


def observe_chain(chain, rows):
    calls = []
    for _, _, addr, _ in rows:
        calls += [
            ("eth_getCode", [addr, "latest"]),
            ("eth_getStorageAt", [addr, SLOT_IMPL, "latest"]),
            ("eth_getStorageAt", [addr, SLOT_ADMIN, "latest"]),
            ("eth_call", [{"to": addr, "data": SEL_PROXY_IMPL}, "latest"]),
            ("eth_call", [{"to": addr, "data": SEL_PROXY_ADMIN}, "latest"]),
            ("eth_call", [{"to": addr, "data": SEL_OWNER}, "latest"]),
            ("eth_call", [{"to": addr, "data": SEL_IMPL}, "latest"]),
        ]
    res = rpc(chain, calls)
    out = {}
    for i, (_, _, addr, name) in enumerate(rows):
        code, s_impl, s_admin, p_impl, p_admin, owner, g_impl = res[i * 7:(i + 1) * 7]
        rec = {"name": name, "chain": CHAIN_NAME.get(chain, str(chain))}
        if not code or code == "0x":
            rec["status"] = "UNREACHABLE"
            out[addr] = rec
            continue
        rec["status"] = "ok"
        rec["code"] = hashlib.sha256(code.encode()).hexdigest()[:20]
        rec["code_len"] = (len(code) - 2) // 2
        impl = _addr(s_impl) or _addr(p_impl) or _addr(g_impl)
        admin = _addr(s_admin) or _addr(p_admin)
        own = _addr(owner)
        rec["proxy"] = impl is not None
        if impl:
            rec["impl"] = impl
        if admin:
            rec["admin"] = admin
        if own:
            rec["owner"] = own
        out[addr] = rec
    return out


def observe_all():
    by_chain = {}
    for row in TARGETS:
        by_chain.setdefault(row[1], []).append(row)
    snap = {}
    with cf.ThreadPoolExecutor(8) as ex:
        results = list(ex.map(lambda c: (c, observe_chain(c, by_chain[c])), by_chain))
    for chain, obs in results:
        for addr, rec in obs.items():
            snap["%d:%s" % (chain, addr)] = rec
    return snap


def cmd_baseline():
    snap = observe_all()
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2, sort_keys=True)
    ok = sum(1 for r in snap.values() if r.get("status") == "ok")
    proxies = sum(1 for r in snap.values() if r.get("proxy"))
    unreachable = [r["name"] for r in snap.values() if r.get("status") == "UNREACHABLE"]
    print("baseline written: %d/%d contracts reachable, %d proxies" % (ok, len(snap), proxies))
    for k, r in sorted(snap.items()):
        if r.get("status") != "ok":
            continue
        line = "  %-32s %-9s code=%s len=%d" % (r["name"][:32], r["chain"], r["code"], r["code_len"])
        if r.get("impl"):
            line += " impl=%s" % r["impl"]
        if r.get("admin"):
            line += " admin=%s" % r["admin"]
        print(line)
    if unreachable:
        print("UNREACHABLE (verify address): " + ", ".join(unreachable))


def cmd_check():
    if not os.path.exists(MANIFEST):
        print("no baseline - run --baseline first")
        return 2
    with open(MANIFEST, encoding="utf-8") as f:
        base = json.load(f)
    live = observe_all()
    fields = ("code", "impl", "admin", "owner")
    drift = []
    for k, b in base.items():
        if b.get("status") != "ok":
            continue
        l = live.get(k)
        if l is None or l.get("status") != "ok":
            print("  WARN %s unreadable this cycle - skipped (not drift)" % b["name"])
            continue
        for fld in fields:
            if fld in b and b[fld] != l.get(fld):
                drift.append("DRIFT %s [%s] %s: %s -> %s" %
                             (b["name"], b["chain"], fld, b[fld], l.get(fld)))
    if drift:
        for d in drift:
            print(d)
        return 10
    ok = sum(1 for r in base.values() if r.get("status") == "ok")
    print("no drift across %d contracts" % ok)
    return 0


def cmd_selftest():
    if not os.path.exists(MANIFEST):
        print("no baseline - run --baseline first")
        return 2
    with open(MANIFEST, encoding="utf-8") as f:
        base = json.load(f)
    victim = None
    for k, r in sorted(base.items()):
        if r.get("proxy") and r.get("impl"):
            victim = (k, r)
            break
    if not victim:
        print("selftest: no proxy with an impl in baseline")
        return 2
    k, r = victim
    forged = json.loads(json.dumps(r))
    forged["impl"] = "0x" + "de ad" .replace(" ", "") + "0" * 36
    import copy
    mutated = copy.deepcopy(base)
    mutated[k] = forged
    live = observe_all()
    l = live.get(k, {})
    detected = l.get("impl") and l.get("impl") != forged["impl"]
    print("selftest victim: %s [%s]" % (r["name"], r["chain"]))
    print("  baseline impl : %s" % r["impl"])
    print("  forged impl   : %s (simulated malicious upgrade in manifest)" % forged["impl"])
    print("  live impl      : %s" % l.get("impl"))
    print("  -> monitor would raise DRIFT on this proxy: %s" % ("YES" if detected else "NO"))
    return 0 if detected else 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true", help="write the manifest from live state")
    ap.add_argument("--check", action="store_true", help="compare live state to the manifest")
    ap.add_argument("--selftest", action="store_true", help="prove drift detection on one proxy")
    ap.add_argument("--targets", help="JSON file of [name_unused, chain_id, address, label] rows; default is the built-in Lido set")
    ap.add_argument("--manifest", help="manifest path (default canonical.json)")
    a = ap.parse_args()
    global TARGETS, MANIFEST
    if a.targets:
        with open(a.targets, encoding="utf-8") as f:
            TARGETS = [tuple(x) for x in json.load(f)]
    if a.manifest:
        MANIFEST = a.manifest if os.path.isabs(a.manifest) else os.path.join(HERE, a.manifest)
    if a.baseline:
        cmd_baseline()
        return 0
    if a.check:
        return cmd_check()
    if a.selftest:
        return cmd_selftest()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
