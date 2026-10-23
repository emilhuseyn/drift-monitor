# drift-monitor

A monitor that proves, continuously, that a protocol's contracts on every chain
still match a known-good baseline. It watches the one thing behavioural monitoring
does not: whether a proxy's implementation, its admin, or a contract's deployed
bytecode has changed out from under you.

This is a working tool, not a mockup. The runs below are real, against mainnet and
several L2s, with no API key, over public RPC. It ships with two worked target
sets - Lido and Uniswap v4 - and points at any protocol through a targets file.

## Why this exists

Large protocols govern a wide surface: core contracts on mainnet plus tokens,
bridge adapters and periphery deployed across a growing list of L2s. Most of it is
upgradeable, and the upgrade key is often a different account on every chain.

Transaction monitors (Forta, Hypernative) watch behaviour. They do not
continuously assert that each deployed implementation is still the audited one.
That gap matters most where it is least watched: a token or bridge proxy on an L2.
Catching a silent or malicious implementation swap there is what this tool is for.

## What it records

For every target, read straight from the chain:

- `code`  - hash + length of the deployed runtime bytecode
- `impl`  - EIP-1967 implementation slot (the proxy's current logic)
- `admin` - EIP-1967 admin slot (who can upgrade it)
- `owner` - owner() / proxy__getAdmin() where exposed

A failed RPC read is never compared against the baseline, so an outage cannot
raise a false alert. Only two valid observations can produce drift.

## Usage

```
py drift_monitor.py --baseline    # built-in Lido set -> canonical.json
py drift_monitor.py --check       # compare live state to the baseline
py drift_monitor.py --selftest    # prove drift detection on one proxy

py drift_monitor.py --targets uniswap_targets.json --manifest uniswap_canonical.json --baseline
```

The target list is data, not code. A targets file is a JSON array of
`[chain_name, chain_id, address, label]` rows.

## Example 1 - Lido (18 contracts, 8 chains)

```
baseline written: 18/18 contracts reachable, 17 proxies
  stETH (Lido core)         ethereum  impl=0x028271e3...  admin=0x3e40d73e...
  WithdrawalQueueERC721     ethereum  impl=0xe42c659d...  admin=0x3e40d73e...
  wstETH (Optimism)         optimism  impl=0xfe57042d...  admin=0xefa0db53...
  wstETH (Base)             base      impl=0x69ce2505...  admin=0x0e375994...
  wstETH (Arbitrum)         arbitrum  impl=0x0fbcbaea...  admin=0x1dca4185...
  wstETH (Linea)            linea     impl=0xc0583e2f...  admin=0xf951d759...
  wstETH (Scroll)           scroll    impl=0x38224d52...  admin=0x8e34d07e...
  wstETH (Mantle)           mantle    impl=0x1fabaaec...  admin=0x3a7b055b...
  ... 18 total across 8 chains

$ py drift_monitor.py --check
no drift across 18 contracts

$ py drift_monitor.py --selftest
selftest victim: wstETH (Optimism) [optimism]
  baseline impl : 0xfe57042de76c8d6b1df0e9e2047329fd3e2b7334
  forged impl   : 0xdead000000000000000000000000000000000000
  live impl     : 0xfe57042de76c8d6b1df0e9e2047329fd3e2b7334
  -> monitor would raise DRIFT on this proxy: YES
```

Notable: each L2's wstETH sits behind a different upgrade admin. A compromise of
any single one of those keys is a silent upgrade of that chain's wstETH, invisible
to anyone only watching mainnet.

## Example 2 - Uniswap v4 (13 contracts, 5 chains)

```
baseline written: 13/13 contracts reachable, 0 proxies
  v4 PoolManager (Ethereum)      ethereum  code=62b338e5... len=24009
  v4 PoolManager (Unichain)      unichain  code=2b0f0bb5... len=24050
  v4 PoolManager (Base)          base      code=695584a2... len=24009
  v4 PositionManager (Ethereum)  ethereum  code=4637b468... len=23877
  Permit2 (Ethereum)             ethereum  code=6edcbff6... len=9152
  ... 13 total across 5 chains
```

Uniswap v4 is immutable, so there is no proxy to watch - but the monitor still
proves every chain runs the canonical bytecode, and on the first sweep it flagged
that Unichain's PoolManager build is a different length (24050) to the other five
chains (24009). That is exactly the cross-chain divergence a standing check is for.

## Scope

A production deployment would cover every governed address on every chain a
protocol reaches, run on an interval, and push alerts into a channel the protocol
chooses. The engine here is the same one; only the target list and the alert sink
grow.
