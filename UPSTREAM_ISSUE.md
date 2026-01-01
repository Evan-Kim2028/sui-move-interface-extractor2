# Upstream Issue: move-stackless-bytecode-2 bitwise op result typing

## Summary

`move-stackless-bytecode-2` translator panics with `Type mismatch: U64 vs Bool` when translating bytecode containing integer bitwise operations.

## Impact

- Affects bytecode-first workflows using `move-model-2` / `move-stackless-bytecode-2`
- Reproducible on Sui framework package `0x2` and many mainnet packages
- Failure mode is a hard panic, not recoverable

## Root Cause

In `move-stackless-bytecode-2/src/translate.rs`, bitwise operations incorrectly return `Bool` instead of preserving the integer operand type:

```rust
// Current (incorrect):
IB::BitAnd => binop!(Op::BitAnd, lhs => N::Type::Bool.into()),
IB::BitOr => binop!(Op::BitOr, lhs => N::Type::Bool.into()),
IB::Xor => binop!(Op::Xor, lhs => N::Type::Bool.into()),
```

Move bytecode defines these as integer bitwise operators where `u64 & u64 -> u64`.

## Proposed Fix

```diff
- IB::BitAnd => binop!(Op::BitAnd, lhs => N::Type::Bool.into()),
- IB::BitOr  => binop!(Op::BitOr,  lhs => N::Type::Bool.into()),
- IB::Xor    => binop!(Op::Xor,    lhs => N::Type::Bool.into()),
+ IB::BitAnd => binop!(Op::BitAnd, lhs => lhs.ty.clone()),
+ IB::BitOr  => binop!(Op::BitOr,  lhs => lhs.ty.clone()),
+ IB::Xor    => binop!(Op::Xor,    lhs => lhs.ty.clone()),
```

Logical boolean operators (`IB::And`, `IB::Or`) should continue returning `Bool`.

## Reproduction

```bash
# Using sui-packages dataset
cargo run -- \
  --package-id 0x0000000000000000000000000000000000000000000000000000000000000002 \
  --bytecode-dataset sui-packages \
  --use-local-bytecode
```

Panics with:
```
thread 'main' panicked at .../move-stackless-bytecode-2/src/translate.rs:551:22:
Type mismatch: U64 vs Bool
```

## Local Patch Applied

File: `vendor/sui/external-crates/move/crates/move-stackless-bytecode-2/src/translate.rs`

Base commit: `b079752c05d5d53f3020fe18784c5da10c97a931`

## Test Coverage

After applying the patch, verification passes on 1,000 most-used mainnet packages:
- Before patch: ~58% success rate (panics on bitwise ops)
- After patch: 100% success rate

## Notes

The incorrect `Bool` typing appears to have been present since the introduction of `translate.rs` (commit `16fa239c19`, 2025-09-23).
